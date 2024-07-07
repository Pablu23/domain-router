package domainrouter

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"

	"github.com/rs/zerolog/log"
)

// ConstMap for disallowing change of elements during runtime, for threadsafty
type constMap[K comparable, V any] struct {
	dirty map[K]V
}

func NewConstMap[K comparable, V any](m map[K]V) *constMap[K, V] {
	return &constMap[K, V]{
		dirty: m,
	}
}

func (m *constMap[K, V]) Get(key K) (value V, ok bool) {
	value, ok = m.dirty[key]
	return value, ok
}

type Router struct {
	domains *constMap[string, int]
	client  *http.Client
}

func New(domains map[string]int, client *http.Client) Router {
	return Router{
		domains: NewConstMap(domains),
		client:  client,
	}
}

func (router *Router) Route(w http.ResponseWriter, r *http.Request) {
	port, ok := router.domains.Get(r.Host)
	if !ok {
		w.WriteHeader(http.StatusOK)
		return
	}

	if !dumpRequest(w, r) {
		return
	}

	subUrlPath := r.URL.RequestURI()
	req, err := http.NewRequest(r.Method, fmt.Sprintf("http://localhost:%d%s", port, subUrlPath), r.Body)
	if err != nil {
		log.Error().Err(err).Str("path", subUrlPath).Int("port", port).Msg("Could not create request")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	for name, values := range r.Header {
		for _, value := range values {
			req.Header.Set(name, value)
		}
	}

	for _, cookie := range r.Cookies() {
		req.AddCookie(cookie)
	}

	if !dumpRequest(w, req) {
		return
	}

	res, err := router.client.Do(req)
	if err != nil {
		log.Error().Err(err).Str("path", subUrlPath).Int("port", port).Msg("Could not complete request")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	cookies := res.Cookies()
	for _, cookie := range cookies {
		// fmt.Printf("Setting cookie, Name: %s, Value: %s\n", cookie.Name, cookie.Value)
		http.SetCookie(w, cookie)
	}

	if !dumpResponse(w, res) {
		return
	}

	if loc, err := res.Location(); !errors.Is(err, http.ErrNoLocation) {
		http.Redirect(w, r, loc.RequestURI(), http.StatusFound)
	} else {
		for name, values := range res.Header {
			for _, value := range values {
				w.Header().Set(name, value)
			}
		}
		w.WriteHeader(res.StatusCode)

		body, err := io.ReadAll(res.Body)
		defer res.Body.Close()
		if err != nil {
			log.Error().Err(err).Msg("Could not read body")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		_, err = w.Write(body)
		if err != nil {
			log.Error().Err(err).Msg("Could not write body")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
}

func dumpRequest(w http.ResponseWriter, r *http.Request) bool {
	if e := log.Debug(); e.Enabled() && r.Method == "POST" {
		rDump, err := httputil.DumpRequest(r, true)
		if err != nil {
			log.Error().Err(err).Msg("Could not dump request")
			w.WriteHeader(http.StatusInternalServerError)
			return false
		}
		log.Debug().Str("dump", string(rDump)).Send()
	}
	return true
}

func dumpResponse(w http.ResponseWriter, r *http.Response) bool {
	if e := log.Trace(); e.Enabled() {
		dump, err := httputil.DumpResponse(r, true)
		if err != nil {
			log.Error().Err(err).Msg("Could not dump response")
			w.WriteHeader(http.StatusInternalServerError)
			return false
		}
		log.Trace().Str("dump", string(dump)).Send()
	}
	return true
}
