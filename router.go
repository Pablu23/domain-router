package domainrouter

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"

	"github.com/pablu23/domain-router/util"
	"github.com/rs/zerolog/log"
)

type Router struct {
	config  *Config
	domains *util.ImmutableMap[string, struct {
		Port   int
		Remote string
		Secure bool
	}]
	client *http.Client
}

func New(config *Config, client *http.Client) Router {
	m := make(map[string]struct {
		Port   int
		Remote string
		Secure bool
	})
	for _, host := range config.Hosts {
		for _, domain := range host.Domains {
			m[domain] = struct {
				Port   int
				Remote string
				Secure bool
			}{host.Port, host.Remote, host.Secure}
		}
	}

	return Router{
		config:  config,
		domains: util.NewImmutableMap(m),
		client:  client,
	}
}

func (router *Router) Healthz(w http.ResponseWriter, r *http.Request) {
	if !router.config.General.AnnouncePublic {
		http.NotFound(w, r)
		return
	}

	result := make([]struct {
		Domain  string
		Healthy bool
	}, 0)

	for _, host := range router.config.Hosts {
		if !host.Public {
			continue
		}

		healthy := true
		var url string
		if host.Secure {
			url = fmt.Sprintf("https://%s:%d/healthz", host.Remote, host.Port)
		} else {
			url = fmt.Sprintf("http://%s:%d/healthz", host.Remote, host.Port)
		}

		res, err := router.client.Get(url)
		if err != nil {
			log.Warn().Err(err).Int("port", host.Port).Msg("Unhealthy")
			healthy = false
		}

		for _, domain := range host.Domains {
			result = append(result, struct {
				Domain  string
				Healthy bool
			}{domain, healthy && res.StatusCode == 200})
		}
	}

	data, err := json.Marshal(&result)
	if err != nil {
		log.Error().Err(err).Msg("Could not json encode Healthz")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.Write(data)
	w.WriteHeader(http.StatusOK)
}

func (router *Router) Route(w http.ResponseWriter, r *http.Request) {
	host, ok := router.domains.Get(r.Host)
	if !ok {
		log.Warn().Str("host", r.Host).Msg("Could not find Host")
		w.WriteHeader(http.StatusOK)
		return
	}

	if !dumpRequest(w, r) {
		return
	}

	subUrlPath := r.URL.RequestURI()
	var url string
	if host.Secure {
		url = fmt.Sprintf("https://%s:%d%s", host.Remote, host.Port, subUrlPath)
	} else {
		url = fmt.Sprintf("http://%s:%d%s", host.Remote, host.Port, subUrlPath)
	}

	req, err := http.NewRequest(r.Method, url, r.Body)
	if err != nil {
		log.Error().Err(err).Bool("secure", host.Secure).Str("remote", host.Remote).Str("path", subUrlPath).Int("port", host.Port).Msg("Could not create request")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	for name, values := range r.Header {
		for _, value := range values {
			req.Header.Set(name, value)
		}
	}
	req.Header.Set("X-Forwarded-For", r.RemoteAddr)

	for _, cookie := range r.Cookies() {
		req.AddCookie(cookie)
	}

	if !dumpRequest(w, req) {
		return
	}

	res, err := router.client.Do(req)
	if err != nil {
		log.Error().Err(err).Str("remote", host.Remote).Str("path", subUrlPath).Int("port", host.Port).Msg("Could not complete request")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	cookies := res.Cookies()
	for _, cookie := range cookies {
		http.SetCookie(w, cookie)
	}

	if !dumpResponse(w, res) {
		return
	}

	// Exit early because its a redirect
	if !handleLocation(w, r, res) {
		return
	}

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

func handleLocation(w http.ResponseWriter, r *http.Request, res *http.Response) bool {
	if loc, err := res.Location(); err == nil {
		http.Redirect(w, r, loc.RequestURI(), http.StatusFound)
		return false
	} else if !errors.Is(err, http.ErrNoLocation) {
		log.Error().Err(err).Msg("Could not extract location")
		w.WriteHeader(http.StatusInternalServerError)
		return false
	}
	return true
}

func dumpRequest(w http.ResponseWriter, r *http.Request) bool {
	if e := log.Trace(); e.Enabled() && r.Method == "POST" {
		rDump, err := httputil.DumpRequest(r, true)
		if err != nil {
			log.Error().Err(err).Msg("Could not dump request")
			w.WriteHeader(http.StatusInternalServerError)
			return false
		}
		log.Trace().Str("dump", string(rDump)).Msg("Dumping Request")
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
		log.Trace().Str("dump", string(dump)).Msg("Dumping Response")
	}
	return true
}
