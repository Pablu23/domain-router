package domainrouter

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"sync/atomic"

	"github.com/rs/zerolog/log"
)

type Router struct {
	config  *Config
	domains *ThreadMap[string, Host]
	client  *http.Client
}

type Host struct {
	Port    int
	Remotes []string
	Secure  bool
	Current *atomic.Uint32
}

func New(config *Config, client *http.Client) Router {
	m := make(map[string]Host)
	for _, host := range config.Hosts {
		for _, domain := range host.Domains {
			m[domain] = Host{host.Port, host.Remotes, host.Secure, &atomic.Uint32{}}
		}
	}

	return Router{
		config:  config,
		domains: NewThreadMap(m),
		client:  client,
	}
}

func (router *Router) roundRobin(host *Host) {
	l := len(host.Remotes)
	if l > 1 && host.Current.Load()+1 < uint32(l) {
		host.Current.Add(1)
	} else if l > 1 {
		host.Current.Store(0)
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
		for _, remote := range host.Remotes {
			var url string
			if host.Secure {
				url = fmt.Sprintf("https://%s:%d/healthz", remote, host.Port)
			} else {
				url = fmt.Sprintf("http://%s:%d/healthz", remote, host.Port)
			}

			res, err := router.client.Get(url)
			if err != nil {
				log.Warn().Err(err).Str("remote", remote).Int("port", host.Port).Msg("Unhealthy")
				healthy = false
			} else if res.StatusCode != 200 {
				healthy = false
			}
		}

		for _, domain := range host.Domains {
			result = append(result, struct {
				Domain  string
				Healthy bool
			}{domain, healthy})
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

func createRequest(r *http.Request, host *Host, remote string) (*http.Request, error) {
	subUrlPath := r.URL.RequestURI()
	var url string
	if host.Secure {
		url = fmt.Sprintf("https://%s:%d%s", remote, host.Port, subUrlPath)
	} else {
		url = fmt.Sprintf("http://%s:%d%s", remote, host.Port, subUrlPath)
	}

	req, err := http.NewRequest(r.Method, url, r.Body)
	if err != nil {
		return nil, err
	}

	copyRequestHeader(r, req)
	req.Header.Set("X-Forwarded-For", r.RemoteAddr)
	req.Header.Set("Cache-Control", "no-store, no-cache, max-age=0, must-revalidate, proxy-revalidate")

	for _, cookie := range r.Cookies() {
		req.AddCookie(cookie)
	}

	return req, nil
}

var etagHeaders = map[string]struct{}{
	"ETag":                {},
	"If-Modified-Since":   {},
	"If-Match":            {},
	"If-None-Match":       {},
	"If-Range":            {},
	"If-Unmodified-Since": {},
}

func copyRequestHeader(origin *http.Request, destination *http.Request) {
	for name, values := range origin.Header {

		// Skip etag Headers
		if _, ok := etagHeaders[name]; ok {
			continue
		}

		for _, value := range values {
			destination.Header.Set(name, value)
		}
	}
}

func applyResponseHeader(w http.ResponseWriter, res *http.Response) {
	for name, values := range res.Header {
		for _, value := range values {
			w.Header().Set(name, value)
		}
	}
	w.WriteHeader(res.StatusCode)
}

func (router *Router) applyCookies(w http.ResponseWriter, res *http.Response) {
	cookies := res.Cookies()
	for _, cookie := range cookies {
		if router.config.Server.Ssl.Enabled {
			cookie.Secure = true
		}
		http.SetCookie(w, cookie)
	}
}

func applyBody(w http.ResponseWriter, res *http.Response) error {
	body, err := io.ReadAll(res.Body)
	defer res.Body.Close()
	if err != nil {
		return err
	}

	_, err = w.Write(body)
	if err != nil {
		return err
	}

	w.WriteHeader(res.StatusCode)
	return nil
}

func (router *Router) Route(w http.ResponseWriter, r *http.Request) {
	// If trace enabled dump incoming request, could break request so exit early if that happens
	if !dumpRequest(w, r) {
		return
	}

	host, ok := router.domains.Get(r.Host)
	if !ok {
		log.Warn().Str("host", r.Host).Msg("Could not find Host")
		w.WriteHeader(http.StatusOK)
		return
	}

	remote := host.Remotes[host.Current.Load()]
	go router.roundRobin(&host)

	req, err := createRequest(r, &host, remote)
	if err != nil {
		log.Error().Err(err).Bool("secure", host.Secure).Str("remote", remote).Int("port", host.Port).Msg("Could not create request")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Dump created request
	if !dumpRequest(w, req) {
		return
	}

	res, err := router.client.Do(req)
	if err != nil {
		log.Error().Err(err).Str("remote", remote).Int("port", host.Port).Msg("Could not complete request")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// If trace enabled dump response
	if !dumpResponse(w, res) {
		return
	}

	router.applyCookies(w, res)
	applyResponseHeader(w, res)

	// Exit early because its a redirect
	// Maybe this should be before applying cookies or after applying headers
	if !handleLocation(w, r, res) {
		return
	}

	err = applyBody(w, res)
	if err != nil {
		log.Error().Err(err).Msg("Could not apply body")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func handleLocation(w http.ResponseWriter, r *http.Request, res *http.Response) bool {
	if loc, err := res.Location(); err == nil {
		http.Redirect(w, r, loc.String(), http.StatusFound)
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
