package domainrouter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"net/url"
	"slices"
	"strings"
	"sync"
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

func rewriteRequestURL(r *http.Request, host *Host, remote string) error {
	subUrlPath := r.URL.RequestURI()
	var uri string
	if host.Secure {
		uri = fmt.Sprintf("https://%s:%d%s", remote, host.Port, subUrlPath)
	} else {
		uri = fmt.Sprintf("http://%s:%d%s", remote, host.Port, subUrlPath)
	}

	remoteUrl, err := url.Parse(uri)
	if err != nil {
		return err
	}

	r.RequestURI = ""
	r.URL.Scheme = remoteUrl.Scheme
	r.URL.Host = remoteUrl.Host
	r.Header.Set("X-Forwarded-For", r.RemoteAddr)
	r.Header.Set("Cache-Control", "no-store, no-cache, max-age=0, must-revalidate, proxy-revalidate")

	return nil
}

func (router *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	transport := http.DefaultTransport
	portLessHost, _ := strings.CutSuffix(r.Host, fmt.Sprintf(":%d", router.config.Server.Port))
	host, ok := router.domains.Get(portLessHost)
	if !ok {
		log.Warn().Str("host", portLessHost).Msg("Could not find Host")
		w.WriteHeader(http.StatusOK)
		return
	}

	remote := host.Remotes[host.Current.Load()]
	go router.roundRobin(&host)

	// Copy request
	// Copy body with Buffer Pool
	ctx := r.Context()

	outreq := r.Clone(ctx)
	if r.ContentLength == 0 {
		outreq.Body = nil
	}
	if outreq.Body != nil {
		defer outreq.Body.Close()
	}
	outreq.Close = false

	reqUpType := upgradeType(outreq.Header)
	if !isPrintableAscii(reqUpType) {
		log.Error().Str("request_upgrade_type", reqUpType).Msg("Client tried to switch to invalid protocol")
		return
	}
	removeHopByHopHeaders(outreq.Header)

	if slices.Contains(r.Header.Values("Te"), "trailers") {
		outreq.Header.Set("Te", "trailers")
	}

	if reqUpType != "" {
		outreq.Header.Set("Connection", "Upgrade")
		outreq.Header.Set("Upgrade", reqUpType)
		log.Trace().Str("upgrade_type", reqUpType).Msg("Found upgrade Type")
	}

	stripClientProvidedXForwardHeaders(outreq.Header)

	if _, ok := outreq.Header["User-Agent"]; !ok {
		outreq.Header.Set("User-Agent", "")
	}

	err := rewriteRequestURL(outreq, &host, remote)
	if err != nil {
		log.Error().Err(err).Bool("secure", host.Secure).Str("remote", remote).Int("port", host.Port).Msg("Could not create request")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var (
		roundTripMutex sync.Mutex
		roundTripDone  bool
	)

	trace := &httptrace.ClientTrace{
		Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
			roundTripMutex.Lock()
			defer roundTripMutex.Unlock()
			if roundTripDone {
				return nil
			}
			h := w.Header()
			copyHeader(h, http.Header(header))
			w.WriteHeader(code)

			clear(h)
			return nil
		},
	}
	outreq = outreq.WithContext(httptrace.WithClientTrace(outreq.Context(), trace))

	res, err := transport.RoundTrip(outreq)
	roundTripMutex.Lock()
	roundTripDone = true
	roundTripMutex.Unlock()
	if err != nil {
		log.Error().Err(err).Any("out_request", outreq).Msg("Could not complete transport round trip")
		return
	}

	if res.StatusCode == http.StatusSwitchingProtocols {
		router.handleUpgradeResponse(w, res, outreq)
		return
	}

	removeHopByHopHeaders(res.Header)

	copyHeader(w.Header(), res.Header)

	w.WriteHeader(res.StatusCode)
	err = router.copyResponse(w, res.Body)
	res.Body.Close()
}

func (router *Router) copyResponse(dst http.ResponseWriter, src io.ReadCloser) error {
	buf := make([]byte, 32*1024)
	var written int64
	for {
		nr, rerr := src.Read(buf)
		if rerr != nil && rerr != io.EOF && rerr != context.Canceled {
			log.Error().Err(rerr).Msg("Could not copy body")
			return rerr
		}
		if nr > 0 {
			nw, werr := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if werr != nil {
				return werr
			}
		}
		if rerr != nil && rerr == io.EOF {
			return nil
		}
	}
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func (router *Router) handleUpgradeResponse(w http.ResponseWriter, res *http.Response, req *http.Request) {
	reqUpType := upgradeType(req.Header)
	resUpType := upgradeType(res.Header)
	if !strings.EqualFold(reqUpType, resUpType) {
		log.Error().Str("response_upgrade_type", resUpType).Str("request_upgrade_type", reqUpType).Msg("Response and Request Upgrade type do not match")
		return
	}

	backConn, ok := res.Body.(io.ReadWriteCloser)
	if !ok {
		log.Error().Msg("Could not switch protocols with non writable body")
		return
	}

	rc := http.NewResponseController(w)
	conn, brw, hijackErr := rc.Hijack()
	if errors.Is(hijackErr, http.ErrNotSupported) {
		log.Error().Type("response_writer_type", w).Msg("Could not switch protocols using non-Hijacker ResponseWriter")
		return
	}

	backConnCloseCh := make(chan bool)
	go func() {
		select {
		case <-req.Context().Done():
		case <-backConnCloseCh:
		}
		backConn.Close()
	}()
	defer close(backConnCloseCh)

	if hijackErr != nil {
		log.Error().Err(hijackErr).Msg("Hijack failed on protocol switch")
		return
	}
	defer conn.Close()

	copyHeader(w.Header(), res.Header)

	res.Header = w.Header()
	res.Body = nil
	if err := res.Write(brw); err != nil {
		log.Error().Err(err).Msg("Could not write")
		return
	}
	if err := brw.Flush(); err != nil {
		log.Error().Err(err).Msg("Could not flush")
		return
	}
	errc := make(chan error, 1)
	spc := switchProtocolCopier{user: conn, backend: backConn}
	go spc.copyToBackend(errc)
	go spc.copyFromBackend(errc)

	err := <-errc
	if err == nil {
		err = <-errc
	}
}

type switchProtocolCopier struct {
	user, backend io.ReadWriter
}

var errCopyDone = errors.New("hijacked connection copy complete")

func (c switchProtocolCopier) copyFromBackend(errc chan<- error) {
	if _, err := io.Copy(c.user, c.backend); err != nil {
		errc <- err
		return
	}

	// backend conn has reached EOF so propogate close write to user conn
	if wc, ok := c.user.(interface{ CloseWrite() error }); ok {
		errc <- wc.CloseWrite()
		return
	}
	errc <- errCopyDone
}

func (c switchProtocolCopier) copyToBackend(errc chan<- error) {
	if _, err := io.Copy(c.backend, c.user); err != nil {
		errc <- err
		return
	}
	// user conn has reached EOF so propogate close write to backend conn
	if wc, ok := c.backend.(interface{ CloseWrite() error }); ok {
		errc <- wc.CloseWrite()
		return
	}

	errc <- errCopyDone
}

func stripClientProvidedXForwardHeaders(header http.Header) {
	header.Del("Forwarded")
	header.Del("X-Forwarded-For")
	header.Del("X-Forwarded-Host")
	header.Del("X-Forwarded-Proto")
}

func removeHopByHopHeaders(header http.Header) {
	for _, f := range header.Values("Connection") {
		if strings.TrimSpace(f) != "" {
			header.Del(f)
		}
	}
}

func isPrintableAscii(reqUpType string) bool {
	for _, c := range reqUpType {
		if c < 32 && c > 126 {
			return false
		}
	}
	return true
}

func upgradeType(header http.Header) string {
	// Iterate over Connection headers if those exist multiple times
	for _, conVal := range header.Values("Connection") {
		for _, headerVal := range strings.Split(conVal, ",") {
			trimmed := strings.TrimSpace(headerVal)
			if strings.EqualFold(trimmed, "upgrade") {
				upType := header.Get("Upgrade")
				return upType
			}
		}
	}
	return ""
}
