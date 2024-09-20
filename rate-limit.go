package domainrouter

import (
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

type Limiter struct {
	current map[string]*atomic.Int64
	max     int
	ticker  *time.Ticker
	refill  int
	m       *sync.RWMutex
	c       chan string
}

func NewLimiter(maxRequests int, refills int, refillInterval time.Duration) Limiter {
	return Limiter{
		current: make(map[string]*atomic.Int64),
		max:     maxRequests,
		ticker:  time.NewTicker(refillInterval),
		refill:  refills,
		m:       &sync.RWMutex{},
		c:       make(chan string),
	}
}

func (l *Limiter) Start() {
	go l.Manage()
	return
}

func (l *Limiter) Manage() {
	for {
		select {
		case ip := <-l.c:
			l.m.Lock()
			if counter, ok := l.current[ip]; ok {
				counter.Add(1)
			} else {
				counter := &atomic.Int64{}
				l.current[ip] = counter
			}
			l.m.Unlock()
		case <-l.ticker.C:
			l.m.RLock()
			for ip := range l.current {
				n := l.current[ip].Add(int64(-l.refill))
				if n < 0 {
					l.current[ip].Store(0)
					n = 0
				}
				log.Debug().Int64("bucket", n).Str("remote", ip).Msg("Updated limit")
			}
			l.m.RUnlock()
			log.Debug().Msg("Refreshed Limits")
		}
	}
}

func (l *Limiter) RateLimiter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr := strings.Split(r.RemoteAddr, ":")[0]
		l.m.RLock()
		count, ok := l.current[addr]
		l.m.RUnlock()
		if ok && int(count.Load()) >= l.max {
			hj, ok := w.(http.Hijacker)
			if !ok {
				r.Body.Close()
				log.Warn().Str("host", r.Host).Str("uri", r.RequestURI).Str("method", r.Method).Str("remote", addr).Msg("Rate limited")
				return
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				log.Error().Err(err).Str("host", r.Host).Str("uri", r.RequestURI).Str("method", r.Method).Str("remote", addr).Msg("Could not hijack connection")
			}

			log.Warn().Str("host", r.Host).Str("uri", r.RequestURI).Str("method", r.Method).Str("remote", addr).Msg("Rate limited")
			conn.Close()
			return
		}
		l.c <- addr
		next.ServeHTTP(w, r)
	})
}
