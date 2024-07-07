package domainrouter

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

type Limiter struct {
	current map[string]int
	max     int
	ticker  *time.Ticker
	refill  int
	m       *sync.RWMutex
	c       chan string
}

func NewLimiter(maxRequests int, refills int, refillInterval time.Duration) Limiter {
	return Limiter{
		current: make(map[string]int),
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
			if _, ok := l.current[ip]; ok {
				l.current[ip] += 1
			} else {
				l.current[ip] = 1
			}
			l.m.Unlock()
		case <-l.ticker.C:
			l.m.Lock()
			start := time.Now()
			count := len(l.current)
			deleted := 0
			for ip, times := range l.current {
				if times-l.refill <= 0 {
					deleted += 1
					delete(l.current, ip)
				} else {
					l.current[ip] -= l.refill
				}
			}
			l.m.Unlock()
			elapsed := time.Since(start)
			if count >= 1 {
				log.Info().Int("ips", count).Int("forgotten", deleted).Str("duration", elapsed.String()).Msg("Refill rate limit")
			}
		}
	}
}

func (l *Limiter) RateLimiter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr := strings.Split(r.RemoteAddr, ":")[0]
		l.m.RLock()
		count, ok := l.current[addr]
		l.m.RUnlock()
		if ok && count >= l.max {
			hj, ok := w.(http.Hijacker)
			if !ok {
				r.Body.Close()
				log.Warn().Str("host", r.Host).Str("uri", r.RequestURI).Str("method", r.Method).Str("remote", addr).Msg("Rate limited")
				return
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				panic(err)
			}

			log.Warn().Str("host", r.Host).Str("uri", r.RequestURI).Str("method", r.Method).Str("remote", addr).Msg("Rate limited")
			conn.Close()
			return
		}
		l.c <- addr
		next.ServeHTTP(w, r)
	})
}
