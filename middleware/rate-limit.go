package middleware

import (
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

type Limiter struct {
	currentBuckets map[string]*atomic.Int64
	bucketSize     int
	refillTicker   *time.Ticker
	cleanupTicker  *time.Ticker
	bucketRefill   int
	rwLock         *sync.RWMutex
	rateChannel    chan string
	stop           chan struct{}
}

func NewLimiter(maxRequests int, refills int, refillInterval time.Duration, cleanupInterval time.Duration) *Limiter {
	return &Limiter{
		currentBuckets: make(map[string]*atomic.Int64),
		bucketSize:     maxRequests,
		refillTicker:   time.NewTicker(refillInterval),
		cleanupTicker:  time.NewTicker(cleanupInterval),
		bucketRefill:   refills,
		rwLock:         &sync.RWMutex{},
		rateChannel:    make(chan string),
	}
}

func (l *Limiter) UpdateCleanupTime(new time.Duration) {
	l.cleanupTicker.Reset(new)
}

func (l *Limiter) Stop() {
	l.stop <- struct{}{}
	log.Info().Msg("Stopped Ratelimits")
}

func (l *Limiter) Manage() {
	for {
		select {
		case ip := <-l.rateChannel:
			if l.AddIfExists(ip) {
				break
			}

			l.rwLock.Lock()
			counter := &atomic.Int64{}
			l.currentBuckets[ip] = counter
			l.rwLock.Unlock()
		case <-l.refillTicker.C:
			l.rwLock.RLock()
			for ip := range l.currentBuckets {
				n := l.currentBuckets[ip].Add(int64(-l.bucketRefill))
				if n < 0 {
					l.currentBuckets[ip].Store(0)
					n = 0
				}
				log.Trace().Int64("bucket", n).Str("remote", ip).Msg("Updated limit")
			}
			l.rwLock.RUnlock()
			log.Trace().Msg("Refreshed Limits")
		case <-l.cleanupTicker.C:
			start := time.Now()
			l.rwLock.Lock()
			deletedBuckets := 0
			for ip := range l.currentBuckets {
				if l.currentBuckets[ip].Load() <= 0 {
					delete(l.currentBuckets, ip)
					deletedBuckets += 1
				}
			}
			l.rwLock.Unlock()
			duration := time.Since(start)
			log.Debug().Str("duration", duration.String()).Int("deleted_buckets", deletedBuckets).Msg("Cleaned up Buckets")
		case <- l.stop:
			return
		}
	}
}

// Adds one if ip already exists and returns true
// If ip doesnt yet exist only returns false
func (l *Limiter) AddIfExists(ip string) bool {
	l.rwLock.RLock()
	defer l.rwLock.RUnlock()
	if counter, ok := l.currentBuckets[ip]; ok {
		counter.Add(1)
		return true
	}
	return false
}

func (l *Limiter) Use(next http.Handler) http.Handler {
	log.Info().Int("bucket_size", l.bucketSize).Int("bucket_refill", l.bucketRefill).Msg("Enabling Ratelimits")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr := strings.Split(r.RemoteAddr, ":")[0]
		l.rwLock.RLock()
		count, ok := l.currentBuckets[addr]
		l.rwLock.RUnlock()
		if ok && int(count.Load()) >= l.bucketSize {
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
		l.rateChannel <- addr
		next.ServeHTTP(w, r)
	})
}
