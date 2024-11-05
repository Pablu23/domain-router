package middleware

import (
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/urfave/negroni"
)

func RequestLogger(next http.Handler) http.Handler {
  log.Info().Msg("Enabling Logging")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		lrw := negroni.NewResponseWriter(w)
		next.ServeHTTP(lrw, r)

		duration := time.Since(start)
		if duration.Milliseconds() > 500 {
			log.Warn().Str("host", r.Host).Str("uri", r.RequestURI).Str("method", r.Method).Int("status", lrw.Status()).Int("size", lrw.Size()).Str("duration", duration.String()).Msg("Slow Request")
		} else {
			log.Info().Str("host", r.Host).Str("uri", r.RequestURI).Str("method", r.Method).Int("status", lrw.Status()).Int("size", lrw.Size()).Str("duration", duration.String()).Msg("Received Request")
		}
	})
}
