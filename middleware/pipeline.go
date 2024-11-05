package middleware

import (
	"net/http"
	"slices"
)

type Middleware func(http.Handler) http.Handler

func Pipeline(funcs ...Middleware) Middleware {
	return func(next http.Handler) http.Handler {
		for _, m := range slices.Backward(funcs) {
			next = m(next)
		}

		return next
	}
}
