package middleware

import (
	"context"
	"net/http"
	"slices"
)

type Middleware interface {
	Use(http.Handler) http.Handler
	Manage()
	Stop(context.Context)
}

type Pipeline struct {
	middleware []Middleware
}

func NewPipeline() *Pipeline {
	return &Pipeline{}
}

func (p *Pipeline) AddMiddleware(m Middleware) {
	p.middleware = append(p.middleware, m)
}

func (p *Pipeline) Use() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		for _, m := range slices.Backward(p.middleware) {
			next = m.Use(next)
		}

		return next
	}
}

func (p *Pipeline) Stop(ctx context.Context) {
	for _, m := range p.middleware {
		m.Stop(ctx)
	}
}

func (p *Pipeline) Manage() {
	for _, m := range p.middleware {
		go m.Manage()
	}
}

// func Pipeline(funcs ...Middleware) func(http.Handler) http.Handler {
// 	return func(next http.Handler) http.Handler {
// 		for _, m := range slices.Backward(funcs) {
// 			next = m.Use(next)
// 		}
//
// 		return next
// 	}
// }
