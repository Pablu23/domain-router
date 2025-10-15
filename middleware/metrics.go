package middleware

import (
	"cmp"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

type Metrics struct {
	c               chan RequestMetric
	endpointMetrics []EndpointMetrics
	ticker          *time.Ticker
	file            string
	stop            chan struct{}
}

type EndpointMetrics struct {
	Host             string
	Endpoint         string
	AbsoluteDuration time.Duration
	Calls            uint64
}

type RequestMetric struct {
	Start  time.Time
	Stop   time.Time
	Host   string
	Method string
	Uri    string
	Status int
	Size   int
}

func NewMetrics(bufferSize int, flushTimeout time.Duration, file string) *Metrics {
	return &Metrics{
		c:      make(chan RequestMetric, bufferSize),
		ticker: time.NewTicker(flushTimeout),
		file:   file,
	}
}

func (m *Metrics) Use(next http.Handler) http.Handler {
	log.Info().Msg("Enabling Request Metrics")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rm := RequestMetric{
			Start:  start,
			Host:   r.Host,
			Method: r.Method,
			Uri:    r.URL.Path,
		}

		log.Trace().Any("request_metric", rm).Msg("RequestMetric created")
		next.ServeHTTP(w, r)
		rm.Stop = time.Now()
		log.Trace().Any("request_metric", rm).Msg("RequestMetric finished")

		m.c <- rm
	})
}

func (m *Metrics) Manage() {
	for {
		select {
		case rm := <-m.c:
			m.calculateDuration(rm)
		case <-m.ticker.C:
			m.Flush()
		case <-m.stop:
			return
		}
	}
}

func (m *Metrics) calculateDuration(rm RequestMetric) {
	duration := rm.Stop.Sub(rm.Start)

	// TODO: Replace this with a hash probably
	index := slices.IndexFunc(m.endpointMetrics, func(e EndpointMetrics) bool {
		if strings.EqualFold(e.Host, rm.Host) && strings.EqualFold(e.Endpoint, rm.Uri) {
			return true
		}
		return false
	})

	var in EndpointMetrics
	if index >= 0 {
		in = m.endpointMetrics[index]
	} else {
		in = EndpointMetrics{
			Host:             rm.Host,
			Endpoint:         rm.Uri,
			AbsoluteDuration: time.Duration(0),
			Calls:            0,
		}
	}

	in.AbsoluteDuration += duration
	in.Calls += 1

	if index >= 0 {
		m.endpointMetrics[index] = in
	} else {
		m.endpointMetrics = append(m.endpointMetrics, in)
	}
}

func (m *Metrics) Flush() {
	file, err := os.Create(m.file)
	if err != nil {
		log.Error().Err(err).Str("file", m.file).Msg("Could not open file for flushing")
		return
	}

	a := make([]EndpointMetrics, len(m.endpointMetrics))
	copy(a, m.endpointMetrics)
	slices.SortStableFunc(a, func(e1 EndpointMetrics, e2 EndpointMetrics) int {
		return cmp.Compare(e1.Calls, e2.Calls)
	})

	err = json.NewEncoder(file).Encode(a)
	if err != nil {
		log.Error().Err(err).Str("file", m.file).Msg("Could not json Encode to file")
		return
	}

	log.Debug().Str("file", m.file).Int("count", len(a)).Msg("Completed Metrics flush")
}

func (m *Metrics) Stop(ctx context.Context) {
	log.Info().Msg("Stopping Request Metrics")
	for len(m.c) > 0 {
		select {
		case rm := <-m.c:
			m.calculateDuration(rm)
		case <-ctx.Done():
			m.stop <- struct{}{}
			log.Warn().Msg("Hard Stopped Request Metrics")
			return
		}
	}
	m.Flush()
	m.stop <- struct{}{}
	log.Info().Msg("Stopped Request Metrics")
}
