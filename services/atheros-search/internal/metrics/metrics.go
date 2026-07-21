package metrics

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	SearchRequests     *prometheus.CounterVec
	SearchLatency      *prometheus.HistogramVec
	ResultsReturned    *prometheus.CounterVec
	EmbeddingCacheHits prometheus.Counter
	EmbeddingCacheMiss prometheus.Counter
}

func New() *Metrics {
	m := &Metrics{
		SearchRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "athsearch_search_requests_total",
			Help: "Search requests by kind, mode, and status.",
		}, []string{"kind", "mode", "status"}),
		SearchLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "athsearch_search_latency_ms",
			Help:    "Search request latency in milliseconds.",
			Buckets: []float64{5, 10, 25, 50, 100, 250, 500, 1000, 2500},
		}, []string{"kind", "mode"}),
		ResultsReturned: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "athsearch_results_returned_total",
			Help: "Search results returned by source kind.",
		}, []string{"kind"}),
		EmbeddingCacheHits: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "athsearch_embedding_cache_hits_total",
			Help: "Query embedding cache hits.",
		}),
		EmbeddingCacheMiss: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "athsearch_embedding_cache_misses_total",
			Help: "Query embedding cache misses.",
		}),
	}
	prometheus.MustRegister(
		m.SearchRequests,
		m.SearchLatency,
		m.ResultsReturned,
		m.EmbeddingCacheHits,
		m.EmbeddingCacheMiss,
	)
	return m
}

func (m *Metrics) ObserveSearch(kind, mode, status string, started time.Time, results int) {
	m.SearchRequests.WithLabelValues(kind, mode, status).Inc()
	m.SearchLatency.WithLabelValues(kind, mode).Observe(float64(time.Since(started).Milliseconds()))
	m.ResultsReturned.WithLabelValues(kind).Add(float64(results))
}

func StartServer(ctx context.Context, port int) (*http.Server, error) {
	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           promhttp.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "athsearch metrics server stopped: %v\n", err)
		}
	}()
	return server, nil
}
