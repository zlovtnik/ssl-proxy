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
	SearchRequests        *prometheus.CounterVec
	SearchLatency         *prometheus.HistogramVec
	ResultsReturned       *prometheus.CounterVec
	EmbeddingCacheHits    prometheus.Counter
	EmbeddingCacheMiss    prometheus.Counter
	EmbeddingJobsQueued   prometheus.Counter
	WorkerJobsLeased      *prometheus.CounterVec
	WorkerJobsCompleted   *prometheus.CounterVec
	WorkerJobsFailed      *prometheus.CounterVec
	WorkerJobsPermanent   *prometheus.CounterVec
	WorkerPrepareLatency  prometheus.Histogram
	WorkerEmbedLatency    prometheus.Histogram
	WorkerCompleteLatency prometheus.Histogram
	WorkerBatchSize       prometheus.Histogram
	WorkerQueueDepth      prometheus.Gauge
	AlertsInserted        *prometheus.CounterVec
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
		EmbeddingJobsQueued: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "athsearch_embedding_jobs_enqueued_total",
			Help: "Embedding jobs enqueued by search ingest.",
		}),
		WorkerJobsLeased: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "athsearch_worker_jobs_leased_total",
			Help: "Embedding jobs leased by the worker.",
		}, []string{"kind"}),
		WorkerJobsCompleted: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "athsearch_worker_jobs_completed_total",
			Help: "Embedding jobs completed by the worker.",
		}, []string{"kind"}),
		WorkerJobsFailed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "athsearch_worker_jobs_failed_total",
			Help: "Embedding jobs retried after worker failures.",
		}, []string{"kind", "failure_type"}),
		WorkerJobsPermanent: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "athsearch_worker_jobs_permanent_total",
			Help: "Embedding jobs permanently failed by the worker.",
		}, []string{"kind"}),
		WorkerPrepareLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "athsearch_worker_prepare_latency_ms",
			Help:    "Worker job preparation latency in milliseconds.",
			Buckets: []float64{5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000},
		}),
		WorkerEmbedLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "athsearch_worker_embed_latency_ms",
			Help:    "Worker embedding provider latency in milliseconds.",
			Buckets: []float64{25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000},
		}),
		WorkerCompleteLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "athsearch_worker_complete_latency_ms",
			Help:    "Worker embedding completion latency in milliseconds.",
			Buckets: []float64{5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000},
		}),
		WorkerBatchSize: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "athsearch_worker_batch_size",
			Help:    "Number of jobs in each leased worker batch.",
			Buckets: []float64{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024},
		}),
		WorkerQueueDepth: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "athsearch_worker_queue_depth",
			Help: "Current count of pending or failed embedding jobs.",
		}),
		AlertsInserted: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "athsearch_alerts_inserted_total",
			Help: "Alerts inserted by alert type.",
		}, []string{"alert_type"}),
	}
	prometheus.MustRegister(
		m.SearchRequests,
		m.SearchLatency,
		m.ResultsReturned,
		m.EmbeddingCacheHits,
		m.EmbeddingCacheMiss,
		m.EmbeddingJobsQueued,
		m.WorkerJobsLeased,
		m.WorkerJobsCompleted,
		m.WorkerJobsFailed,
		m.WorkerJobsPermanent,
		m.WorkerPrepareLatency,
		m.WorkerEmbedLatency,
		m.WorkerCompleteLatency,
		m.WorkerBatchSize,
		m.WorkerQueueDepth,
		m.AlertsInserted,
	)
	return m
}

func (m *Metrics) ObserveSearch(kind, mode, status string, started time.Time, results int) {
	m.SearchRequests.WithLabelValues(kind, mode, status).Inc()
	m.SearchLatency.WithLabelValues(kind, mode).Observe(float64(time.Since(started).Milliseconds()))
	m.ResultsReturned.WithLabelValues(kind).Add(float64(results))
}

func (m *Metrics) SetWorkerQueueDepth(depth int64) {
	m.WorkerQueueDepth.Set(float64(depth))
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
