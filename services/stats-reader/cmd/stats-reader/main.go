// Command stats-reader serves precomputed public stats from Redis and
// MinIO. It is intentionally passive: no Postgres, no Kafka, no compute.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/redis/go-redis/v9"

	"github.com/zlovtnik/ssl-proxy/services/stats-reader/internal/config"
	httpsrv "github.com/zlovtnik/ssl-proxy/services/stats-reader/internal/http"
	"github.com/zlovtnik/ssl-proxy/services/stats-reader/internal/store"
)

func main() {
	cfg := config.Load()

	rdb := redis.NewClient(&redis.Options{
		Addr:                  cfg.RedisAddr,
		Password:              cfg.RedisPassword,
		ContextTimeoutEnabled: true,
		DialTimeout:           2 * time.Second,
		ReadTimeout:           2 * time.Second,
		WriteTimeout:          2 * time.Second,
		MaxRetries:            -1,
	})
	defer rdb.Close()

	mclient, err := minio.New(cfg.MinioEndpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.MinioAccessKey, cfg.MinioSecretKey, ""),
		Secure: cfg.MinioUseSSL,
	})
	if err != nil {
		log.Fatalf("stats-reader: minio client: %v", err)
	}

	st := store.New(
		store.NewRedisClient(rdb),
		store.NewMinioObjects(mclient),
		cfg.RedisKey,
		cfg.MinioStatsBucket,
		cfg.ObjectKey(),
	)

	srv := &http.Server{
		Addr:              ":" + strconv.Itoa(cfg.HTTPPort),
		Handler:           httpsrv.New(st, cfg.AllowedOrigins).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Printf("stats-reader: listening on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("stats-reader: serve: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("stats-reader: shutdown: %v", err)
	}
}
