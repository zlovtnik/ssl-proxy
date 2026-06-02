package ingest

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/config"
)

const (
	freshnessDebounceInterval = 750 * time.Millisecond
	freshnessRetryInterval    = 5 * time.Second
	freshnessMaxPending       = 256
)

func StartFreshnessConsumer(ctx context.Context, pool *pgxpool.Pool, cfg config.Config, logger zerolog.Logger) {
	if !cfg.IngestEnabled {
		logger.Info().Msg("redpanda freshness consumer disabled")
		return
	}
	if strings.TrimSpace(cfg.RedpandaBootstrap) == "" {
		logger.Warn().Msg("redpanda bootstrap is empty; using periodic freshness refresh fallback")
		startPollingFreshnessRefresher(ctx, pool, cfg, logger)
		return
	}

	go func() {
		if err := runKafkaFreshnessConsumer(ctx, pool, cfg, logger); err != nil {
			logger.Error().Err(err).Msg("redpanda freshness consumer stopped")
		}
	}()
}

func startPollingFreshnessRefresher(ctx context.Context, pool *pgxpool.Pool, cfg config.Config, logger zerolog.Logger) {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := runFreshnessMaintenance(ctx, pool, cfg); err != nil {
					logger.Warn().Err(err).Msg("embedding job enqueue refresh failed")
				}
			}
		}
	}()
}

func runKafkaFreshnessConsumer(ctx context.Context, pool *pgxpool.Pool, cfg config.Config, logger zerolog.Logger) error {
	consumer, err := kafka.NewConsumer(&kafka.ConfigMap{
		"bootstrap.servers":  cfg.RedpandaBootstrap,
		"group.id":           cfg.ConsumerGroup,
		"auto.offset.reset":  "earliest",
		"enable.auto.commit": false,
	})
	if err != nil {
		return err
	}
	defer consumer.Close()

	topics := uniqueTopics(cfg.AuditTopic, cfg.BandwidthTopic)
	if err := consumer.SubscribeTopics(topics, nil); err != nil {
		return err
	}
	logger.Info().Strs("topics", topics).Str("bootstrap", cfg.RedpandaBootstrap).Msg("redpanda freshness consumer started")

	pending := map[string]*kafka.Message{}
	var flushAt time.Time
	for ctx.Err() == nil {
		event := consumer.Poll(250)
		now := time.Now()
		switch value := event.(type) {
		case *kafka.Message:
			pending[topicPartitionKey(value.TopicPartition)] = value
			if flushAt.IsZero() {
				flushAt = now.Add(freshnessDebounceInterval)
			}
		case kafka.Error:
			if value.IsFatal() {
				return value
			}
			logger.Debug().Err(value).Msg("redpanda poll error")
		}

		shouldFlush := len(pending) >= freshnessMaxPending || (!flushAt.IsZero() && !now.Before(flushAt))
		if shouldFlush {
			if err := runFreshnessMaintenance(ctx, pool, cfg); err != nil {
				logger.Warn().Err(err).Int("pending_offsets", len(pending)).Msg("freshness maintenance failed; offsets not committed")
				flushAt = time.Now().Add(freshnessRetryInterval)
				continue
			}
			if err := commitPendingMessages(consumer, pending); err != nil {
				logger.Warn().Err(err).Int("pending_offsets", len(pending)).Msg("redpanda offset commit failed")
				flushAt = time.Now().Add(freshnessRetryInterval)
				continue
			}
			pending = map[string]*kafka.Message{}
			flushAt = time.Time{}
		}
	}
	return nil
}

func runFreshnessMaintenance(ctx context.Context, pool *pgxpool.Pool, cfg config.Config) error {
	_, err := pool.Exec(ctx, "SELECT vec_enqueue_embedding_jobs($1)", cfg.EmbeddingModel)
	return err
}

func commitPendingMessages(consumer *kafka.Consumer, pending map[string]*kafka.Message) error {
	keys := make([]string, 0, len(pending))
	for key := range pending {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if _, err := consumer.CommitMessage(pending[key]); err != nil {
			return err
		}
	}
	return nil
}

func uniqueTopics(values ...string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func topicPartitionKey(tp kafka.TopicPartition) string {
	topic := ""
	if tp.Topic != nil {
		topic = *tp.Topic
	}
	return fmt.Sprintf("%s:%s", topic, strconv.Itoa(int(tp.Partition)))
}
