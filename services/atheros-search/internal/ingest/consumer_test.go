package ingest

import (
	"testing"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/stretchr/testify/require"
)

func TestUniqueTopicsTrimsAndDedupes(t *testing.T) {
	got := uniqueTopics(" wireless.audit ", "", "audit.wireless.bandwidth", "wireless.audit")

	require.Equal(t, []string{"wireless.audit", "audit.wireless.bandwidth"}, got)
}

func TestTopicPartitionKeyIncludesTopicAndPartition(t *testing.T) {
	topic := "wireless.audit"
	got := topicPartitionKey(kafka.TopicPartition{Topic: &topic, Partition: 3})

	require.Equal(t, "wireless.audit:3", got)
}
