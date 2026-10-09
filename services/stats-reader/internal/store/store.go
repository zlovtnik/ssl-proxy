// Package store reads precomputed stats snapshots from Redis and MinIO,
// keeping an in-process last-good copy as a final fallback.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"

	"github.com/minio/minio-go/v7"
	"github.com/redis/go-redis/v9"
)

// ErrUnavailable is returned when no source can produce a snapshot.
var ErrUnavailable = errors.New("metrics unavailable")

// Redis is the hot snapshot source.
type Redis interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Ping(ctx context.Context) error
}

// Objects is the object-store snapshot source.
type Objects interface {
	GetObject(ctx context.Context, bucket, key string) ([]byte, error)
	BucketExists(ctx context.Context, bucket string) (bool, error)
}

// Store resolves snapshots in order: Redis, MinIO, then the in-process
// last-good copy. It never synthesizes snapshot content.
type Store struct {
	redis     Redis
	objects   Objects
	redisKey  string
	bucket    string
	objectKey string

	mu       sync.RWMutex
	lastGood []byte
}

// New builds a Store. objectKey is the full object path inside bucket.
func New(redis Redis, objects Objects, redisKey, bucket, objectKey string) *Store {
	return &Store{
		redis:     redis,
		objects:   objects,
		redisKey:  redisKey,
		bucket:    bucket,
		objectKey: objectKey,
	}
}

// Snapshot returns the freshest valid snapshot bytes available. A source
// hit only counts when the payload parses and carries asOf.
func (s *Store) Snapshot(ctx context.Context) ([]byte, error) {
	if raw, err := s.redis.Get(ctx, s.redisKey); err == nil {
		if _, vErr := validate(raw); vErr == nil {
			s.setLastGood(raw)
			return raw, nil
		}
	}
	if raw, err := s.objects.GetObject(ctx, s.bucket, s.objectKey); err == nil {
		if _, vErr := validate(raw); vErr == nil {
			s.setLastGood(raw)
			return raw, nil
		}
	}
	if raw := s.getLastGood(); raw != nil {
		return raw, nil
	}
	return nil, ErrUnavailable
}

// Health reports store reachability for the operator endpoint. It never
// gates process readiness.
func (s *Store) Health(ctx context.Context) (redisOK, minioOK bool) {
	redisOK = s.redis.Ping(ctx) == nil
	if ok, err := s.objects.BucketExists(ctx, s.bucket); err == nil && ok {
		minioOK = true
	}
	return redisOK, minioOK
}

func (s *Store) setLastGood(raw []byte) {
	kept := make([]byte, len(raw))
	copy(kept, raw)
	s.mu.Lock()
	s.lastGood = kept
	s.mu.Unlock()
}

func (s *Store) getLastGood() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.lastGood == nil {
		return nil
	}
	out := make([]byte, len(s.lastGood))
	copy(out, s.lastGood)
	return out
}

// validate reports whether raw is a snapshot object we are willing to
// serve: it must parse and carry a non-empty string asOf.
func validate(raw []byte) (map[string]any, error) {
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, err
	}
	asOf, ok := obj["asOf"].(string)
	if !ok || asOf == "" {
		return nil, errors.New("snapshot missing asOf")
	}
	return obj, nil
}

// RedisClient adapts go-redis to the Redis interface.
type RedisClient struct {
	client *redis.Client
}

// NewRedisClient wraps a go-redis client.
func NewRedisClient(client *redis.Client) *RedisClient {
	return &RedisClient{client: client}
}

// Get returns the raw value at key, or an error on miss/failure.
func (c *RedisClient) Get(ctx context.Context, key string) ([]byte, error) {
	val, err := c.client.Get(ctx, key).Result()
	if err != nil {
		return nil, err
	}
	return []byte(val), nil
}

// Ping reports whether Redis answers.
func (c *RedisClient) Ping(ctx context.Context) error {
	return c.client.Ping(ctx).Err()
}

// MinioObjects adapts minio-go to the Objects interface.
type MinioObjects struct {
	client *minio.Client
}

// NewMinioObjects wraps a minio-go client.
func NewMinioObjects(client *minio.Client) *MinioObjects {
	return &MinioObjects{client: client}
}

// GetObject returns the object body at bucket/key.
func (m *MinioObjects) GetObject(ctx context.Context, bucket, key string) ([]byte, error) {
	obj, err := m.client.GetObject(ctx, bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	defer obj.Close()
	return io.ReadAll(obj)
}

// BucketExists reports whether bucket is present.
func (m *MinioObjects) BucketExists(ctx context.Context, bucket string) (bool, error) {
	return m.client.BucketExists(ctx, bucket)
}
