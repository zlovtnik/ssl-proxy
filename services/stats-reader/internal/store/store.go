// Package store reads precomputed stats snapshots from Redis and MinIO,
// keeping an in-process last-good copy as a final fallback.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/redis/go-redis/v9"
)

// ErrUnavailable is returned when no source can produce a snapshot.
var ErrUnavailable = errors.New("metrics unavailable")

const sourceTimeout = 2 * time.Second
const maxSnapshotBytes = 16384

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

	mu         sync.RWMutex
	lastGood   []byte
	lastGoodAt time.Time
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
	redisCtx, cancelRedis := context.WithTimeout(ctx, sourceTimeout)
	raw, err := s.redis.Get(redisCtx, s.redisKey)
	cancelRedis()
	if err == nil {
		if at, vErr := validate(raw); vErr == nil {
			return s.setLastGood(raw, at), nil
		}
	}
	objectCtx, cancelObject := context.WithTimeout(ctx, sourceTimeout)
	raw, err = s.objects.GetObject(objectCtx, s.bucket, s.objectKey)
	cancelObject()
	if err == nil {
		if at, vErr := validate(raw); vErr == nil {
			return s.setLastGood(raw, at), nil
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

func (s *Store) setLastGood(raw []byte, at time.Time) []byte {
	kept := make([]byte, len(raw))
	copy(kept, raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	// A slow request or an older store must not regress a newer saved snapshot.
	if s.lastGood != nil && at.Before(s.lastGoodAt) {
		return append([]byte(nil), s.lastGood...)
	}
	s.lastGood = kept
	s.lastGoodAt = at
	return append([]byte(nil), kept...)
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
func validate(raw []byte) (time.Time, error) {
	if len(raw) > maxSnapshotBytes {
		return time.Time{}, errors.New("snapshot too large")
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return time.Time{}, err
	}
	asOf, ok := obj["asOf"].(string)
	if !ok || asOf == "" {
		return time.Time{}, errors.New("snapshot missing asOf")
	}
	at, err := time.Parse(time.RFC3339Nano, asOf)
	if err != nil || at.After(time.Now().Add(5*time.Second)) {
		return time.Time{}, errors.New("invalid snapshot timestamp")
	}
	return at, nil
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
	raw, err := io.ReadAll(io.LimitReader(obj, maxSnapshotBytes+1))
	if err == nil && len(raw) > maxSnapshotBytes {
		return nil, errors.New("snapshot too large")
	}
	return raw, err
}

// BucketExists reports whether bucket is present.
func (m *MinioObjects) BucketExists(ctx context.Context, bucket string) (bool, error) {
	return m.client.BucketExists(ctx, bucket)
}
