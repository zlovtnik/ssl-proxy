package embed

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"sync"
	"time"
)

type cachedVector struct {
	key       string
	vector    []float32
	expiresAt time.Time
	kind      Kind
}

type QueryCache struct {
	mu         sync.Mutex
	capacity   int
	ttl        time.Duration
	items      map[string]*list.Element
	order      *list.List
	generation map[Kind]uint64
}

func NewQueryCache(capacity int, ttl time.Duration) *QueryCache {
	return &QueryCache{
		capacity:   capacity,
		ttl:        ttl,
		items:      make(map[string]*list.Element),
		order:      list.New(),
		generation: make(map[Kind]uint64),
	}
}

func CacheKey(text string, kind Kind, generation uint64) string {
	sum := sha256.Sum256([]byte(text + "\x00" + string(kind) + "\x00" + strconv.FormatUint(generation, 10)))
	return hex.EncodeToString(sum[:])
}

func (c *QueryCache) Get(text string, kind Kind) ([]float32, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := CacheKey(text, kind, c.generation[kind])
	elem, ok := c.items[key]
	if !ok {
		return nil, false
	}
	item := elem.Value.(cachedVector)
	if time.Now().After(item.expiresAt) {
		c.order.Remove(elem)
		delete(c.items, key)
		return nil, false
	}
	c.order.MoveToFront(elem)
	return append([]float32(nil), item.vector...), true
}

func (c *QueryCache) Put(text string, kind Kind, vector []float32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := CacheKey(text, kind, c.generation[kind])
	if elem, ok := c.items[key]; ok {
		elem.Value = cachedVector{key: key, vector: append([]float32(nil), vector...), expiresAt: time.Now().Add(c.ttl), kind: kind}
		c.order.MoveToFront(elem)
		return
	}
	elem := c.order.PushFront(cachedVector{key: key, vector: append([]float32(nil), vector...), expiresAt: time.Now().Add(c.ttl), kind: kind})
	c.items[key] = elem
	for len(c.items) > c.capacity {
		last := c.order.Back()
		if last == nil {
			break
		}
		item := last.Value.(cachedVector)
		delete(c.items, item.key)
		c.order.Remove(last)
	}
}

func (c *QueryCache) InvalidateKind(kind Kind) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.generation[kind]++
}

type CachedClient struct {
	Inner Client
	Cache *QueryCache
	Hits  func()
	Miss  func()
}

func (c CachedClient) Embed(ctx context.Context, texts []string, kind Kind) ([][]float32, error) {
	if len(texts) != 1 {
		return c.Inner.Embed(ctx, texts, kind)
	}
	if vec, ok := c.Cache.Get(texts[0], kind); ok {
		if c.Hits != nil {
			c.Hits()
		}
		return [][]float32{vec}, nil
	}
	if c.Miss != nil {
		c.Miss()
	}
	vectors, err := c.Inner.Embed(ctx, texts, kind)
	if err != nil {
		return nil, err
	}
	if len(vectors) == 1 {
		c.Cache.Put(texts[0], kind, vectors[0])
	}
	return vectors, nil
}

func (c CachedClient) Health(ctx context.Context) error {
	return c.Inner.Health(ctx)
}
