package embed

import (
	"context"
	"sync"
	"time"
)

type CircuitState string

const (
	CircuitClosed   CircuitState = "closed"
	CircuitOpen     CircuitState = "open"
	CircuitHalfOpen CircuitState = "half_open"
)

type CircuitClient struct {
	Inner       Client
	FailureMax  int
	OpenBackoff time.Duration

	mu          sync.Mutex
	state       CircuitState
	failures    int
	openedUntil time.Time
}

func NewCircuitClient(inner Client) *CircuitClient {
	return &CircuitClient{
		Inner:       inner,
		FailureMax:  3,
		OpenBackoff: 10 * time.Second,
		state:       CircuitClosed,
	}
}

func (c *CircuitClient) State() CircuitState {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == CircuitOpen && time.Now().After(c.openedUntil) {
		c.state = CircuitHalfOpen
	}
	return c.state
}

func (c *CircuitClient) Embed(ctx context.Context, texts []string, kind Kind) ([][]float32, error) {
	if c.State() == CircuitOpen {
		return nil, ErrCircuitOpen
	}
	vectors, err := c.Inner.Embed(ctx, texts, kind)
	c.record(err)
	return vectors, err
}

func (c *CircuitClient) Health(ctx context.Context) error {
	if c.State() == CircuitOpen {
		return ErrCircuitOpen
	}
	err := c.Inner.Health(ctx)
	c.record(err)
	return err
}

func (c *CircuitClient) record(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		c.failures = 0
		c.state = CircuitClosed
		return
	}
	c.failures++
	if c.failures >= c.FailureMax {
		c.state = CircuitOpen
		c.openedUntil = time.Now().Add(c.OpenBackoff)
	}
}

var ErrCircuitOpen = errCircuitOpen{}

type errCircuitOpen struct{}

func (errCircuitOpen) Error() string { return "embedding circuit breaker is open" }
