package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

const (
	testKey    = "stats:current:v2"
	testBucket = "ssl-proxy-stats"
	testObject = "stats/latest.json"
)

type fakeRedis struct {
	value   []byte
	err     error
	pingErr error
	gets    int
}

func (f *fakeRedis) Get(context.Context, string) ([]byte, error) {
	f.gets++
	if f.err != nil {
		return nil, f.err
	}
	if f.value == nil {
		return nil, errors.New("redis: nil")
	}
	return f.value, nil
}

func (f *fakeRedis) Ping(context.Context) error { return f.pingErr }

type fakeObjects struct {
	value     []byte
	err       error
	exists    bool
	bucketErr error
	gets      int
}

func (f *fakeObjects) GetObject(context.Context, string, string) ([]byte, error) {
	f.gets++
	if f.err != nil {
		return nil, f.err
	}
	if f.value == nil {
		return nil, errors.New("no such key")
	}
	return f.value, nil
}

func (f *fakeObjects) BucketExists(context.Context, string) (bool, error) {
	return f.exists, f.bucketErr
}

func newStore(r *fakeRedis, o *fakeObjects) *Store {
	return New(r, o, testKey, testBucket, testObject)
}

func TestSnapshotRedisHit(t *testing.T) {
	want := []byte(`{"asOf":"2026-01-01T00:00:00Z","peakRecordsDay":7}`)
	r := &fakeRedis{value: want}
	o := &fakeObjects{}
	got, err := newStore(r, o).Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("got %s, want %s", got, want)
	}
	if o.gets != 0 {
		t.Fatalf("MinIO should not be read on Redis hit, got %d reads", o.gets)
	}
}

func TestSnapshotRedisMissFallsBackToMinio(t *testing.T) {
	want := []byte(`{"asOf":"2026-01-01T00:00:00Z"}`)
	r := &fakeRedis{err: errors.New("redis: nil")}
	o := &fakeObjects{value: want}
	got, err := newStore(r, o).Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestSnapshotRedisInvalidFallsBackToMinio(t *testing.T) {
	want := []byte(`{"asOf":"2026-01-02T00:00:00Z"}`)
	r := &fakeRedis{value: []byte(`{"noAsOf":true}`)}
	o := &fakeObjects{value: want}
	got, err := newStore(r, o).Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestSnapshotLastGoodWhenBothFail(t *testing.T) {
	good := []byte(`{"asOf":"2026-01-03T00:00:00Z"}`)
	r := &fakeRedis{value: good}
	o := &fakeObjects{}
	st := newStore(r, o)
	if _, err := st.Snapshot(context.Background()); err != nil {
		t.Fatalf("prime Snapshot: %v", err)
	}

	r.value = nil
	r.err = errors.New("connection refused")
	o.err = errors.New("no such key")

	got, err := st.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot after outages: %v", err)
	}
	if string(got) != string(good) {
		t.Fatalf("got %s, want last-good %s", got, good)
	}
}

func TestSnapshotCannotRegressLastGood(t *testing.T) {
	good := []byte(`{"asOf":"2026-01-03T00:00:00.123456789Z"}`)
	r := &fakeRedis{value: good}
	st := newStore(r, &fakeObjects{})
	if _, err := st.Snapshot(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.value = []byte(`{"asOf":"2026-01-03T00:00:00.123Z"}`)
	got, err := st.Snapshot(context.Background())
	if err != nil || string(got) != string(good) {
		t.Fatalf("older store snapshot displaced last-good: %s, %v", got, err)
	}
}

type stalledRedis struct{ fakeRedis }

func (*stalledRedis) Get(ctx context.Context, _ string) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestSnapshotTimeoutStillReachesHistoricalStore(t *testing.T) {
	want := []byte(`{"asOf":"2026-01-03T00:00:00Z"}`)
	st := New(&stalledRedis{}, &fakeObjects{value: want}, testKey, testBucket, testObject)
	started := time.Now()
	got, err := st.Snapshot(context.Background())
	if err != nil || string(got) != string(want) {
		t.Fatalf("timeout did not fall back to history: %s, %v", got, err)
	}
	if time.Since(started) > sourceTimeout+time.Second {
		t.Fatal("historical fallback exceeded source deadline")
	}
}

func TestSnapshotInvalidTimestampFallsBack(t *testing.T) {
	want := []byte(`{"asOf":"2026-01-03T00:00:00Z"}`)
	for _, invalid := range []string{
		`{"asOf":"invalid"}`,
		`{"asOf":"2999-01-01T00:00:00Z"}`,
	} {
		got, err := newStore(&fakeRedis{value: []byte(invalid)}, &fakeObjects{value: want}).Snapshot(context.Background())
		if err != nil || string(got) != string(want) {
			t.Fatalf("invalid timestamp prevented fallback: %s, %v", got, err)
		}
	}
}

func TestSnapshotUnavailableWhenAllFail(t *testing.T) {
	r := &fakeRedis{err: errors.New("connection refused")}
	o := &fakeObjects{err: errors.New("no such key")}
	_, err := newStore(r, o).Snapshot(context.Background())
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
}

func TestSnapshotRejectsMissingAsOf(t *testing.T) {
	r := &fakeRedis{value: []byte(`{"peakRecordsDay":0}`)}
	o := &fakeObjects{value: []byte(`{"lifetimeTotals":{"recordsTotal":0}}`)}
	_, err := newStore(r, o).Snapshot(context.Background())
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable for payloads without asOf", err)
	}
}

func TestSnapshotRejectsNonObjectPayload(t *testing.T) {
	r := &fakeRedis{value: []byte(`"just a string"`)}
	o := &fakeObjects{value: []byte(`[1,2,3]`)}
	_, err := newStore(r, o).Snapshot(context.Background())
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable for non-object payloads", err)
	}
}

func TestHealth(t *testing.T) {
	r := &fakeRedis{}
	o := &fakeObjects{exists: true}
	redisOK, minioOK := newStore(r, o).Health(context.Background())
	if !redisOK || !minioOK {
		t.Fatalf("health = (%v,%v), want (true,true)", redisOK, minioOK)
	}

	r.pingErr = errors.New("down")
	o.exists = false
	redisOK, minioOK = newStore(r, o).Health(context.Background())
	if redisOK || minioOK {
		t.Fatalf("health = (%v,%v), want (false,false)", redisOK, minioOK)
	}
}
