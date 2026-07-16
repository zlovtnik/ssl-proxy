package worker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"

	"github.com/jackc/pgx/v5/pgconn"
)

const maxErrorSampleLength = 512

type sqlStateError interface {
	SQLState() string
}

func isTransientDatabaseError(err error) bool {
	if err == nil {
		return false
	}
	var stateErr sqlStateError
	if errors.As(err, &stateErr) {
		state := stateErr.SQLState()
		if strings.HasPrefix(state, "08") || strings.HasPrefix(state, "53") {
			return true
		}
		switch state {
		case "57P01", "57P02", "57P03":
			return true
		}
	}
	if errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return pgconn.Timeout(err) || pgconn.SafeToRetry(err)
}

func shouldDeferDatabaseOperation(ctx context.Context, err error) bool {
	return err != nil && (isTransientDatabaseError(err) || errors.Is(err, context.Canceled) || isTransientDatabaseError(context.Cause(ctx)))
}

func databaseUnavailableCause(ctx context.Context, err error) error {
	if isTransientDatabaseError(err) {
		return err
	}
	cause := context.Cause(ctx)
	if isTransientDatabaseError(cause) {
		return cause
	}
	return nil
}

func deferredReason(ctx context.Context, err error) string {
	if databaseUnavailableCause(ctx, err) != nil {
		return deferredReasonDatabaseUnavailable
	}
	return "canceled"
}

type boundedErrors struct {
	label     string
	count     int
	first     error
	transient error
}

func newBoundedErrors(label string) *boundedErrors {
	return &boundedErrors{label: label}
}

func (e *boundedErrors) Add(err error) {
	if err == nil {
		return
	}
	e.count++
	if e.first == nil {
		e.first = err
	}
	if e.transient == nil && isTransientDatabaseError(err) {
		e.transient = err
	}
}

func (e *boundedErrors) Err() error {
	if e.count == 0 {
		return nil
	}
	return boundedErrorSummary{
		label:     e.label,
		count:     e.count,
		first:     e.first,
		transient: e.transient,
	}
}

type boundedErrorSummary struct {
	label     string
	count     int
	first     error
	transient error
}

func (e boundedErrorSummary) Error() string {
	sample := "unknown error"
	if e.first != nil {
		sample = e.first.Error()
	}
	if len(sample) > maxErrorSampleLength {
		sample = sample[:maxErrorSampleLength] + "..."
	}
	return fmt.Sprintf("%s: %d errors (first: %s)", e.label, e.count, sample)
}

func (e boundedErrorSummary) Unwrap() []error {
	if e.transient != nil && !errors.Is(e.first, e.transient) {
		return []error{e.first, e.transient}
	}
	return []error{e.first}
}
