package embed

import (
	"errors"
	"time"
)

// ErrBackendUnavailable identifies failures for which durable worker jobs must
// be deferred instead of consuming a retry attempt.
var ErrBackendUnavailable = errors.New("embedding backend unavailable")

type BackendUnavailableError struct {
	RetryAt time.Time
	Cause   error
}

func (err *BackendUnavailableError) Error() string {
	if err.Cause == nil {
		return ErrBackendUnavailable.Error()
	}
	return ErrBackendUnavailable.Error() + ": " + err.Cause.Error()
}
func (err *BackendUnavailableError) Unwrap() error        { return err.Cause }
func (err *BackendUnavailableError) Is(target error) bool { return target == ErrBackendUnavailable }

func RetryTime(err error) (time.Time, bool) {
	var unavailable *BackendUnavailableError
	if errors.As(err, &unavailable) {
		return unavailable.RetryAt, true
	}
	return time.Time{}, false
}
