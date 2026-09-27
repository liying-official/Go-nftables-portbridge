package web

import (
	"errors"
	"net/http"
)

// The legacy error text remains available to API clients. The key and
// arguments let the Web UI render a message in its currently selected language.
type apiMessage struct {
	cause error
	key   string
	args  map[string]any
}

func (e *apiMessage) Error() string { return e.cause.Error() }
func (e *apiMessage) Unwrap() error { return e.cause }

func apiMessageError(err error, key string, args map[string]any) error {
	return &apiMessage{cause: err, key: key, args: args}
}

func writeFixedAPIError(w http.ResponseWriter, status int, key, message string) {
	writeJSON(w, status, APIError{Error: message, MessageKey: key})
}

func writeKeyedAPIError(w http.ResponseWriter, status int, err error, key string, args map[string]any) {
	writeJSON(w, status, APIError{Error: err.Error(), MessageKey: key, MessageArgs: args})
}

func writeAPIError(w http.ResponseWriter, status int, err error) {
	var message *apiMessage
	if errors.As(err, &message) {
		writeKeyedAPIError(w, status, err, message.key, message.args)
		return
	}
	// Lower-level validation and operating-system errors do not have a stable
	// translation key. Keep their exact diagnostic text under a localized label.
	writeKeyedAPIError(w, status, err, "apiErrorDetail", map[string]any{"detail": err.Error()})
}
