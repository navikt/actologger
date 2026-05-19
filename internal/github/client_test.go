package github

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"testing"

	go_github "github.com/google/go-github/v74/github"
)

func TestIsTransient(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "eof", err: io.EOF, want: true},
		{name: "url-timeout", err: &url.Error{Op: "Get", URL: "https://example.com", Err: timeoutError{}}, want: true},
		{name: "message-match", err: errors.New("read: connection reset by peer"), want: true},
		{name: "plain", err: errors.New("boom"), want: false},
		{name: "github-502", err: &go_github.ErrorResponse{Response: &http.Response{StatusCode: http.StatusBadGateway}}, want: true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isTransient(tt.err); got != tt.want {
				t.Fatalf("isTransient(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
