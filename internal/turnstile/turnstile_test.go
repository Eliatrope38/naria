package turnstile

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func stub(t *testing.T, status int, body string, seen *map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if seen != nil {
			*seen = map[string]string{
				"secret":   r.PostFormValue("secret"),
				"response": r.PostFormValue("response"),
				"remoteip": r.PostFormValue("remoteip"),
			}
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestVerifyAcceptsValidToken(t *testing.T) {
	var seen map[string]string
	srv := stub(t, http.StatusOK, `{"success":true}`, &seen)
	v := New("sekret").WithEndpoint(srv.URL)
	if err := v.Verify(context.Background(), "tok", "203.0.113.9"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if seen["secret"] != "sekret" || seen["response"] != "tok" || seen["remoteip"] != "203.0.113.9" {
		t.Fatalf("siteverify received %v", seen)
	}
}

func TestVerifyRejectsInvalidToken(t *testing.T) {
	srv := stub(t, http.StatusOK, `{"success":false,"error-codes":["invalid-input-response"]}`, nil)
	err := New("s").WithEndpoint(srv.URL).Verify(context.Background(), "bad", "")
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("want ErrRejected, got %v", err)
	}
}

func TestVerifyRejectsEmptyTokenWithoutRoundTrip(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	t.Cleanup(srv.Close)
	err := New("s").WithEndpoint(srv.URL).Verify(context.Background(), "   ", "")
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("want ErrRejected, got %v", err)
	}
	if called {
		t.Fatal("empty token must not reach siteverify")
	}
}

func TestVerifyTransportErrorIsNotRejected(t *testing.T) {
	srv := stub(t, http.StatusBadGateway, `boom`, nil)
	err := New("s").WithEndpoint(srv.URL).Verify(context.Background(), "tok", "")
	if err == nil || errors.Is(err, ErrRejected) {
		t.Fatalf("want transport error distinct from ErrRejected, got %v", err)
	}
}
