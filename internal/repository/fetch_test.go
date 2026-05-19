package repository_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/peios/peipkg/internal/repository"
)

func TestHTTPFetcher(t *testing.T) {
	body := []byte("the repository descriptor")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repo.json" {
			_, _ = w.Write(body)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	f := repository.NewHTTPFetcher()

	got, err := f.Fetch(t.Context(), srv.URL+"/repo.json", 1<<20)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(got) != string(body) {
		t.Errorf("Fetch body: got %q, want %q", got, body)
	}

	if _, err := f.Fetch(t.Context(), srv.URL+"/missing", 1<<20); err == nil {
		t.Error("Fetch of a 404 should fail")
	}
	if _, err := f.Fetch(t.Context(), srv.URL+"/repo.json", 4); err == nil {
		t.Error("Fetch of a body exceeding the limit should fail")
	}
}
