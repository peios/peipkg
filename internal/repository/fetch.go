package repository

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Fetch size limits for repository metadata, bounding a hostile or
// misconfigured server's response.
const (
	maxDescriptorFetch = 4 << 20  // repo.json
	maxSignatureFetch  = 4 << 10  // a detached .sig file
	maxKeyFetch        = 64 << 10 // a public key file
	maxIndexFetch      = 64 << 20 // an active or archive index
)

// Fetcher retrieves the bytes at a URL, up to limit bytes. The HTTP
// implementation is the production one; tests substitute an in-memory
// fetcher.
type Fetcher interface {
	Fetch(ctx context.Context, url string, limit int64) ([]byte, error)
}

// HTTPFetcher is the production [Fetcher]: a plain HTTP(S) GET.
type HTTPFetcher struct {
	client *http.Client
}

// NewHTTPFetcher returns an HTTPFetcher with a request timeout.
func NewHTTPFetcher() *HTTPFetcher {
	return &HTTPFetcher{client: &http.Client{Timeout: 60 * time.Second}}
}

// Fetch performs a GET, rejecting a non-200 response or a body that
// exceeds limit.
func (f *HTTPFetcher) Fetch(ctx context.Context, rawURL string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("peipkg/repository: building request for %s: %w", rawURL, err)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("peipkg/repository: fetching %s: %w", rawURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("peipkg/repository: fetching %s: HTTP %s", rawURL, resp.Status)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("peipkg/repository: reading %s: %w", rawURL, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("peipkg/repository: %s exceeds the %d-byte limit", rawURL, limit)
	}
	return data, nil
}

// resolveURL resolves a URL reference appearing in a descriptor or
// index (§6.4.5) and enforces the transport policy: the result must use
// https unless allowInsecure permits http.
//
// base is the repository base (no trailing slash); documentURL is the
// URL of the document the reference appeared in, for RFC 3986
// document-relative resolution.
func resolveURL(base, documentURL, ref string, allowInsecure bool) (string, error) {
	resolved, err := resolveReference(base, documentURL, ref)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(resolved)
	if err != nil {
		return "", fmt.Errorf("peipkg/repository: resolved URL %q is invalid: %w", resolved, err)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !allowInsecure {
			return "", fmt.Errorf("peipkg/repository: %q uses http but the "+
				"repository does not permit insecure transport", resolved)
		}
	default:
		return "", fmt.Errorf("peipkg/repository: %q must use http or https", resolved)
	}
	return resolved, nil
}

// resolveReference applies the §6.4.5 resolution rules: an absolute URL
// is used as-is; a /-rooted URL is prepended with the repository base;
// any other reference resolves against the document URL per RFC 3986.
func resolveReference(base, documentURL, ref string) (string, error) {
	if u, err := url.Parse(ref); err == nil && u.IsAbs() {
		return ref, nil
	}
	if strings.HasPrefix(ref, "/") {
		return base + ref, nil
	}
	doc, err := url.Parse(documentURL)
	if err != nil {
		return "", fmt.Errorf("peipkg/repository: invalid document URL %q: %w", documentURL, err)
	}
	rel, err := url.Parse(ref)
	if err != nil {
		return "", fmt.Errorf("peipkg/repository: invalid URL reference %q: %w", ref, err)
	}
	return doc.ResolveReference(rel).String(), nil
}
