package repository

import "testing"

func TestResolveURL(t *testing.T) {
	const base = "https://repo.example.org"
	const doc = base + "/repo.json"

	cases := []struct {
		name          string
		ref           string
		allowInsecure bool
		want          string
		wantErr       bool
	}{
		{name: "rooted reference", ref: "/index/active.json", want: base + "/index/active.json"},
		{name: "absolute https", ref: "https://cdn.example.org/i.json",
			want: "https://cdn.example.org/i.json"},
		{name: "document-relative", ref: "keys/k.pub", want: base + "/keys/k.pub"},
		{name: "absolute http rejected", ref: "http://cdn.example.org/i.json", wantErr: true},
		{name: "absolute http allowed", ref: "http://cdn.example.org/i.json",
			allowInsecure: true, want: "http://cdn.example.org/i.json"},
		{name: "non-http scheme rejected", ref: "ftp://x.example.org/i.json", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveURL(base, doc, tc.ref, tc.allowInsecure)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected an error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveURL: %v", err)
			}
			if got != tc.want {
				t.Errorf("resolveURL = %q, want %q", got, tc.want)
			}
		})
	}
}
