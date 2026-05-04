package inspector

import "testing"

func TestExtractHTTPHost(t *testing.T) {
	t.Parallel()

	payload := []byte("GET / HTTP/1.1\r\nHost: blocked.example:8080\r\nUser-Agent: test\r\n\r\n")
	host, ok := ExtractHTTPHost(payload)
	if !ok {
		t.Fatal("expected host to be extracted")
	}
	if host != "blocked.example" {
		t.Fatalf("unexpected host: %q", host)
	}
}

func TestExtractHTTPHostMissingHeader(t *testing.T) {
	t.Parallel()

	payload := []byte("GET / HTTP/1.1\r\nUser-Agent: test\r\n\r\n")
	if _, ok := ExtractHTTPHost(payload); ok {
		t.Fatal("expected extraction to fail when host header is missing")
	}
}
