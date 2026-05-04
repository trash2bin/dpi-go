package inspector

import (
	"net"
	"strings"
)

// ExtractHTTPHost extracts the Host header from an HTTP request payload.
func ExtractHTTPHost(payload []byte) (string, bool) {
	if len(payload) == 0 {
		return "", false
	}

	text := string(payload)
	lines := strings.Split(text, "\r\n")
	if len(lines) == 0 || !looksLikeHTTPRequestLine(lines[0]) {
		return "", false
	}

	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(parts[0]), "host") {
			continue
		}

		host := normalizeHost(parts[1])
		if host == "" {
			return "", false
		}
		return host, true
	}

	return "", false
}

func looksLikeHTTPRequestLine(line string) bool {
	methods := []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "}
	for _, method := range methods {
		if strings.HasPrefix(line, method) {
			return true
		}
	}
	return false
}

func normalizeHost(value string) string {
	host := strings.ToLower(strings.TrimSpace(value))
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return ""
	}

	if strings.HasPrefix(host, "[") {
		if parsedHost, _, err := net.SplitHostPort(host); err == nil {
			host = parsedHost
		}
	} else if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	} else if strings.Count(host, ":") == 1 {
		parts := strings.SplitN(host, ":", 2)
		host = parts[0]
	}

	host = strings.Trim(host, "[]")
	return strings.TrimSuffix(host, ".")
}
