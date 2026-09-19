package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
)

var allowedHosts = map[string]bool{
	"api.internal.example.com": true,
	"metrics.internal.example.com": true,
}

func fetchFromBackend(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, "missing target", http.StatusBadRequest)
		return
	}

	// Parse and validate the URL
	parsed, err := url.Parse(target)
	if err != nil {
		http.Error(w, "invalid url", http.StatusBadRequest)
		return
	}

	// Whitelist check: only allow specific internal hosts
	if !allowedHosts[parsed.Host] {
		http.Error(w, "host not allowed", http.StatusForbidden)
		return
	}

	// Build a sanitized request to the internal service
	// Note: we pass the full path from the original query, but host is already validated
	reqURL := fmt.Sprintf("http://%s%s", parsed.Host, parsed.Path)
	if parsed.RawQuery != "" {
		reqURL = fmt.Sprintf("%s?%s", reqURL, parsed.RawQuery)
	}

	// Make the HTTP request
	resp, err := http.Get(reqURL)
	if err != nil {
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response back
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func main() {
	http.HandleFunc("/fetch", fetchFromBackend)
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	http.ListenAndServe(":"+port, nil)
}

