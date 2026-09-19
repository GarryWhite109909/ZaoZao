package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
)

type healthCheckRequest struct {
	TargetHost string `json:"target_host"`
	Port       string `json:"port"`
}

type healthCheckResponse struct {
	Success bool   `json:"success"`
	Output  string `json:"output,omitempty"`
	Error   string `json:"error,omitempty"`
}

// healthCheckHandler handles POST /api/v1/healthcheck
// It performs a TCP connectivity check to a user-specified host:port
func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	var req healthCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.TargetHost == "" || req.Port == "" {
		http.Error(w, "target_host and port are required", http.StatusBadRequest)
		return
	}

	// Validate port is numeric
	if !isNumeric(req.Port) {
		http.Error(w, "port must be numeric", http.StatusBadRequest)
		return
	}

	// Construct command - using os/exec with shell string concatenation
	// This is the vulnerable patterns: user input flows into shell command
	cmdStr := fmt.Sprintf("nc -z -w 2 %s %s", req.TargetHost, req.Port)
	cmd := exec.Command("sh", "-c", cmdStr)

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Return the raw error (may include command output)
		resp := healthCheckResponse{Success: false, Error: string(output)}
		json.NewEncoder(w).Encode(resp)
		return
	}

	resp := healthCheckResponse{Success: true, Output: string(output)}
	json.NewEncoder(w).Encode(resp)
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func main() {
	http.HandleFunc("/api/v1/healthcheck", healthCheckHandler)
	fmt.Println("API gateway health check service listening on :8080")
	http.ListenAndServe(":8080", nil)
}

