package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
)

type BuildRequest struct {
	Repo string `json:"repo"`
}

var allowedRepos = map[string]bool{
	"frontend": true,
	"backend":  true,
	"infra":    true,
}

func buildHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req BuildRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	// 白名单校验：只允许预定义的仓库名
	if !allowedRepos[req.Repo] {
		http.Error(w, "repo not allowed", http.StatusForbidden)
		return
	}

	// 使用列表参数 + shell=False，避免 shell 注入
	cmd := exec.Command("git", "clone", "https://github.com/org/"+req.Repo+".git")
	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, fmt.Sprintf("build failed: %s", output), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("build started"))
}

func main() {
	http.HandleFunc("/build", buildHandler)
	http.ListenAndServe(":8080", nil)
}

