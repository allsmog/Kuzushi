// Reference Kubernetes-Jobs adapter for the Kuzushi SandboxExecutor
// protocol. Four endpoints, one Job per run, idempotent on the
// (clientId, runId) pair via Job names.
//
// Build:  docker build -t ghcr.io/<you>/kuzushi-sandbox-adapter .
// Deploy: kubectl apply -f ../manifest.yaml
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type server struct {
	k8s       *kubernetes.Clientset
	namespace string
	apiKey    string
	image     string
}

type launchRequest struct {
	ClientID   string            `json:"clientId"`
	RunID      string            `json:"runId"`
	Command    []string          `json:"command"`
	WorkingDir string            `json:"workingDir"`
	Env        map[string]string `json:"env"`
	Stdin      *string           `json:"stdin"`
}

type launchResponse struct {
	RunID string `json:"runId"`
}

type resultResponse struct {
	Status   string  `json:"status"`
	Stdout   string  `json:"stdout"`
	Stderr   string  `json:"stderr"`
	ExitCode *int    `json:"exitCode"`
}

type statusResponse struct {
	Status string `json:"status"`
}

type outputResponse struct {
	Stdout     []string `json:"stdout"`
	Stderr     []string `json:"stderr"`
	NextOffset int      `json:"nextOffset"`
	Done       bool     `json:"done"`
}

func main() {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("could not load in-cluster config: %v", err)
	}
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Fatalf("could not build clientset: %v", err)
	}
	srv := &server{
		k8s:       clientset,
		namespace: defaultEnv("KUZUSHI_NAMESPACE", "default"),
		apiKey:    strings.TrimSpace(os.Getenv("KUZUSHI_SANDBOX_API_KEY")),
		image:     defaultEnv("KUZUSHI_RUNNER_IMAGE", "ghcr.io/returntocorp/semgrep:latest"),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/v1/runs", srv.handleRuns)
	mux.HandleFunc("/v1/runs/", srv.handleRun) // /v1/runs/<id>[/status|/output]

	addr := ":" + defaultEnv("PORT", "8080")
	log.Printf("kuzushi sandbox adapter listening on %s (namespace=%s)", addr, srv.namespace)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func defaultEnv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func (s *server) handleRuns(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method_not_allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.authOk(w, r) {
		return
	}
	var body launchRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	body.ClientID = strings.TrimSpace(body.ClientID)
	body.RunID = strings.TrimSpace(body.RunID)
	if body.ClientID == "" || body.RunID == "" {
		http.Error(w, "clientId and runId required", http.StatusBadRequest)
		return
	}
	if len(body.Command) == 0 {
		http.Error(w, "command must be non-empty", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	name := jobName(body.ClientID, body.RunID)
	if err := s.ensureJob(ctx, name, &body); err != nil {
		log.Printf("ensureJob %s: %v", name, err)
		http.Error(w, fmt.Sprintf("could not launch: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(launchResponse{RunID: body.RunID})
}

func (s *server) handleRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method_not_allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.authOk(w, r) {
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/v1/runs/")
	parts := strings.Split(rest, "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	clientID := strings.TrimSpace(r.Header.Get("X-Kuzushi-Client-Id"))
	if clientID == "" {
		clientID = "default"
	}
	runID := parts[0]
	name := jobName(clientID, runID)

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	switch {
	case len(parts) == 1:
		s.respondResult(ctx, w, name, runID)
	case len(parts) == 2 && parts[1] == "status":
		s.respondStatus(ctx, w, name)
	case len(parts) == 2 && parts[1] == "output":
		since, _ := strconv.Atoi(r.URL.Query().Get("since"))
		s.respondOutput(ctx, w, name, since)
	default:
		http.NotFound(w, r)
	}
}

func (s *server) authOk(w http.ResponseWriter, r *http.Request) bool {
	if s.apiKey == "" {
		return true // dev mode — no auth configured
	}
	header := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	if strings.TrimSpace(strings.TrimPrefix(header, prefix)) != s.apiKey {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *server) respondResult(ctx context.Context, w http.ResponseWriter, name, runID string) {
	state, err := s.fetchState(ctx, name)
	if err != nil {
		if errors.Is(err, errJobNotFound) {
			writeError(w, http.StatusNotFound, "no such run")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resultResponse{
		Status:   state.Status,
		Stdout:   state.Stdout,
		Stderr:   state.Stderr,
		ExitCode: state.ExitCode,
	})
	_ = runID
}

func (s *server) respondStatus(ctx context.Context, w http.ResponseWriter, name string) {
	state, err := s.fetchState(ctx, name)
	if err != nil {
		if errors.Is(err, errJobNotFound) {
			writeError(w, http.StatusNotFound, "no such run")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, statusResponse{Status: state.Status})
}

func (s *server) respondOutput(ctx context.Context, w http.ResponseWriter, name string, since int) {
	state, err := s.fetchState(ctx, name)
	if err != nil {
		if errors.Is(err, errJobNotFound) {
			writeError(w, http.StatusNotFound, "no such run")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	stdoutLines := splitLinesAfter(state.Stdout, since)
	stderrLines := splitLinesAfter(state.Stderr, 0)
	writeJSON(w, http.StatusOK, outputResponse{
		Stdout:     stdoutLines,
		Stderr:     stderrLines,
		NextOffset: countLines(state.Stdout),
		Done:       state.Status == "succeeded" || state.Status == "failed" || state.Status == "cancelled",
	})
}

func splitLinesAfter(text string, since int) []string {
	if text == "" {
		return nil
	}
	all := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if since >= len(all) {
		return nil
	}
	return all[since:]
}

func countLines(text string) int {
	if text == "" {
		return 0
	}
	return len(strings.Split(strings.TrimRight(text, "\n"), "\n"))
}
