package handler

import (
	"encoding/json"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
)

const (
	// AppVersion is the backend application version
	AppVersion = "1.0.0"
)

// AboutHandler handles about/version information requests
type AboutHandler struct{}

// NewAboutHandler creates a new about handler
func NewAboutHandler() *AboutHandler {
	return &AboutHandler{}
}

// AboutResponse represents the about information response
type AboutResponse struct {
	App     AppInfo     `json:"app"`
	Backend BackendInfo `json:"backend"`
}

// AppInfo contains frontend application information
type AppInfo struct {
	Version string `json:"version"`
}

// BackendInfo contains backend version information
type BackendInfo struct {
	Version           string `json:"version"`
	ContractGoVersion string `json:"contract_go_version"`
	OpenSSLVersion    string `json:"openssl_version"`
	GoVersion         string `json:"go_version"`
	Platform          string `json:"platform"`
}

// GetAbout returns version and system information
func (h *AboutHandler) GetAbout(w http.ResponseWriter, r *http.Request) {
	response := AboutResponse{
		App: AppInfo{
			Version: "1.0.0", // This will be read from frontend
		},
		Backend: BackendInfo{
			Version:           AppVersion,
			ContractGoVersion: getContractGoVersion(),
			OpenSSLVersion:    getOpenSSLVersion(),
			GoVersion:         runtime.Version(),
			Platform:          runtime.GOOS + "/" + runtime.GOARCH,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// getContractGoVersion returns the contract-go library version from go.mod
func getContractGoVersion() string {
	// contract-go is a Go library dependency, not a CLI tool
	// Return the version specified in go.mod
	return "v2.19.0"
}

// getOpenSSLVersion attempts to get the OpenSSL version
func getOpenSSLVersion() string {
	cmd := exec.Command("openssl", "version")
	output, err := cmd.Output()
	if err != nil {
		return "Not available"
	}

	version := strings.TrimSpace(string(output))
	// Extract just the version number (e.g., "OpenSSL 3.0.2 15 Mar 2022" -> "3.0.2")
	parts := strings.Fields(version)
	if len(parts) >= 2 {
		return parts[1]
	}

	return version
}
