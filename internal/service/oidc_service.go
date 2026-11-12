package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OIDCUserInfo holds the claims returned by the identity provider's userinfo endpoint.
type OIDCUserInfo struct {
	Email string `json:"email"`
}

// OIDCService performs the OIDC authorization code flow against IBM w3id.
type OIDCService struct {
	clientID       string
	clientSecret   string
	oauthServerURL string
	redirectURI    string
	httpClient     *http.Client
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
}

// NewOIDCService creates a new OIDCService.
func NewOIDCService(clientID, clientSecret, oauthServerURL, redirectURI string) *OIDCService {
	return &OIDCService{
		clientID:       clientID,
		clientSecret:   clientSecret,
		oauthServerURL: strings.TrimRight(oauthServerURL, "/"),
		redirectURI:    redirectURI,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Enabled reports whether all required SSO settings are configured.
func (s *OIDCService) Enabled() bool {
	return s.clientID != "" && s.clientSecret != "" && s.oauthServerURL != "" && s.redirectURI != ""
}

// GetAuthURL builds the provider authorization URL.
func (s *OIDCService) GetAuthURL(state string) string {
	params := url.Values{}
	params.Set("client_id", s.clientID)
	params.Set("response_type", "code")
	params.Set("redirect_uri", s.redirectURI)
	params.Set("scope", "openid email profile")
	if state != "" {
		params.Set("state", state)
	}
	return s.oauthServerURL + "/authorize?" + params.Encode()
}

// ExchangeCode swaps an authorization code for an access token and returns the userinfo.
func (s *OIDCService) ExchangeCode(ctx context.Context, code string) (*OIDCUserInfo, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", s.clientID)
	data.Set("client_secret", s.clientSecret)
	data.Set("redirect_uri", s.redirectURI)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.oauthServerURL+"/token", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned status %d", resp.StatusCode)
	}
	var tokenResp tokenResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenResp)
	if err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("token response contains no access_token")
	}

	req, err = http.NewRequestWithContext(ctx, http.MethodGet, s.oauthServerURL+"/userinfo", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	resp, err = s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo endpoint returned status %d", resp.StatusCode)
	}

	var userInfo OIDCUserInfo
	err = json.NewDecoder(resp.Body).Decode(&userInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}
	return &userInfo, nil
}
