package src

import (
	"strings"
	"testing"

	"github.com/sevensolutions/traefik-oidc-auth/src/session"
)

func TestSetCustomCookies(t *testing.T) {
	// Create a TraefikOidcAuth instance with custom cookies configured
	config := &Config{
		Cookies: []CookieConfig{
			{
				Name:  "custom-user-id",
				Value: "{{.claims.sub}}",
			},
			{
				Name:  "user-email",
				Value: "{{.claims.email}}",
			},
			{
				Name:  "static-cookie",
				Value: "static-value",
			},
		},
	}

	toa := &TraefikOidcAuth{
		Config: config,
	}

	rw := newMockResponseWriter()

	// Mock session and claims
	sessionState := &session.SessionState{
		AccessToken:  "mock-access-token",
		IdToken:      "mock-id-token",
		RefreshToken: "mock-refresh-token",
	}

	claims := map[string]interface{}{
		"sub":   "user123",
		"email": "user@example.com",
		"name":  "John Doe",
	}

	// Call setCustomCookies
	err := toa.setCustomCookies(rw, sessionState, claims)
	if err != nil {
		t.Fatalf("setCustomCookies failed: %v", err)
	}

	// Check if cookies were set correctly
	setCookieHeaders := rw.HeaderMap["Set-Cookie"]
	if len(setCookieHeaders) != 3 {
		t.Fatalf("Expected 3 Set-Cookie headers, got %d", len(setCookieHeaders))
	}

	// Verify the cookies contain expected values
	expectedCookies := map[string]string{
		"custom-user-id": "user123",
		"user-email":     "user@example.com",
		"static-cookie":  "static-value",
	}

	for _, cookieHeader := range setCookieHeaders {
		cookieFound := false
		for expectedName, expectedValue := range expectedCookies {
			expectedPrefix := expectedName + "=" + expectedValue + ";"
			if strings.HasPrefix(cookieHeader, expectedPrefix) {
				cookieFound = true
				delete(expectedCookies, expectedName)
				break
			}
		}
		if !cookieFound {
			t.Fatalf("Unexpected cookie header: %s", cookieHeader)
		}
	}

	if len(expectedCookies) > 0 {
		t.Fatalf("Missing expected cookies: %v", expectedCookies)
	}
}

func TestSetCustomCookiesEmpty(t *testing.T) {
	// Test with no custom cookies configured
	config := &Config{
		Cookies: []CookieConfig{},
	}

	toa := &TraefikOidcAuth{
		Config: config,
	}

	rw := newMockResponseWriter()
	sessionState := &session.SessionState{}
	claims := map[string]interface{}{}

	err := toa.setCustomCookies(rw, sessionState, claims)
	if err != nil {
		t.Fatalf("setCustomCookies failed with empty config: %v", err)
	}

	setCookieHeaders := rw.HeaderMap["Set-Cookie"]
	if len(setCookieHeaders) != 0 {
		t.Fatalf("Expected 0 Set-Cookie headers, got %d", len(setCookieHeaders))
	}
}

func TestSetCustomCookiesTemplateError(t *testing.T) {
	// Test with invalid template
	config := &Config{
		Cookies: []CookieConfig{
			{
				Name:  "invalid-template",
				Value: "{{.invalid.template}}", // This will cause an error
			},
		},
	}

	toa := &TraefikOidcAuth{
		Config: config,
	}

	rw := newMockResponseWriter()
	sessionState := &session.SessionState{}
	claims := map[string]interface{}{}

	err := toa.setCustomCookies(rw, sessionState, claims)
	if err != nil {
		t.Fatalf("setCustomCookies should handle template errors gracefully: %v", err)
	}

	// Should still set a cookie, but with the error message as value
	setCookieHeaders := rw.HeaderMap["Set-Cookie"]
	if len(setCookieHeaders) != 1 {
		t.Fatalf("Expected 1 Set-Cookie header, got %d", len(setCookieHeaders))
	}

	// The cookie should contain an error message
	if !strings.HasPrefix(setCookieHeaders[0], "invalid-template=") {
		t.Fatalf("Expected cookie to start with 'invalid-template=', got: %s", setCookieHeaders[0])
	}
}
