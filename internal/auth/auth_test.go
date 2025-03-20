package auth_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/bootdotdev/learn-cicd-starter/internal/auth"
)

func TestGetAPIKey_ValidKey(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey validapikey123")

	apiKey, err := auth.GetAPIKey(headers)

	assert.NoError(t, err)
	assert.Equal(t, "validapikey123", apiKey)
}

func TestGetAPIKey_NoHeader(t *testing.T) {
	headers := http.Header{}

	apiKey, err := auth.GetAPIKey(headers)

	assert.Error(t, err)
	assert.Equal(t, auth.ErrNoAuthHeaderIncluded, err)
	assert.Empty(t, apiKey)
}

func TestGetAPIKey_MalformedHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer token")

	apiKey, err := auth.GetAPIKey(headers)

	assert.Error(t, err)
	assert.Equal(t, "malformed authorization header", err.Error())
	assert.Empty(t, apiKey)
}
