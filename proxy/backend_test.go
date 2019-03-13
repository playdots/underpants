package proxy

import (
	"net/http"
	"os"
	"testing"

	"github.com/playdots/underpants/auth"
	"github.com/playdots/underpants/auth/google"
	"github.com/playdots/underpants/config"
	"github.com/stretchr/testify/assert"
)

func TestAddToAddHeaders(t *testing.T) {
	ctx := &config.Context{
		Info: &config.Info{
			Oauth: config.OAuthInfo{
				ClientID:     "client_id",
				ClientSecret: "client_secret",
			},
			Host: "localhost",
		},
		Port: 5000,
	}

	envName := "TEST_SERVICE_TOKEN"
	header := &config.ToAddHeader{
		EnvVarName:    envName,
		DestHeaderKey: "Authorization",
		DestHeaderVal: "",
	}

	toAddHeaders := []*config.ToAddHeader{header}
	ri := &config.RouteInfo{
		From:         "here",
		To:           "there",
		ToAddHeaders: toAddHeaders,
	}

	expectedVal := "secure-token-for-test-service"
	os.Setenv(envName, expectedVal)

	var prv auth.Provider
	prv = google.Provider

	b := &Backend{
		Ctx:          ctx,
		Route:        ri,
		AuthProvider: prv,
	}

	err := config.InitToAddHeaders(ri)
	assert.Nil(t, err)
	assert.Equal(t, expectedVal, ri.ToAddHeaders[0].DestHeaderVal)

	r, _ := http.NewRequest("GET", "localhost", nil)
	addToAddHeaders(r.Header, b.Route.ToAddHeaders)

	for key, vals := range r.Header {
		for _, val := range vals {
			if key == "Authorization" {
				assert.Equal(t, expectedVal, val)
			}
		}
	}
}
