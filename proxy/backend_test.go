package proxy

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/playdots/underpants/config"
	"github.com/playdots/underpants/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestAddProxyUserRequest(t *testing.T) {
	user := &user.Info{
		Email: "foo@expected-email-host.com",
		Name:  "foo",
	}

	envName := "TEST_SERVICE_TOKEN"
	header := &config.ToAddHeader{
		EnvVarName:    envName,
		DestHeaderKey: "Authorization",
		DestHeaderVal: "",
	}

	toAddHeaders := []*config.ToAddHeader{header}
	expectedTokenVal := "secure-token-for-test-service"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, expectedTokenVal, r.Header.Get("Authorization"))
	}))
	defer ts.Close()

	ri := &config.RouteInfo{
		From:         "http://example.com",
		To:           ts.URL,
		ToAddHeaders: toAddHeaders,
	}

	os.Setenv(envName, expectedTokenVal)

	info := &config.Info{}
	err := info.ReadFile("test.json")
	require.NoError(t, err)

	config.InitRoute(ri)
	info.Routes = []*config.RouteInfo{ri}

	ctx := &config.Context{
		Info: info,
	}

	b := &Backend{
		Ctx:   ctx,
		Route: ri,
	}

	wr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://example.com/foo", nil)

	b.proxyUserRequest(wr, req, user, []zap.Field{})
	// see assertion within the request handler in NewServer above
}
