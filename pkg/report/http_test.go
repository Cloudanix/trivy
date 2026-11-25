package report

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/types"
)

func TestHttpWriter_Write_DoesNotDuplicateHeaders(t *testing.T) {
	var capturedHeaders http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	hw := HttpWriter{
		Mode:        ModeCI,
		ListenerUrl: srv.URL,
		AuthZToken:  "test-token",
		AccountId:   "acc-123",
	}

	customHeaders := make(http.Header)
	customHeaders.Add("cdx-template-type", "KUBERNETESIMAGESCANNING")
	customHeaders.Add("cdx-build-context", "eyJ0ZXN0Ijp0cnVlfQ==")

	err := hw.Write(types.Report{
		ArtifactName: "java.archive/com.acme/order-service:1.2.0",
		ArtifactType: "java_archive",
	}, customHeaders)
	require.NoError(t, err)

	assert.Equal(t, []string{"KUBERNETESIMAGESCANNING"}, capturedHeaders.Values("Cdx-Template-Type"))
	assert.Equal(t, []string{"eyJ0ZXN0Ijp0cnVlfQ=="}, capturedHeaders.Values("Cdx-Build-Context"))
	assert.Equal(t, []string{"acc-123"}, capturedHeaders.Values("Cdx-Account-Id"))
	assert.Equal(t, []string{"Bearer test-token"}, capturedHeaders.Values("Authorization"))
}
