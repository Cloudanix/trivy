package artifact

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/types"
)

func createTestJar(t *testing.T, dir, filename string, entries map[string]string) string {
	t.Helper()
	jarPath := filepath.Join(dir, filename)
	f, err := os.Create(jarPath)
	require.NoError(t, err)
	defer f.Close()

	zw := zip.NewWriter(f)
	for name, content := range entries {
		w, err := zw.Create(name)
		require.NoError(t, err)
		_, err = w.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return jarPath
}

func TestEnrichArchiveReport_PomProperties(t *testing.T) {
	tmp := t.TempDir()
	jarPath := createTestJar(t, tmp, "order-service-1.2.0.jar", map[string]string{
		"META-INF/MANIFEST.MF":                                  "Manifest-Version: 1.0\n",
		"META-INF/maven/com.acme/order-service/pom.properties": "groupId=com.acme\nartifactId=order-service\nversion=1.2.0\n",
	})

	opts := flag.Options{
		ScanOptions: flag.ScanOptions{Target: jarPath},
	}
	inReport := types.Report{
		ArtifactName: jarPath,
		ArtifactType: "filesystem",
	}

	got := enrichArchiveReport(opts, TargetRootfs, inReport)
	assert.Equal(t, "java.archive/com.acme/order-service:1.2.0", got.ArtifactName)
	assert.Equal(t, ArtifactTypeJavaArchive, got.ArtifactType)
	assert.True(t, strings.HasPrefix(got.ArtifactID, "sha256:"))
	assert.Equal(t, got.ArtifactID, got.Metadata.ImageID)
	assert.Equal(t, []string{"java.archive/com.acme/order-service:1.2.0"}, got.Metadata.RepoTags)
	assert.Equal(t, "jvm", got.Metadata.ImageConfig.Architecture)
	assert.Equal(t, "java", got.Metadata.ImageConfig.OS)
	assert.Greater(t, got.Metadata.Size, int64(0))
}

func TestEnrichArchiveReport_FilenameFallbackAndExplicitOverride(t *testing.T) {
	tmp := t.TempDir()
	jarPath := createTestJar(t, tmp, "billing-worker-2.4.1-SNAPSHOT.jar", map[string]string{
		"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n",
	})

	opts := flag.Options{
		ScanOptions: flag.ScanOptions{Target: jarPath},
	}
	got := enrichArchiveReport(opts, TargetRootfs, types.Report{ArtifactName: jarPath})
	assert.Equal(t, "java.archive/billing-worker:2.4.1-SNAPSHOT", got.ArtifactName)

	// Explicit CLI overrides take precedence
	opts.ExportOptions = flag.ExportOptions{
		ArtifactName: "java.archive/custom-org/billing:v2.4.1",
		ArtifactID:   "sha256:deadbeef",
		ArtifactType: "java_archive",
	}
	gotOverride := enrichArchiveReport(opts, TargetRootfs, types.Report{ArtifactName: jarPath})
	assert.Equal(t, "java.archive/custom-org/billing:v2.4.1", gotOverride.ArtifactName)
	assert.Equal(t, "sha256:deadbeef", gotOverride.ArtifactID)
	assert.Equal(t, "sha256:deadbeef", gotOverride.Metadata.ImageID)
	assert.Equal(t, []string{"java.archive/custom-org/billing:v2.4.1"}, gotOverride.Metadata.RepoTags)
}
