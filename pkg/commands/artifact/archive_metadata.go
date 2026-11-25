package artifact

import (
	"archive/zip"
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	ArtifactTypeJavaArchive ftypes.ArtifactType = "java_archive"
	JavaArchiveRegistry                         = "java.archive"
)

var jarFilenameVersionRe = regexp.MustCompile(`^(.+?)-(\d[0-9A-Za-z._\-+]*)$`)

func isJavaArchivePath(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".jar", ".war", ".ear", ".par":
		return true
	default:
		return false
	}
}

// enrichArchiveReport normalizes ArtifactName, ArtifactID, ArtifactType, and Metadata
// for rootfs/filesystem scans when scanning Java archives (.jar/.war/.ear/.par) or when
// explicit --artifact-name / --artifact-id / --artifact-type export flags are supplied.
func enrichArchiveReport(opts flag.Options, targetKind TargetKind, report types.Report) types.Report {
	if targetKind != TargetRootfs && targetKind != TargetFilesystem {
		return report
	}

	target := opts.Target
	isJavaArchive := isJavaArchivePath(target)
	hasOverrides := opts.ExportOptions.ArtifactName != "" ||
		opts.ExportOptions.ArtifactID != "" ||
		opts.ExportOptions.ArtifactType != ""

	if !isJavaArchive && !hasOverrides {
		return report
	}

	var (
		fileSize    int64
		fileModTime time.Time
		computedID  string
		derivedName string
	)

	if target != "" {
		if st, err := os.Stat(target); err == nil {
			fileModTime = st.ModTime().UTC()
			if st.Mode().IsRegular() {
				fileSize = st.Size()
				if opts.ExportOptions.ArtifactID == "" {
					if digest, err := sha256File(target); err == nil {
						computedID = "sha256:" + digest
					}
				}
				if isJavaArchive && opts.ExportOptions.ArtifactName == "" {
					derivedName = deriveJavaArchiveCoordinate(target)
				}
			}
		}
	}

	artifactName := opts.ExportOptions.ArtifactName
	if artifactName == "" {
		artifactName = derivedName
	}
	if artifactName != "" {
		report.ArtifactName = artifactName
	}

	artifactID := opts.ExportOptions.ArtifactID
	if artifactID == "" {
		artifactID = computedID
	}
	if artifactID != "" {
		report.ArtifactID = artifactID
		if report.Metadata.ImageID == "" {
			report.Metadata.ImageID = artifactID
		}
	}

	artifactType := opts.ExportOptions.ArtifactType
	if artifactType != "" {
		report.ArtifactType = ftypes.ArtifactType(artifactType)
	} else if isJavaArchive {
		report.ArtifactType = ArtifactTypeJavaArchive
	}

	if fileSize > 0 && report.Metadata.Size == 0 {
		report.Metadata.Size = fileSize
	}

	if report.ArtifactName != "" && len(report.Metadata.RepoTags) == 0 {
		report.Metadata.RepoTags = []string{report.ArtifactName}
	}

	if isJavaArchive || report.ArtifactType == ArtifactTypeJavaArchive {
		if report.Metadata.ImageConfig.Architecture == "" {
			report.Metadata.ImageConfig.Architecture = "jvm"
		}
		if report.Metadata.ImageConfig.OS == "" {
			report.Metadata.ImageConfig.OS = "java"
		}
		if report.Metadata.ImageConfig.Created.IsZero() && !fileModTime.IsZero() {
			report.Metadata.ImageConfig.Created = v1.Time{Time: fileModTime}
		}
	}

	return report
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func deriveJavaArchiveCoordinate(path string) string {
	groupID, artifactID, version := readJavaArchiveMetadata(path)
	if artifactID == "" || version == "" {
		base := filepath.Base(path)
		ext := filepath.Ext(base)
		stem := strings.TrimSuffix(base, ext)
		if m := jarFilenameVersionRe.FindStringSubmatch(stem); len(m) == 3 {
			if artifactID == "" {
				artifactID = m[1]
			}
			if version == "" {
				version = m[2]
			}
		} else {
			if artifactID == "" {
				artifactID = stem
			}
			if version == "" {
				version = "latest"
			}
		}
	}

	artifactID = sanitizeSegment(artifactID)
	version = sanitizeTag(version)
	if groupID != "" {
		groupID = sanitizeSegment(groupID)
		return JavaArchiveRegistry + "/" + groupID + "/" + artifactID + ":" + version
	}
	return JavaArchiveRegistry + "/" + artifactID + ":" + version
}

func readJavaArchiveMetadata(path string) (groupID, artifactID, version string) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return "", "", ""
	}
	defer zr.Close()

	// 1. Prefer top-level META-INF/maven/<groupId>/<artifactId>/pom.properties
	for _, f := range zr.File {
		name := filepath.ToSlash(f.Name)
		if strings.HasPrefix(name, "META-INF/maven/") && strings.HasSuffix(name, "/pom.properties") {
			props := parsePropertiesZipEntry(f)
			g := strings.TrimSpace(props["groupId"])
			a := strings.TrimSpace(props["artifactId"])
			v := strings.TrimSpace(props["version"])
			if a != "" && v != "" {
				return g, a, v
			}
		}
	}

	// 2. Fall back to META-INF/MANIFEST.MF
	for _, f := range zr.File {
		if strings.EqualFold(filepath.ToSlash(f.Name), "META-INF/MANIFEST.MF") {
			headers := parseManifestZipEntry(f)
			g := firstNonEmpty(headers["implementation-vendor-id"], headers["specification-vendor"])
			a := firstNonEmpty(headers["implementation-title"], headers["bundle-symbolicname"], headers["automatic-module-name"])
			if idx := strings.Index(a, ";"); idx != -1 {
				a = strings.TrimSpace(a[:idx])
			}
			v := firstNonEmpty(headers["implementation-version"], headers["bundle-version"])
			if a != "" && v != "" && !strings.Contains(a, " ") {
				return g, a, v
			}
		}
	}

	return "", "", ""
}

func parsePropertiesZipEntry(f *zip.File) map[string]string {
	out := make(map[string]string)
	rc, err := f.Open()
	if err != nil {
		return out
	}
	defer rc.Close()

	scanner := bufio.NewScanner(rc)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

func parseManifestZipEntry(f *zip.File) map[string]string {
	out := make(map[string]string)
	rc, err := f.Open()
	if err != nil {
		return out
	}
	defer rc.Close()

	scanner := bufio.NewScanner(rc)
	var lastKey string
	for scanner.Scan() {
		raw := scanner.Text()
		if raw == "" {
			lastKey = ""
			continue
		}
		if strings.HasPrefix(raw, " ") && lastKey != "" {
			out[lastKey] += strings.TrimPrefix(raw, " ")
			continue
		}
		if k, v, ok := strings.Cut(raw, ":"); ok {
			lastKey = strings.ToLower(strings.TrimSpace(k))
			out[lastKey] = strings.TrimSpace(v)
		}
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func sanitizeSegment(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, " ", "-")
	return strings.Trim(s, "/")
}

func sanitizeTag(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, " ", "-")
	if s == "" {
		return "latest"
	}
	return s
}
