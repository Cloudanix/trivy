package main

import (
	"context"
	"errors"

	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	fTypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/licensing"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/google/go-containerregistry/pkg/name"

	_ "modernc.org/sqlite" // sqlite driver for RPM DB and Java DB
)

var (
	version = "dev"
)

type ScanConfig struct {
	Image       string `json:"image,omitempty"`
	APIEndpoint string `json:"apiEndpoint,omitempty"`
	AuthZToken  string `json:"authZToken,omitempty"`
	Identifier  string `json:"identifier,omitempty"`
	Env         string `json:"env,omitempty"`
	ResetDB     bool   `json:"resetDB,omitempty"`
	DownloadDB  bool   `json:"downloadDB,omitempty"`
}

func scanImage(scanConfig ScanConfig) error {
	ctx := context.Background()

	var dbRepository, javaDBRepository name.Reference
	var err error
	if dbRepository, err = name.ParseReference("ghcr.io/aquasecurity/trivy-db", name.WithDefaultTag("")); err != nil {
		return xerrors.Errorf("invalid db repository: %w", err)
	}

	if javaDBRepository, err = name.ParseReference("ghcr.io/aquasecurity/trivy-java-db", name.WithDefaultTag("")); err != nil {
		return xerrors.Errorf("invalid java db repository: %w", err)
	}

	opts := flag.Options{
		GlobalOptions: flag.GlobalOptions{
			ConfigFile:            "trivy.yaml",
			ShowVersion:           false,
			Quiet:                 false,
			Debug:                 false,
			Insecure:              false,
			Timeout:               300000000000,
			GenerateDefaultConfig: false,
		},
		DBOptions: flag.DBOptions{
			Reset:              scanConfig.ResetDB, // To reset database
			DownloadDBOnly:     scanConfig.DownloadDB,
			SkipDBUpdate:       false,
			DownloadJavaDBOnly: false,
			SkipJavaDBUpdate:   false,
			NoProgress:         false, // To show/hide db download progress bar
			DBRepository:       dbRepository,
			JavaDBRepository:   javaDBRepository,
			Light:              false,
		},
		ImageOptions: flag.ImageOptions{
			Input:               "",
			ImageConfigScanners: nil,
			ScanRemovedPkgs:     false,
			Platform: fTypes.Platform{
				Force: false,
			},
			DockerHost:   "",
			ImageSources: fTypes.AllImageSources,
		},
		LicenseOptions: flag.LicenseOptions{
			LicenseFull:            false,
			IgnoredLicenses:        nil,
			LicenseConfidenceLevel: 0.9,
			LicenseRiskThreshold:   0,
			LicenseCategories: map[fTypes.LicenseCategory][]string{
				fTypes.CategoryForbidden:    licensing.ForbiddenLicenses,
				fTypes.CategoryNotice:       licensing.NoticeLicenses,
				fTypes.CategoryPermissive:   licensing.PermissiveLicenses,
				fTypes.CategoryReciprocal:   licensing.ReciprocalLicenses,
				fTypes.CategoryRestricted:   licensing.RestrictedLicenses,
				fTypes.CategoryUnencumbered: licensing.UnencumberedLicenses,
			},
		},
		ReportOptions: flag.ReportOptions{
			Format:         "json",
			ReportFormat:   "summary",
			Template:       "",
			DependencyTree: false,
			ListAllPkgs:    false,
			IgnoreFile:     ".trivyignore",
			ExitCode:       0,
			ExitOnEOL:      0,
			IgnorePolicy:   "",
			Output:         "tmp/output.txt",
			Severities:     []dbTypes.Severity{0, 1, 2, 3, 4},
		},
		ScanOptions: flag.ScanOptions{
			Target:      scanConfig.Image,
			SkipDirs:    nil,
			SkipFiles:   nil,
			OfflineScan: false,
			Scanners: types.Scanners{
				"vuln",
				"secret",
			},
			FilePatterns:   nil,
			SBOMSources:    nil,
			RekorURL:       "https://rekor.sigstore.dev",
			IncludeDevDeps: false,
		},
		VulnerabilityOptions: flag.VulnerabilityOptions{
			VulnType: []string{
				types.VulnTypeOS,
				types.VulnTypeLibrary,
			},
		},
		ExportOptions: flag.ExportOptions{
			APIEndpoint: scanConfig.APIEndpoint,
			AuthZToken:  scanConfig.AuthZToken,
			Identifier:  scanConfig.Identifier,
			Env:         scanConfig.Env,
		},
		AppVersion: version,
	}

	r, err := artifact.NewRunner(ctx, opts)
	if err != nil {
		if errors.Is(err, artifact.SkipScan) {
			return nil
		}
		return xerrors.Errorf("init error: %w", err)
	}
	defer r.Close(ctx)

	var report types.Report
	if report, err = r.ScanImage(ctx, opts); err != nil {
		return xerrors.Errorf("image scan error: %w", err)
	}

	report, err = r.Filter(ctx, opts, report)
	if err != nil {
		return xerrors.Errorf("filter error: %w", err)
	}

	artifact.PublishReport(report, opts.ExportOptions)

	return nil
}
