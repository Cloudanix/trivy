package flag

// e.g. config yaml:
//
//	api-endpoint: https://api.google.com
//	authz-token: AUTHORIZATION_TOKEN
//	identifier: IDENTIFIER
//	env: LIVE | DEBUG

var (
	ArtifactNameFlag = Flag[string]{
		Name:       "artifact-name",
		ConfigName: "export.artifact-name",
		Default:    "",
		Usage:      "Logical artifact name override for report output and HTTP export (e.g. java.archive/com.acme/app:1.0.0)",
	}
	ArtifactIDFlag = Flag[string]{
		Name:       "artifact-id",
		ConfigName: "export.artifact-id",
		Default:    "",
		Usage:      "Artifact ID/digest override for report output and HTTP export (e.g. sha256:...)",
	}
	ArtifactTypeFlag = Flag[string]{
		Name:       "artifact-type",
		ConfigName: "export.artifact-type",
		Default:    "",
		Usage:      "Artifact type override for report output and HTTP export (e.g. java_archive)",
	}
)

// ExportFlagGroup composes common printer flag structs
// used for commands requiring export logic.
type ExportFlagGroup struct {
	APIEndpoint  *Flag[string]
	AuthZToken   *Flag[string]
	Identifier   *Flag[string]
	Env          *Flag[string]
	ArtifactName *Flag[string]
	ArtifactID   *Flag[string]
	ArtifactType *Flag[string]
}

type ExportOptions struct {
	APIEndpoint  string
	AuthZToken   string
	Identifier   string
	Env          string
	ArtifactName string
	ArtifactID   string
	ArtifactType string
}

func NewExportFlagGroup() *ExportFlagGroup {
	apiEndpoint := APIEndpointFlag.Clone()
	apiEndpoint.ConfigName = "export.api-endpoint"
	return &ExportFlagGroup{
		APIEndpoint:  apiEndpoint,
		AuthZToken:   AuthZTokenFlag.Clone(),
		Identifier:   IdentifierFlag.Clone(),
		Env:          EnvFlag.Clone(),
		ArtifactName: ArtifactNameFlag.Clone(),
		ArtifactID:   ArtifactIDFlag.Clone(),
		ArtifactType: ArtifactTypeFlag.Clone(),
	}
}

func (f *ExportFlagGroup) Name() string {
	return "Export"
}

func (f *ExportFlagGroup) Flags() []Flagger {
	return []Flagger{
		f.APIEndpoint,
		f.AuthZToken,
		f.Identifier,
		f.Env,
		f.ArtifactName,
		f.ArtifactID,
		f.ArtifactType,
	}
}

func (f *ExportFlagGroup) ToOptions(opts *Options) error {
	opts.ExportOptions = ExportOptions{
		APIEndpoint:  f.APIEndpoint.Value(),
		AuthZToken:   f.AuthZToken.Value(),
		Identifier:   f.Identifier.Value(),
		Env:          f.Env.Value(),
		ArtifactName: f.ArtifactName.Value(),
		ArtifactID:   f.ArtifactID.Value(),
		ArtifactType: f.ArtifactType.Value(),
	}
	return nil
}
