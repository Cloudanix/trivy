package flag

// e.g. config yaml:
//
//	api-endpoint: https://api.google.com
//	authz-token: AUTHORIZATION_TOKEN
//	identifier: IDENTIFIER
//	env: LIVE | DEBUG
var (
	APIEndpointFlag = Flag[string]{
		Name:       "api-endpoint",
		ConfigName: "api-endpoint",
		Default:    "DEFAULT_API_ENDPOINT",
		Usage:      "API Endpoint",
	}
	AuthZTokenFlag = Flag[string]{
		Name:       "authz-token",
		ConfigName: "authz-token",
		Default:    "DEFAULT_AUTHORIZATION_TOKEN",
		Usage:      "Authorization Token",
	}
	IdentifierFlag = Flag[string]{
		Name:       "identifier",
		ConfigName: "identifier",
		Default:    "DEFAULT_IDENTIFIER",
		Usage:      "Identifier",
	}
	EnvFlag = Flag[string]{
		Name:       "env",
		ConfigName: "env",
		Default:    "LIVE",
		Usage:      "Environment",
	}
)

// ExportFlagGroup composes common printer flag structs
// used for commands requiring export logic.
type ExportFlagGroup struct {
	APIEndpoint *Flag[string]
	AuthZToken  *Flag[string]
	Identifier  *Flag[string]
	Env         *Flag[string]
}

type ExportOptions struct {
	APIEndpoint string
	AuthZToken  string
	Identifier  string
	Env         string
}

func NewExportFlagGroup() *ExportFlagGroup {
	return &ExportFlagGroup{
		APIEndpoint: &APIEndpointFlag,
		AuthZToken:  &AuthZTokenFlag,
		Identifier:  &IdentifierFlag,
		Env:         &EnvFlag,
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
	}
}

func (f *ExportFlagGroup) ToOptions(args []string) (ExportOptions, error) {
	apiEndpoint := f.APIEndpoint.Value()
	authZToken := f.AuthZToken.Value()
	identifier := f.Identifier.Value()
	env := f.Env.Value()

	return ExportOptions{
		APIEndpoint: apiEndpoint,
		AuthZToken:  authZToken,
		Identifier:  identifier,
		Env:         env,
	}, nil
}
