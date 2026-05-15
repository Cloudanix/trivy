package flag

// e.g. config yaml:
//
//	api-endpoint: https://api.google.com
//	authz-token: AUTHORIZATION_TOKEN
//	identifier: IDENTIFIER
//	env: LIVE | DEBUG

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
		APIEndpoint: APIEndpointFlag.Clone(),
		AuthZToken:  AuthZTokenFlag.Clone(),
		Identifier:  IdentifierFlag.Clone(),
		Env:         EnvFlag.Clone(),
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

func (f *ExportFlagGroup) ToOptions(opts *Options) error {
	opts.ExportOptions = ExportOptions{
		APIEndpoint: f.APIEndpoint.Value(),
		AuthZToken:  f.AuthZToken.Value(),
		Identifier:  f.Identifier.Value(),
		Env:         f.Env.Value(),
	}
	return nil
}
