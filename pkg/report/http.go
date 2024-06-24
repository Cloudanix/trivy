package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/google/uuid"
	retry "github.com/hashicorp/go-retryablehttp"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	HeaderAuthorization     = "Authorization"
	HeaderAccountId         = "cdx-account-id"
	HeaderSessionId         = "cdx-session-id"
	HeaderClusterIdentifier = "cdx-cluster-identifier"
	HeaderClusterName       = "cdx-cluster-name"
	HeaderClusterDomain     = "cdx-cluster-domain"
	HeaderNodeName          = "cdx-node-name"
)

const (
	ModeEnv     = "ENV"
	ModeArg     = "ARG"
	ModeCI      = "CI_PLUGIN"
	ModeRuntime = "RUNTIME_PLUGIN"
)

// HttpWriter implements result Writer
type HttpWriter struct {
	Mode string

	AuthZToken  string // Temporary storage for Auth Token
	ListenerUrl string `yaml:"LISTENER_URL"` // HTTP Listener URL

	AccountId         string `yaml:"ACCOUNT_ID"`         // Unique Account Id
	ClusterIdentifier string `yaml:"CLUSTER_IDENTIFIER"` // Cluster Identifier
	ClusterName       string `yaml:"CLUSTER_NAME"`       // Cluster Name
	ClusterDomain     string `yaml:"CLUSTER_DOMAIN"`     // Cluster Domain

	NodeName string // Node Name
}

func (hw HttpWriter) readEnvironments() {
	if _, ok := os.LookupEnv("API_ENDPOINT"); ok {
		hw.ListenerUrl = os.Getenv("API_ENDPOINT")
		hw.AuthZToken = os.Getenv("AUTHZ_TOKEN")
		hw.AccountId = os.Getenv("IDENTIFIER")
	}
}

func (hw HttpWriter) initHttpWriter(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var cfg *HttpWriter
	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(&cfg)
	if err != nil {
		return err
	}

	hw.ListenerUrl = cfg.ListenerUrl
	hw.AccountId = cfg.AccountId
	hw.ClusterIdentifier = cfg.ClusterIdentifier
	hw.ClusterName = cfg.ClusterName
	hw.ClusterDomain = cfg.ClusterDomain

	return nil
}

func readFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func (hw HttpWriter) readConfig() {
	cfgFile := "/etc/cdx/config/config.yaml"
	err := hw.initHttpWriter(cfgFile)
	if err != nil {
		log.Errorf("failed to load http-post config: %s - %s\n", cfgFile, err)
		return
	}

	sctFile := "/etc/cdx/secrets/auth-token"
	hw.AuthZToken, err = readFile(sctFile)
	if err != nil {
		log.Errorf("Unable to initialize authz token: %v - %v\n", sctFile, err)
	}

	log.Info("secrets initialized")

	hw.NodeName = os.Getenv("NODE_NAME")
}

// Write sends the results in JSON format to an external HTTP Endpoint
func (hw HttpWriter) Write(report types.Report) error {
	if hw.Mode == ModeRuntime {
		hw.readConfig()
	}

	output, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return xerrors.Errorf("failed to marshal json: %w", err)
	}

	if err := hw.publishReport(output); err != nil {
		return xerrors.Errorf("failed to publish report: %w", err)
	}
	return nil
}

func (hw HttpWriter) publishReport(report []byte) error {
	Rc := retry.NewClient().StandardClient()

	counter := 0

	for {
		req, err := http.NewRequest(http.MethodPost, hw.ListenerUrl, bytes.NewReader(report))
		if err != nil {
			return nil
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Add(HeaderAuthorization, fmt.Sprintf("Bearer %s", hw.AuthZToken))

		req.Header.Add(HeaderSessionId, uuid.New().String())

		if hw.AccountId != "" {
			req.Header.Add(HeaderAccountId, hw.AccountId)
		}

		if hw.ClusterIdentifier != "" {
			req.Header.Add(HeaderClusterIdentifier, hw.ClusterIdentifier)
		}

		if hw.ClusterName != "" {
			req.Header.Add(HeaderClusterName, hw.ClusterName)
		}

		if hw.ClusterDomain != "" {
			req.Header.Add(HeaderClusterDomain, hw.ClusterDomain)
		}

		if hw.NodeName != "" {
			req.Header.Add(HeaderNodeName, hw.NodeName)
		}

		counter++
		resp, err := Rc.Do(req)
		if err != nil {
			return err
		}

		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		log.Infof("Result published with status: %s", string(body))

		if err == nil && resp.StatusCode == http.StatusOK {
			return nil
		}

		if counter > 3 {
			return err
		}

		// sleep before next retry
		time.Sleep(4 * time.Second)
	}
}
