package main

import (
	"context"
	"os"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/commands"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/plugin"

	_ "modernc.org/sqlite" // sqlite driver for RPM DB and Java DB
)

var (
	version = "dev"
)

func main() {
	if err := run(); err != nil {
		log.Fatal("Fatal error", log.Err(err))
	}
}

func run() error {
	// Trivy behaves as the specified plugin.
	if runAsPlugin := os.Getenv("TRIVY_RUN_AS_PLUGIN"); runAsPlugin != "" {
		log.InitLogger(false, false)
		if err := plugin.Run(context.Background(), runAsPlugin, plugin.Options{Args: os.Args[1:]}); err != nil {
			return xerrors.Errorf("plugin error: %w", err)
		}

		return nil
	}

	app := commands.NewApp()
	if err := app.Execute(); err != nil {
		return err
	}
	return nil
}
