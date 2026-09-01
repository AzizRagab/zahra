package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	cfgFile string
	apiURL  string
	jsonOut bool
	quiet   bool
	verbose bool
)

// rootCmd is the base command. The Long description is deliberately
// short (4.8.2 — help must fit on one laptop screen).
var rootCmd = &cobra.Command{
	Use:   "pentestswarm",
	Short: "Autonomous AI-Powered Penetration Testing",
	Long:  `Swarms of AI agents autonomously pentest a target — recon, exploitation, reporting.`,
	CompletionOptions: cobra.CompletionOptions{
		HiddenDefaultCmd: true, // declutter the help output (4.8.2)
	},
}

// Execute runs the root command.
func Execute(version, commit, date string) {
	rootCmd.Version = fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: ./config.yaml)")
	rootCmd.PersistentFlags().StringVar(&apiURL, "api", "http://localhost:8080", "API server URL")
	rootCmd.PersistentFlags().BoolVar(&jsonOut, "json", false, "output in JSON format")
	rootCmd.PersistentFlags().BoolVar(&quiet, "quiet", false, "suppress decorative output")
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "enable debug logging")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
