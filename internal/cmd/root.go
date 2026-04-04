package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/AlbertoMZCruz/supply-guard/internal/config"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "supply-guard",
	Short: "Supply chain security scanner",
	Long: `SupplyGuard detects what vulnerability scanners miss:
malicious packages, suspicious install scripts, typosquatting,
IOC matches, and policy violations.

Zero dependencies. Works offline. Complements Trivy/Grype/Snyk.`,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: ./supplyguard.yaml)")
	rootCmd.PersistentFlags().StringP("output", "o", "table", "output format: table, json, sarif")
	rootCmd.PersistentFlags().StringSlice("fail-on", []string{}, "fail with exit code 1 on these severities (e.g. critical,high)")

	_ = viper.BindPFlag("output", rootCmd.PersistentFlags().Lookup("output"))
	_ = viper.BindPFlag("fail_on", rootCmd.PersistentFlags().Lookup("fail-on"))
}

func initConfig() {
	config.SetDefaults()

	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		cwd, err := os.Getwd()
		if err != nil {
			fmt.Fprintln(os.Stderr, "warning: cannot get working directory:", err)
			return
		}
		viper.AddConfigPath(cwd)
		viper.SetConfigName("supplyguard")
		viper.SetConfigType("yaml")

		home, err := os.UserHomeDir()
		if err == nil {
			viper.AddConfigPath(filepath.Join(home, ".config", "supplyguard"))
		}
	}

	viper.SetEnvPrefix("SUPPLYGUARD")
	viper.AutomaticEnv()

	_ = viper.ReadInConfig()
}
