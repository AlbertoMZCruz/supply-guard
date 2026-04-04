package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
	"github.com/AlbertoMZCruz/supply-guard/internal/version"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("supply-guard %s\n", version.Version)
		fmt.Printf("  commit:  %s\n", version.Commit)
		fmt.Printf("  built:   %s\n", version.Date)
		fmt.Printf("  go:      %s\n", runtime.Version())
		fmt.Printf("  os/arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
