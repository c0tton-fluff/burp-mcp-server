package cmd

import (
	"github.com/c0tton-fluff/burp-mcp-server/cmd/ext"
	"github.com/spf13/cobra"
)

var extCmd = &cobra.Command{
	Use:   "ext",
	Short: "Interact with Burp extensions via bridge",
	Long:  `Commands for discovering extensions, triggering audits, and retrieving findings through the burp-bridge extension.`,
}

func init() {
	rootCmd.AddCommand(extCmd)

	extCmd.AddCommand(ext.HealthCmd)
	extCmd.AddCommand(ext.ListCmd)
	extCmd.AddCommand(ext.ScanCmd)
	extCmd.AddCommand(ext.StatusCmd)
	extCmd.AddCommand(ext.FindingsCmd)
	extCmd.AddCommand(ext.CancelCmd)
}
