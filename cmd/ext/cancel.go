package ext

import (
	"fmt"

	"github.com/c0tton-fluff/burp-mcp-server/internal/bridge"
	"github.com/spf13/cobra"
)

var CancelCmd = &cobra.Command{
	Use:   "cancel <scan-id>",
	Short: "Cancel a running audit",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := bridge.NewClient()
		if err := client.CancelScan(args[0]); err != nil {
			return err
		}
		fmt.Printf("SCAN %s -- cancelled\n", args[0])
		return nil
	},
}
