package ext

import (
	"encoding/json"
	"fmt"

	"github.com/c0tton-fluff/burp-mcp-server/internal/bridge"
	"github.com/spf13/cobra"
)

var healthJSON bool

var HealthCmd = &cobra.Command{
	Use:   "health",
	Short: "Check bridge liveness",
	RunE: func(cmd *cobra.Command, args []string) error {
		client := bridge.NewClient()
		resp, err := client.Health()
		if err != nil {
			return err
		}

		if healthJSON {
			out, _ := json.MarshalIndent(resp, "", "  ")
			fmt.Println(string(out))
			return nil
		}

		fmt.Printf("BRIDGE OK -- Burp %s -- %d extensions -- bridge %s on :%d\n",
			resp.BurpVersion, resp.ExtensionsLoaded, resp.BridgeVersion, resp.Port)
		return nil
	},
}

func init() {
	HealthCmd.Flags().BoolVar(&healthJSON, "json", false, "JSON output")
}
