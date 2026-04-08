package ext

import (
	"encoding/json"
	"fmt"

	"github.com/c0tton-fluff/burp-mcp-server/internal/bridge"
	"github.com/spf13/cobra"
)

var statusJSON bool

var StatusCmd = &cobra.Command{
	Use:   "status <scan-id>",
	Short: "Poll scan progress",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := bridge.NewClient()
		s, err := client.GetScanStatus(args[0])
		if err != nil {
			return err
		}

		if statusJSON {
			out, _ := json.MarshalIndent(s, "", "  ")
			fmt.Println(string(out))
			return nil
		}

		progress := ""
		if s.InsertionPointsTotal > 0 {
			progress = fmt.Sprintf(" -- %d/%d insertion points",
				s.InsertionPointsTested, s.InsertionPointsTotal)
		}
		elapsed := ""
		if s.ElapsedSeconds > 0 {
			elapsed = fmt.Sprintf(" -- %ds elapsed", s.ElapsedSeconds)
		}
		findings := ""
		if s.FindingsCount > 0 {
			findings = fmt.Sprintf(" -- %d finding(s)", s.FindingsCount)
		}

		fmt.Printf("SCAN %s -- %s%s%s%s\n",
			s.ScanID, s.Status, progress, elapsed, findings)
		return nil
	},
}

func init() {
	StatusCmd.Flags().BoolVar(&statusJSON, "json", false, "JSON output")
}
