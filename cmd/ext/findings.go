package ext

import (
	"encoding/json"
	"fmt"

	"github.com/c0tton-fluff/burp-mcp-server/internal/bridge"
	"github.com/spf13/cobra"
)

var (
	findingsScanID     string
	findingsSeverity   string
	findingsConfidence string
	findingsExtension  string
	findingsURL        string
	findingsJSON       bool
)

var FindingsCmd = &cobra.Command{
	Use:   "findings",
	Short: "List scanner findings",
	RunE: func(cmd *cobra.Command, args []string) error {
		client := bridge.NewClient()
		resp, err := client.GetFindings(bridge.FindingsFilter{
			ScanID:     findingsScanID,
			Severity:   findingsSeverity,
			Confidence: findingsConfidence,
			Extension:  findingsExtension,
			URL:        findingsURL,
		})
		if err != nil {
			return err
		}

		if findingsJSON {
			out, _ := json.MarshalIndent(resp, "", "  ")
			fmt.Println(string(out))
			return nil
		}

		if len(resp.Findings) == 0 {
			fmt.Println("No findings")
			return nil
		}

		fmt.Printf("%-9s %-11s %-29s %-25s %s\n",
			"SEVERITY", "CONFIDENCE", "EXTENSION", "URL", "NAME")
		for _, f := range resp.Findings {
			ext := f.Extension
			if len(ext) > 29 {
				ext = ext[:26] + "..."
			}
			target := f.Method + " " + f.URL
			if len(target) > 25 {
				target = target[:22] + "..."
			}
			fmt.Printf("%-9s %-11s %-29s %-25s %s\n",
				f.Severity, f.Confidence, ext, target, f.Name)
		}
		fmt.Printf("---\n%d findings\n", resp.Count)
		return nil
	},
}

func init() {
	FindingsCmd.Flags().StringVar(&findingsScanID, "scan", "", "Filter by scan ID")
	FindingsCmd.Flags().StringVar(&findingsSeverity, "severity", "", "Filter by severity (high/medium/low/info)")
	FindingsCmd.Flags().StringVar(&findingsConfidence, "confidence", "", "Filter by confidence (certain/firm/tentative)")
	FindingsCmd.Flags().StringVar(&findingsExtension, "ext", "", "Filter by extension name (substring)")
	FindingsCmd.Flags().StringVar(&findingsURL, "url", "", "Filter by URL (substring)")
	FindingsCmd.Flags().BoolVar(&findingsJSON, "json", false, "JSON output")
}
