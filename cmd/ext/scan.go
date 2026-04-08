package ext

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/c0tton-fluff/burp-mcp-server/internal/bridge"
	"github.com/spf13/cobra"
)

var (
	scanRaw     string
	scanURL     string
	scanMethod  string
	scanHost    string
	scanPort    int
	scanHTTPS   bool
	scanConfig  string
	scanWait    bool
	scanTimeout time.Duration
	scanJSON    bool
)

var ScanCmd = &cobra.Command{
	Use:   "scan [request-file]",
	Short: "Trigger targeted audit on a request",
	Long: `Trigger a Burp scanner audit on a specific HTTP request.
All loaded extension scan checks fire automatically.

Request source (pick one):
  burp ext scan request.txt          # from file
  burp ext scan --raw "POST /api ..."  # inline raw request

Audit type: --config active|passive (default: active)
Blocking: --wait blocks until scan completes (with optional --timeout)`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var rawRequest string

		switch {
		case len(args) == 1:
			data, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("read request file: %w", err)
			}
			rawRequest = string(data)
		case scanRaw != "":
			rawRequest = scanRaw
		default:
			return fmt.Errorf("provide a request file or --raw")
		}

		if rawRequest == "" {
			return fmt.Errorf("empty request")
		}

		client := bridge.NewClient()

		req := bridge.ScanRequest{
			Request: rawRequest,
			Host:    scanHost,
			Port:    scanPort,
			HTTPS:   scanHTTPS,
			Config:  scanConfig,
		}

		status, err := client.StartScan(req)
		if err != nil {
			return err
		}

		if scanJSON && !scanWait {
			out, _ := json.MarshalIndent(status, "", "  ")
			fmt.Println(string(out))
			return nil
		}

		if !scanWait {
			fmt.Printf("SCAN %s -- %s -- %s audit -- %s\n",
				status.ScanID, status.Target, status.Config, status.Status)
			return nil
		}

		// Polling mode
		deadline := time.Now().Add(scanTimeout)
		for {
			if time.Now().After(deadline) {
				fmt.Printf("TIMEOUT: scan %s still running after %s\n",
					status.ScanID, scanTimeout)
				os.Exit(1)
			}

			s, err := client.GetScanStatus(status.ScanID)
			if err != nil {
				return err
			}

			if s.Status == "completed" || s.Status == "failed" || s.Status == "cancelled" {
				if scanJSON {
					out, _ := json.MarshalIndent(s, "", "  ")
					fmt.Println(string(out))
				} else {
					fmt.Printf("SCAN %s -- %s -- %d findings\n",
						s.ScanID, s.Status, s.FindingsCount)
				}
				return nil
			}

			time.Sleep(2 * time.Second)
		}
	},
}

func init() {
	ScanCmd.Flags().StringVar(&scanRaw, "raw", "", "Inline raw HTTP request")
	ScanCmd.Flags().StringVar(&scanHost, "host", "", "Target host (overrides Host header)")
	ScanCmd.Flags().IntVar(&scanPort, "port", 443, "Target port")
	ScanCmd.Flags().BoolVar(&scanHTTPS, "https", true, "Use HTTPS")
	ScanCmd.Flags().StringVar(&scanConfig, "config", "active", "Audit type (active/passive)")
	ScanCmd.Flags().BoolVar(&scanWait, "wait", false, "Block until scan completes")
	ScanCmd.Flags().DurationVar(&scanTimeout, "timeout", 5*time.Minute, "Max wait time (with --wait)")
	ScanCmd.Flags().BoolVar(&scanJSON, "json", false, "JSON output")
}
