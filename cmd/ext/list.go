package ext

import (
	"encoding/json"
	"fmt"

	"github.com/c0tton-fluff/burp-mcp-server/internal/bridge"
	"github.com/spf13/cobra"
)

var (
	listName    string
	listType    string
	listJSON    bool
)

var ListCmd = &cobra.Command{
	Use:   "list",
	Short: "List loaded extensions",
	RunE: func(cmd *cobra.Command, args []string) error {
		client := bridge.NewClient()
		resp, err := client.ListExtensions(listName, listType)
		if err != nil {
			return err
		}

		if listJSON {
			out, _ := json.MarshalIndent(resp, "", "  ")
			fmt.Println(string(out))
			return nil
		}

		// Table output matching spec format
		fmt.Printf("%-44s %-7s %-8s %s\n", "EXTENSION", "LOADED", "TYPE", "SCAN")
		for _, e := range resp.Extensions {
			loaded := "no"
			if e.Loaded {
				loaded = "yes"
			}
			scan := "no"
			if e.HasScanCheck {
				scan = "yes"
			}
			name := e.Name
			if len(name) > 44 {
				name = name[:41] + "..."
			}
			fmt.Printf("%-44s %-7s %-8s %s\n", name, loaded, e.Type, scan)
		}

		scanCount := 0
		for _, e := range resp.Extensions {
			if e.HasScanCheck {
				scanCount++
			}
		}
		fmt.Printf("---\n%d extensions, %d with scan checks\n",
			len(resp.Extensions), scanCount)
		return nil
	},
}

func init() {
	ListCmd.Flags().StringVar(&listName, "name", "", "Filter by name (substring)")
	ListCmd.Flags().StringVar(&listType, "type", "", "Filter by type (active/passive/utility)")
	ListCmd.Flags().BoolVar(&listJSON, "json", false, "JSON output")
}
