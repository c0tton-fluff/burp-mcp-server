package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const version = "1.0.0"

var rootCmd = &cobra.Command{
	Use:     "burp-mcp-server",
	Short:   "MCP server for Burp Suite",
	Long:    `A Model Context Protocol (MCP) server that proxies Burp Suite tools with clean, structured responses.`,
	Version: version,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringP("burp-url", "u", "", "Burp MCP SSE endpoint URL (or set BURP_MCP_URL env var)")
}

// getBurpURL returns the Burp SSE URL from flag or environment variable.
func getBurpURL(cmd *cobra.Command) string {
	url, _ := cmd.Flags().GetString("burp-url")
	if url == "" {
		url = os.Getenv("BURP_MCP_URL")
	}
	if url == "" {
		url = "http://127.0.0.1:9876/sse"
	}
	return url
}
