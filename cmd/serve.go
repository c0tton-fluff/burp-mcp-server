package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/c0tton-fluff/burp-mcp-server/internal/burp"
	"github.com/c0tton-fluff/burp-mcp-server/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the MCP server",
	Long: `Start the MCP server for Burp Suite.

This command connects to Burp's MCP extension via SSE and exposes
clean, structured tools to Claude Code via stdio.`,
	RunE: runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)
}

func runServe(cmd *cobra.Command, args []string) error {
	burpURL := getBurpURL(cmd)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	// Connect to Burp's MCP extension via SSE
	fmt.Fprintf(os.Stderr, "Connecting to Burp MCP at %s...\n", burpURL)
	burpClient, err := burp.NewClient(burpURL)
	if err != nil {
		return fmt.Errorf("failed to create Burp client: %w", err)
	}

	session, err := burpClient.Connect(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to Burp MCP: %w", err)
	}
	defer burpClient.Close()
	fmt.Fprintf(os.Stderr, "Connected to Burp MCP\n")

	// Create MCP server for Claude Code
	server := mcp.NewServer(
		&mcp.Implementation{
			Name:    "burp-mcp-server",
			Version: version,
		},
		nil,
	)

	// Register tools
	tools.RegisterSendRequestTool(server, session)
	tools.RegisterGetProxyHistoryTool(server, session)
	tools.RegisterGetScannerIssuesTool(server, session)
	tools.RegisterCreateRepeaterTabTool(server, session)
	tools.RegisterSendToIntruderTool(server, session)
	tools.RegisterEncodeTool(server, session)
	tools.RegisterDecodeTool(server, session)

	// Run the server with stdio transport
	fmt.Fprintf(os.Stderr, "Burp MCP server ready (stdio)\n")
	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil {
		return fmt.Errorf("server error: %w", err)
	}

	return nil
}
