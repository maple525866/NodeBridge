package mcpserver

import (
	"context"
	"fmt"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type bearerRoundTripper struct {
	base  http.RoundTripper
	token string
}

func (b *bearerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	if b.token != "" {
		clone.Header.Set("Authorization", "Bearer "+b.token)
	}
	return b.base.RoundTrip(clone)
}

// RunStdioBridge 启动轻量 stdio MCP 桥接：从本地常驻 Streamable HTTP Daemon 拉取工具清单并透明转发所有工具调用。
func RunStdioBridge(ctx context.Context, mcpURL, token, version string) error {
	if version == "" {
		version = "0.1.0"
	}
	httpClient := &http.Client{
		Transport: &bearerRoundTripper{
			base:  http.DefaultTransport,
			token: token,
		},
	}

	client := mcp.NewClient(&mcp.Implementation{
		Name:    "nodebridge-stdio-bridge",
		Version: version,
	}, nil)

	upstream, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   mcpURL,
		HTTPClient: httpClient,
	}, nil)
	if err != nil {
		return fmt.Errorf("连接本地常驻 Daemon (%s) 失败，请确认已运行 `nodebridge daemon`: %w", mcpURL, err)
	}
	defer upstream.Close()

	listRes, err := upstream.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		return fmt.Errorf("从本地 Daemon 获取工具清单失败: %w", err)
	}

	bridgeSrv := mcp.NewServer(&mcp.Implementation{
		Name:    "nodebridge-stdio",
		Version: version,
	}, nil)

	for _, t := range listRes.Tools {
		toolCopy := *t
		toolName := t.Name
		bridgeSrv.AddTool(&toolCopy, func(callCtx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var args any
			if req != nil && req.Params != nil {
				args = req.Params.Arguments
			}
			return upstream.CallTool(callCtx, &mcp.CallToolParams{
				Name:      toolName,
				Arguments: args,
			})
		})
	}

	return bridgeSrv.Run(ctx, &mcp.StdioTransport{})
}
