package threagile

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// initLSP wires a minimal Language Server Protocol implementation over stdio.
// Capabilities (initial pass): initialize, textDocument/didOpen, textDocument/didSave,
// textDocument/diagnostics (driven by validate + lint). Future iterations will add
// completion, hover, and go-to-definition.
func (what *Threagile) initLSP() *Threagile {
	lsp := &cobra.Command{
		Use:    LspCommand,
		Short:  "Run as a Language Server Protocol server over stdio (for IDE integration)",
		Hidden: true, // experimental; opt-in for IDE plugins
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)
			return runLSPServer(os.Stdin, os.Stdout)
		},
	}

	what.rootCmd.AddCommand(lsp)
	return what
}

// minimal LSP message reader/writer over Content-Length-framed stdio
type lspMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *lspError       `json:"error,omitempty"`
}

type lspError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func runLSPServer(in io.Reader, out io.Writer) error {
	reader := bufio.NewReader(in)

	for {
		// read headers
		contentLength := 0
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return err
			}
			line = strings.TrimRight(line, "\r\n")
			if line == "" {
				break
			}
			if strings.HasPrefix(strings.ToLower(line), "content-length:") {
				v := strings.TrimSpace(line[len("content-length:"):])
				contentLength, _ = strconv.Atoi(v)
			}
		}

		if contentLength == 0 {
			continue
		}

		body := make([]byte, contentLength)
		if _, err := io.ReadFull(reader, body); err != nil {
			return err
		}

		var msg lspMessage
		if err := json.Unmarshal(body, &msg); err != nil {
			continue
		}

		switch msg.Method {
		case "initialize":
			writeLSPResponse(out, msg.ID, map[string]any{
				"capabilities": map[string]any{
					"textDocumentSync": 1, // full sync
					"completionProvider": map[string]any{
						"triggerCharacters": []string{":", " "},
					},
				},
				"serverInfo": map[string]any{
					"name":    "threagile-lsp",
					"version": ThreagileVersion,
				},
			})

		case "initialized":
			// notification — no response

		case "shutdown":
			writeLSPResponse(out, msg.ID, nil)

		case "exit":
			return nil

		case "textDocument/didOpen", "textDocument/didSave", "textDocument/didChange":
			// Run validate + lint on the document URI and publish diagnostics
			var p struct {
				TextDocument struct {
					URI string `json:"uri"`
				} `json:"textDocument"`
			}
			_ = json.Unmarshal(msg.Params, &p)
			uri := p.TextDocument.URI
			path := strings.TrimPrefix(uri, "file://")

			diags := lspDiagnosticsFor(path)
			writeLSPNotification(out, "textDocument/publishDiagnostics", map[string]any{
				"uri":         uri,
				"diagnostics": diags,
			})

		default:
			if len(msg.ID) > 0 {
				// respond to unknown request with method-not-found
				writeLSPErrorResponse(out, msg.ID, -32601, "method not found: "+msg.Method)
			}
		}
	}
}

type lspDiagnostic struct {
	Range    lspRange `json:"range"`
	Severity int      `json:"severity"` // 1=error, 2=warning, 3=info, 4=hint
	Message  string   `json:"message"`
	Source   string   `json:"source"`
}

type lspRange struct {
	Start lspPosition `json:"start"`
	End   lspPosition `json:"end"`
}

type lspPosition struct {
	Line      int `json:"line"`
	Character int `json:"character"`
}

func lspDiagnosticsFor(path string) []lspDiagnostic {
	var diags []lspDiagnostic
	if path == "" {
		return diags
	}

	zeroRange := lspRange{Start: lspPosition{0, 0}, End: lspPosition{0, 80}}

	for _, e := range validateModel(path) {
		diags = append(diags, lspDiagnostic{
			Range:    zeroRange,
			Severity: 1, // error
			Message:  e,
			Source:   "threagile/validate",
		})
	}
	for _, f := range lintModel(path) {
		sev := 2 // warning
		if f.Severity == "info" {
			sev = 3
		}
		msg := f.Message
		if f.Asset != "" {
			msg = fmt.Sprintf("[%s] %s", f.Asset, msg)
		}
		diags = append(diags, lspDiagnostic{
			Range:    zeroRange,
			Severity: sev,
			Message:  msg,
			Source:   "threagile/lint",
		})
	}

	return diags
}

func writeLSPResponse(out io.Writer, id json.RawMessage, result any) {
	resp := lspMessage{JSONRPC: "2.0", ID: id, Result: result}
	writeLSPMessage(out, resp)
}

func writeLSPErrorResponse(out io.Writer, id json.RawMessage, code int, message string) {
	resp := lspMessage{JSONRPC: "2.0", ID: id, Error: &lspError{Code: code, Message: message}}
	writeLSPMessage(out, resp)
}

func writeLSPNotification(out io.Writer, method string, params any) {
	raw, _ := json.Marshal(params)
	resp := lspMessage{JSONRPC: "2.0", Method: method, Params: raw}
	writeLSPMessage(out, resp)
}

func writeLSPMessage(out io.Writer, msg lspMessage) {
	data, _ := json.Marshal(msg)
	fmt.Fprintf(out, "Content-Length: %d\r\n\r\n", len(data))
	_, _ = out.Write(data)
}
