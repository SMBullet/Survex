package tools

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// AIConfig holds configuration for an AI provider.
type AIConfig struct {
	Provider string // "anthropic" | "openai" | "deepseek" | "gemini" | "ollama" | "pollinations"
	APIKey   string
	Model    string
	BaseURL  string // custom endpoint (Ollama / self-hosted)
}

// DefaultModel returns the recommended default model for a provider.
func (c *AIConfig) DefaultModel() string {
	switch c.Provider {
	case "anthropic":
		return "claude-haiku-4-5-20251001"
	case "openai":
		return "gpt-4o-mini"
	case "deepseek":
		return "deepseek-chat"
	case "gemini":
		return "gemini-1.5-flash"
	case "ollama":
		return "llama3.2"
	case "pollinations":
		return "openai"
	}
	return ""
}

// Query sends a prompt to the configured provider and returns the text response.
func (c *AIConfig) Query(systemPrompt, userPrompt string) (string, error) {
	if c.Provider == "" {
		return "", fmt.Errorf("no AI provider configured")
	}
	model := c.Model
	if model == "" {
		model = c.DefaultModel()
	}
	switch c.Provider {
	case "anthropic":
		return c.queryAnthropic(model, systemPrompt, userPrompt)
	case "gemini":
		return c.queryGemini(model, systemPrompt, userPrompt)
	default: // openai, deepseek, ollama, pollinations — all OpenAI-compatible
		return c.queryOpenAICompat(model, systemPrompt, userPrompt)
	}
}

// ── Anthropic Messages API ───────────────────────────────────────────────────

type anthropicReq struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	System    string             `json:"system,omitempty"`
	Messages  []anthropicMessage `json:"messages"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResp struct {
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (c *AIConfig) queryAnthropic(model, system, user string) (string, error) {
	payload := anthropicReq{
		Model:     model,
		MaxTokens: 1024,
		System:    system,
		Messages:  []anthropicMessage{{Role: "user", Content: user}},
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("anthropic request: %w", err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	var result anthropicResp
	if err := json.Unmarshal(data, &result); err != nil {
		return "", fmt.Errorf("parse anthropic response: %w", err)
	}
	if result.Error != nil {
		return "", fmt.Errorf("anthropic: %s", result.Error.Message)
	}
	if len(result.Content) == 0 {
		return "", fmt.Errorf("empty response from anthropic")
	}
	return result.Content[0].Text, nil
}

// ── OpenAI-compatible (OpenAI, DeepSeek, Ollama, Pollinations) ──────────────

type openAIReq struct {
	Model    string         `json:"model"`
	Messages []openAIMessage `json:"messages"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIResp struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (c *AIConfig) queryOpenAICompat(model, system, user string) (string, error) {
	endpoint := c.openAIEndpoint()

	messages := []openAIMessage{}
	if system != "" {
		messages = append(messages, openAIMessage{Role: "system", Content: system})
	}
	messages = append(messages, openAIMessage{Role: "user", Content: user})

	body, _ := json.Marshal(openAIReq{Model: model, Messages: messages})

	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	var result openAIResp
	if err := json.Unmarshal(data, &result); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}
	if result.Error != nil {
		return "", fmt.Errorf("API error: %s", result.Error.Message)
	}
	if len(result.Choices) == 0 {
		return "", fmt.Errorf("empty response")
	}
	return result.Choices[0].Message.Content, nil
}

// openAIEndpoint returns the full chat completions endpoint URL for the provider.
func (c *AIConfig) openAIEndpoint() string {
	switch c.Provider {
	case "openai":
		return "https://api.openai.com/v1/chat/completions"
	case "deepseek":
		return "https://api.deepseek.com/v1/chat/completions"
	case "pollinations":
		// Free public endpoint — no API key required.
		return "https://text.pollinations.ai/openai"
	case "ollama":
		base := c.BaseURL
		if base == "" {
			base = "http://localhost:11434"
		}
		return strings.TrimRight(base, "/") + "/v1/chat/completions"
	}
	return "https://api.openai.com/v1/chat/completions"
}

// ── Google Gemini ────────────────────────────────────────────────────────────

type geminiReq struct {
	Contents          []geminiContent  `json:"contents"`
	SystemInstruction *geminiContent   `json:"system_instruction,omitempty"`
}

type geminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []geminiPart `json:"parts"`
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiResp struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (c *AIConfig) queryGemini(model, system, user string) (string, error) {
	url := fmt.Sprintf(
		"https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s",
		model, c.APIKey,
	)

	payload := geminiReq{
		Contents: []geminiContent{
			{Role: "user", Parts: []geminiPart{{Text: user}}},
		},
	}
	if system != "" {
		payload.SystemInstruction = &geminiContent{
			Parts: []geminiPart{{Text: system}},
		}
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("gemini request: %w", err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	var result geminiResp
	if err := json.Unmarshal(data, &result); err != nil {
		return "", fmt.Errorf("parse gemini response: %w", err)
	}
	if result.Error != nil {
		return "", fmt.Errorf("gemini: %s", result.Error.Message)
	}
	if len(result.Candidates) == 0 || len(result.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("empty response from gemini")
	}
	return result.Candidates[0].Content.Parts[0].Text, nil
}

// ── Task-specific helpers ────────────────────────────────────────────────────

// ExplainFinding explains a security finding: what it is, impact, and remediation.
func (c *AIConfig) ExplainFinding(title, detail, severity, asset string) (string, error) {
	system := `You are a senior security engineer briefing a team on a finding.
Be concise — max 4 short paragraphs. Structure:
1. What it is (1-2 sentences)
2. Impact and exploitation scenario (2-3 sentences)
3. Remediation steps (3-5 bullet points starting with •)
Do not use markdown headers or bold text.`

	user := fmt.Sprintf(`Security Finding
Title: %s
Severity: %s
Asset: %s
Detail: %s

Explain this finding clearly: what it is, how an attacker could exploit it, and concrete remediation steps.`,
		title, severity, asset, detail)

	return c.Query(system, user)
}

// SuggestScanConfig suggests scan profile and modules for a described target.
func (c *AIConfig) SuggestScanConfig(description string) (string, error) {
	system := `You are an attack surface management expert. Given a target description, suggest the optimal scan configuration.
Respond ONLY in valid JSON — no markdown fences, no extra text. Use exactly this schema:
{
  "profile": "quick|web|full|passive|cloud|custom",
  "modules": ["array", "of", "module", "ids"],
  "reasoning": "One or two sentences explaining your choices.",
  "warnings": "Any important caveats, or empty string."
}
Available profiles: quick (fast recon), web (full web+vuln), full (everything), passive (no active probing), cloud (cloud storage focus).
Available modules: crts, dns, dnsbrute, subfinder, amass, gau, katana, screenshot, shodan, httpx, tls, waf, headers, cors, cookies, takeover, email, jsscan, github, s3, nmap, nuclei, apidiscovery, graphql, ffuf, openredirect, dalfox, sqlmap.
When profile is not "custom", set modules to an empty array — the profile defines them.`

	user := fmt.Sprintf(`Target description: %s

Suggest the best scan configuration for this target. Consider scope, noise/stealth, and what attack surface is most relevant.`, description)

	return c.Query(system, user)
}

// ExecutiveSummary generates a management-level paragraph summarizing scan findings.
func (c *AIConfig) ExecutiveSummary(client string, findingCount int, maxSeverity, findings string) (string, error) {
	system := `You are a security consultant writing an executive summary for a client report.
Write 3-5 sentences maximum. Use plain business language — no jargon, no markdown, no bullet points.
Cover: overall risk posture, the most critical issues found, and the top recommended action.`

	user := fmt.Sprintf(`Client: %s
Total Findings: %d
Highest Severity: %s
Top Findings:
%s

Write a concise executive summary suitable for a CISO or board audience.`,
		client, findingCount, maxSeverity, findings)

	return c.Query(system, user)
}
