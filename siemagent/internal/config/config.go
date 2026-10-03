package config

import "os"

// Gemini exposes an OpenAI-compatible endpoint, so the existing go-openai
// client works against it unchanged.
const (
	geminiBaseURL = "https://generativelanguage.googleapis.com/v1beta/openai/"
	geminiModel   = "gemini-3.8-flash"
	kimchiBaseURL = "https://api.kimchi.ai/v1"
	kimchiModel   = "kimi-k2-5"
)

type Config struct {
	Provider      string // "gemini" or "kimchi" (any OpenAI-compatible endpoint)
	BaseURL       string // OpenAI-compatible endpoint
	APIKey        string
	ModelName     string
	Workers       int
	Port          string
	QdrantAddr    string // gRPC address for Qdrant (host:port)
	OllamaURL     string // Ollama base URL for embeddings
	AllowedOrigin string // CORS allowed origin
}

func Load() Config {
	// GEMINI_API_KEY takes precedence; otherwise fall back to Kimchi/OpenAI.
	// Each provider reads its own model variable so a leftover Kimchi
	// SIEM_MODEL is never sent to Gemini.
	provider := "gemini"
	apiKey := os.Getenv("GEMINI_API_KEY")
	baseURL := os.Getenv("GEMINI_BASE_URL")
	model := os.Getenv("GEMINI_MODEL")
	defaultBaseURL, defaultModel := geminiBaseURL, geminiModel
	if apiKey == "" {
		provider = "kimchi"
		apiKey = os.Getenv("KIMCHI_API_KEY")
		if apiKey == "" {
			apiKey = os.Getenv("OPENAI_API_KEY")
		}
		baseURL = os.Getenv("KIMCHI_BASE_URL")
		model = os.Getenv("SIEM_MODEL")
		defaultBaseURL, defaultModel = kimchiBaseURL, kimchiModel
	}
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	if model == "" {
		model = defaultModel
	}

	port := os.Getenv("CONDUCTOR_PORT")
	if port == "" {
		port = "8080"
	}

	qdrantAddr := os.Getenv("QDRANT_ADDR")
	if qdrantAddr == "" {
		qdrantAddr = "localhost:6334"
	}

	ollamaURL := os.Getenv("OLLAMA_URL")
	if ollamaURL == "" {
		ollamaURL = "http://localhost:11434"
	}

	allowedOrigin := os.Getenv("ALLOWED_ORIGIN")
	if allowedOrigin == "" {
		allowedOrigin = "http://localhost:5173"
	}

	return Config{
		Provider:      provider,
		BaseURL:       baseURL,
		APIKey:        apiKey,
		ModelName:     model,
		Workers:       5,
		Port:          port,
		QdrantAddr:    qdrantAddr,
		OllamaURL:     ollamaURL,
		AllowedOrigin: allowedOrigin,
	}
}
