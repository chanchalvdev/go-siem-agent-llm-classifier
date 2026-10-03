package config

import (
	"slices"
	"testing"
)

func clearLLMEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"LLM_PROVIDER", "GEMINI_API_KEY", "GEMINI_BASE_URL", "GEMINI_MODEL",
		"KIMCHI_API_KEY", "KIMCHI_BASE_URL", "OPENAI_API_KEY", "SIEM_MODEL",
		"OLLAMA_URL", "OLLAMA_MODEL", "SIEM_API_KEYS", "POSTGRES_DSN",
		"SYSLOG_UDP_ADDR", "SYSLOG_TCP_ADDR", "DETECTION_MODE", "SIGMA_RULES_DIR",
	} {
		t.Setenv(k, "")
	}
}

func TestLoadGemini(t *testing.T) {
	clearLLMEnv(t)
	t.Setenv("GEMINI_API_KEY", "g-key")
	t.Setenv("KIMCHI_API_KEY", "k-key")

	cfg := Load()
	if cfg.Provider != ProviderGemini || cfg.APIKey != "g-key" {
		t.Fatalf("want gemini/g-key, got %s/%s", cfg.Provider, cfg.APIKey)
	}
	if cfg.BaseURL != geminiBaseURL || cfg.ModelName != geminiModel {
		t.Fatalf("unexpected gemini defaults: %s %s", cfg.BaseURL, cfg.ModelName)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid gemini config rejected: %v", err)
	}
}

func TestLoadGeminiModelOverride(t *testing.T) {
	clearLLMEnv(t)
	t.Setenv("GEMINI_API_KEY", "g-key")
	t.Setenv("GEMINI_MODEL", "gemini-3.8-pro")

	if got := Load().ModelName; got != "gemini-3.8-pro" {
		t.Fatalf("want model override, got %s", got)
	}
}

func TestLoadGeminiIgnoresKimchiModel(t *testing.T) {
	clearLLMEnv(t)
	t.Setenv("GEMINI_API_KEY", "g-key")
	t.Setenv("SIEM_MODEL", "kimi-k2.7")

	if got := Load().ModelName; got != geminiModel {
		t.Fatalf("SIEM_MODEL leaked into gemini: got %s", got)
	}
}

func TestLoadOpenAIModelOverride(t *testing.T) {
	clearLLMEnv(t)
	t.Setenv("KIMCHI_API_KEY", "k-key")
	t.Setenv("SIEM_MODEL", "kimi-k2.7")

	if got := Load().ModelName; got != "kimi-k2.7" {
		t.Fatalf("want openai model override, got %s", got)
	}
}

func TestLoadOpenAIFallback(t *testing.T) {
	clearLLMEnv(t)
	t.Setenv("OPENAI_API_KEY", "o-key")

	cfg := Load()
	if cfg.Provider != ProviderOpenAI || cfg.APIKey != "o-key" {
		t.Fatalf("want openai/o-key, got %s/%s", cfg.Provider, cfg.APIKey)
	}
	if cfg.BaseURL != openaiBaseURL || cfg.ModelName != openaiModel {
		t.Fatalf("unexpected openai defaults: %s %s", cfg.BaseURL, cfg.ModelName)
	}
}

func TestLoadKimchiAlias(t *testing.T) {
	clearLLMEnv(t)
	t.Setenv("LLM_PROVIDER", "Kimchi")
	t.Setenv("GEMINI_API_KEY", "g-key")
	t.Setenv("KIMCHI_API_KEY", "k-key")

	cfg := Load()
	if cfg.Provider != ProviderOpenAI || cfg.APIKey != "k-key" {
		t.Fatalf("explicit kimchi should win over gemini key, got %s/%s", cfg.Provider, cfg.APIKey)
	}
}

func TestLoadOllama(t *testing.T) {
	clearLLMEnv(t)
	t.Setenv("LLM_PROVIDER", "ollama")
	t.Setenv("OLLAMA_URL", "http://ollama:11434/")
	t.Setenv("GEMINI_API_KEY", "g-key")

	cfg := Load()
	if cfg.Provider != ProviderOllama || cfg.ModelName != ollamaModel {
		t.Fatalf("want ollama/%s, got %s/%s", ollamaModel, cfg.Provider, cfg.ModelName)
	}
	if cfg.BaseURL != "http://ollama:11434/v1" || cfg.OllamaURL != "http://ollama:11434" {
		t.Fatalf("unexpected ollama URLs: base=%s ollama=%s", cfg.BaseURL, cfg.OllamaURL)
	}
	if cfg.APIKey == "" {
		t.Fatal("ollama needs a placeholder key for the OpenAI client")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("ollama needs no key, got %v", err)
	}
}

func TestValidate(t *testing.T) {
	clearLLMEnv(t)
	if err := Load().Validate(); err == nil {
		t.Fatal("missing key should fail validation")
	}

	t.Setenv("LLM_PROVIDER", "gemini")
	if err := Load().Validate(); err == nil {
		t.Fatal("gemini without GEMINI_API_KEY should fail validation")
	}

	t.Setenv("LLM_PROVIDER", "claude-local")
	if err := Load().Validate(); err == nil {
		t.Fatal("unknown provider should fail validation")
	}
}

func TestLoadPlatformSettings(t *testing.T) {
	clearLLMEnv(t)
	t.Setenv("SIEM_API_KEYS", " key-a , ,key-b ")
	t.Setenv("POSTGRES_DSN", "postgres://x")
	t.Setenv("SYSLOG_UDP_ADDR", ":5514")
	t.Setenv("DETECTION_MODE", " Enrich ")
	t.Setenv("SIGMA_RULES_DIR", "/rules")

	cfg := Load()
	if !slices.Equal(cfg.APIKeys, []string{"key-a", "key-b"}) || !cfg.AuthEnabled() {
		t.Fatalf("unexpected API keys: %q", cfg.APIKeys)
	}
	if cfg.DetectionMode != "enrich" || cfg.SigmaRulesDir != "/rules" {
		t.Fatalf("unexpected detection settings: %+v", cfg)
	}
	if cfg.PostgresDSN != "postgres://x" || cfg.SyslogUDPAddr != ":5514" || cfg.SyslogTCPAddr != "" {
		t.Fatalf("unexpected settings: %+v", cfg)
	}

	t.Setenv("SIEM_API_KEYS", "")
	if Load().AuthEnabled() {
		t.Fatal("auth should be off without keys")
	}
}
