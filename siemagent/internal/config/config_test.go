package config

import "testing"

func clearLLMEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"GEMINI_API_KEY", "GEMINI_BASE_URL", "KIMCHI_API_KEY",
		"KIMCHI_BASE_URL", "OPENAI_API_KEY", "SIEM_MODEL", "GEMINI_MODEL",
	} {
		t.Setenv(k, "")
	}
}

func TestLoadGemini(t *testing.T) {
	clearLLMEnv(t)
	t.Setenv("GEMINI_API_KEY", "g-key")
	t.Setenv("KIMCHI_API_KEY", "k-key")

	cfg := Load()
	if cfg.Provider != "gemini" || cfg.APIKey != "g-key" {
		t.Fatalf("want gemini/g-key, got %s/%s", cfg.Provider, cfg.APIKey)
	}
	if cfg.BaseURL != geminiBaseURL || cfg.ModelName != geminiModel {
		t.Fatalf("unexpected gemini defaults: %s %s", cfg.BaseURL, cfg.ModelName)
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

func TestLoadKimchiModelOverride(t *testing.T) {
	clearLLMEnv(t)
	t.Setenv("KIMCHI_API_KEY", "k-key")
	t.Setenv("SIEM_MODEL", "kimi-k2.7")

	if got := Load().ModelName; got != "kimi-k2.7" {
		t.Fatalf("want kimchi model override, got %s", got)
	}
}

func TestLoadKimchiFallback(t *testing.T) {
	clearLLMEnv(t)
	t.Setenv("OPENAI_API_KEY", "o-key")

	cfg := Load()
	if cfg.Provider != "kimchi" || cfg.APIKey != "o-key" {
		t.Fatalf("want kimchi/o-key, got %s/%s", cfg.Provider, cfg.APIKey)
	}
	if cfg.BaseURL != kimchiBaseURL || cfg.ModelName != kimchiModel {
		t.Fatalf("unexpected kimchi defaults: %s %s", cfg.BaseURL, cfg.ModelName)
	}
}
