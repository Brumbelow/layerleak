package config

import (
	"strings"
	"testing"
)

func TestLoadMetricsAddrDisabledByDefault(t *testing.T) {
	clearLayerleakEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.APIMetricsAddr != "" {
		t.Fatalf("APIMetricsAddr = %q, want empty (disabled)", cfg.APIMetricsAddr)
	}
}

func TestLoadMetricsAddrValidatesLikeAPIAddr(t *testing.T) {
	for _, value := range []string{"127.0.0.1:9090", "[::1]:9090", ":9090", "0.0.0.0:9090", "metrics.internal:9090"} {
		t.Run("valid/"+value, func(t *testing.T) {
			clearLayerleakEnv(t)
			t.Setenv("LAYERLEAK_API_METRICS_ADDR", " "+value+" ")
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if cfg.APIMetricsAddr != value {
				t.Fatalf("APIMetricsAddr = %q, want %q", cfg.APIMetricsAddr, value)
			}
		})
	}
	for _, value := range []string{"9090", "localhost", "127.0.0.1:0", "127.0.0.1:65536", "http://127.0.0.1:9090", "bad host:9090", "::1:9090"} {
		t.Run("invalid/"+value, func(t *testing.T) {
			clearLayerleakEnv(t)
			t.Setenv("LAYERLEAK_API_METRICS_ADDR", value)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "LAYERLEAK_API_METRICS_ADDR") {
				t.Fatalf("Load() error = %v, want LAYERLEAK_API_METRICS_ADDR rejection", err)
			}
		})
	}
}

func TestLoadMetricsAddrMustDifferFromAPIAddr(t *testing.T) {
	clearLayerleakEnv(t)
	t.Setenv("LAYERLEAK_API_ADDR", "0.0.0.0:8080")
	t.Setenv("LAYERLEAK_API_METRICS_ADDR", "0.0.0.0:8080")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "LAYERLEAK_API_METRICS_ADDR") || !strings.Contains(err.Error(), "LAYERLEAK_API_ADDR") {
		t.Fatalf("Load() error = %v, want both variables named", err)
	}

	t.Setenv("LAYERLEAK_API_METRICS_ADDR", "0.0.0.0:9090")
	if _, err := Load(); err != nil {
		t.Fatalf("Load() with distinct ports error = %v", err)
	}
}
