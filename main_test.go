package main

import "testing"

func TestParseArgsRequiresCommand(t *testing.T) {
	_, err := parseArgs([]string{"-x", "socks5://127.0.0.1:1080"})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func TestParseArgsBasic(t *testing.T) {
	cfg, err := parseArgs([]string{
		"-x", "socks5://127.0.0.1:1080",
		"-d", "tun9",
		"--tun-cidr", "10.66.0.1/24",
		"-u", "tap9",
		"--",
		"curl", "-I", "https://example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.proxyURL != "socks5://127.0.0.1:1080" {
		t.Fatalf("unexpected proxyURL: %s", cfg.proxyURL)
	}
	if cfg.tunDevice != "tun9" {
		t.Fatalf("unexpected tunDevice: %s", cfg.tunDevice)
	}
	if cfg.tunCIDR != "10.66.0.1/24" {
		t.Fatalf("unexpected tunCIDR: %s", cfg.tunCIDR)
	}
	if cfg.uplinkDev != "tap9" {
		t.Fatalf("unexpected uplinkDev: %s", cfg.uplinkDev)
	}
	if len(cfg.command) != 3 {
		t.Fatalf("unexpected command length: %d", len(cfg.command))
	}
}

func TestParseArgsBasicWithoutDoubleDash(t *testing.T) {
	cfg, err := parseArgs([]string{
		"-x", "socks5://127.0.0.1:1080",
		"-d", "tun9",
		"--tun-cidr", "10.66.0.1/24",
		"-u", "tap9",
		"curl", "-I", "https://example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.proxyURL != "socks5://127.0.0.1:1080" {
		t.Fatalf("unexpected proxyURL: %s", cfg.proxyURL)
	}
	if cfg.tunDevice != "tun9" {
		t.Fatalf("unexpected tunDevice: %s", cfg.tunDevice)
	}
	if cfg.tunCIDR != "10.66.0.1/24" {
		t.Fatalf("unexpected tunCIDR: %s", cfg.tunCIDR)
	}
	if cfg.uplinkDev != "tap9" {
		t.Fatalf("unexpected uplinkDev: %s", cfg.uplinkDev)
	}
	if len(cfg.command) != 3 {
		t.Fatalf("unexpected command length: %d", len(cfg.command))
	}
}

func TestParseProxyHost(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"socks5://192.168.1.2:1080", "192.168.1.2"},
		{"http://user:pass@example.com:8080", "example.com"},
		{"127.0.0.1:1080", "127.0.0.1"},
		{"example.com", "example.com"},
	}

	for _, tc := range tests {
		got, err := parseProxyHost(tc.in)
		if err != nil {
			t.Fatalf("parseProxyHost(%q) unexpected error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("parseProxyHost(%q)=%q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseRouteLine(t *testing.T) {
	line := "192.168.231.2 via 10.0.2.2 dev tap0 src 10.0.2.100 uid 0"
	dev, via := parseRouteLine(line)
	if dev != "tap0" || via != "10.0.2.2" {
		t.Fatalf("unexpected parse result dev=%q via=%q", dev, via)
	}
}

func TestParseArgsInvalidTunCIDR(t *testing.T) {
	_, err := parseArgs([]string{
		"--tun-cidr", "not-a-cidr",
		"--",
		"echo", "ok",
	})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func TestParseArgsResolvConf(t *testing.T) {
	cfg, err := parseArgs([]string{
		"--resolv-conf", "/tmp/resolv.conf",
		"--",
		"echo", "ok",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.resolvConf != "/tmp/resolv.conf" {
		t.Fatalf("unexpected resolvConf: %s", cfg.resolvConf)
	}
}
