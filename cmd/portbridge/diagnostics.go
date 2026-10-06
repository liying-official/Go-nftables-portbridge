package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"portbridge/internal/config"
	"portbridge/internal/diagnostics"
)

func runDiagnosis(options commandOptions, output io.Writer) error {
	if options.diagnoseLanguage != "en-US" && options.diagnoseLanguage != "zh-CN" {
		return errors.New("--diagnose-language must be en-US or zh-CN")
	}
	if options.resetToken || options.cleanupNFT || options.prepareTLS || options.requireHTTPS || options.httpsInfo || options.httpsCheck || options.showVersion || options.validateBootstrap != "" || len(options.bootstrap) > 0 || options.httpsOpts.cert != "" || options.httpsOpts.key != "" || len(options.httpsOpts.names) > 0 {
		return errors.New("diagnosis cannot be combined with startup, mutation, or other inspection modes")
	}
	cfg, readErr := config.ReadOnly(options.cfgPath)
	if readErr != nil {
		cfg = config.Default()
	}
	report := diagnostics.Build(cfg, nil, false, diagnostics.InspectEnvironment(cfg, "diagnostic-command"))
	report.Source = "diagnostic-command"
	if readErr != nil {
		report.ConfigRevision = ""
		finding := diagnostics.Note("configuration_invalid", "error")
		finding.Evidence = readErr.Error()
		report.Findings = append(report.Findings, finding)
	} else if live, err := readServiceDiagnostics(cfg, options.tokenPath); err == nil {
		report = live
	} else {
		finding := diagnostics.Note("management_unavailable", "warning")
		finding.Evidence = err.Error()
		report.Findings = append(report.Findings, finding)
	}
	if options.diagnoseJSON {
		encoder := json.NewEncoder(output)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	}
	language := options.diagnoseLanguage
	if language == "zh-CN" {
		fmt.Fprintf(output, "PortBridge 只读诊断\n来源: %s；运行状态已观察: %t；业务健康: %s\n", report.Source, report.RuntimeObserved, report.BusinessHealth)
	} else {
		fmt.Fprintf(output, "PortBridge read-only diagnostics\nSource: %s; runtime observed: %t; business health: %s\n", report.Source, report.RuntimeObserved, report.BusinessHealth)
	}
	fmt.Fprintf(output, "CAP_NET_ADMIN=%s; CAP_NET_BIND_SERVICE=%s; nft=%t; conntrack=%t; accounting=%s\n", report.Environment.NetAdmin, report.Environment.BindService, report.Environment.NFTTool, report.Environment.ConntrackTool, report.Environment.ConntrackAccounting)
	printFindings(output, report.Findings, language)
	printFindings(output, report.Environment.Findings, language)
	if report.LatestOperation != nil {
		fmt.Fprintf(output, "%s: %s; %s; %s=%s\n", diagnosticLabel(language, "Operation", "应用操作"), report.LatestOperation.ID, report.LatestOperation.State, diagnosticLabel(language, "revision", "配置版本"), report.LatestOperation.Revision)
	}
	for _, rule := range report.Rules {
		fmt.Fprintf(output, "\n%q (%q): %s; %s=%s; %s=%s; %s=%s; Go=%t\n", rule.Name, rule.ID, rule.State, diagnosticLabel(language, "requested", "请求数据面"), rule.Requested, diagnosticLabel(language, "actual", "观察数据面"), rule.Actual, diagnosticLabel(language, "kernel", "内核状态"), rule.KernelState, rule.GoRunning)
		if rule.Evidence != "" {
			fmt.Fprintf(output, "  %s: %q\n", diagnosticLabel(language, "Evidence", "记录证据"), rule.Evidence)
		}
		printFindings(output, rule.Findings, language)
	}
	return nil
}

func diagnosticLabel(language, english, chinese string) string {
	if language == "zh-CN" {
		return chinese
	}
	return english
}

func printFindings(output io.Writer, findings []diagnostics.Finding, language string) {
	for _, finding := range findings {
		fmt.Fprintf(output, "[%s/%s] %s\n  %s\n", finding.Severity, finding.Code, finding.Summary.Localized(language), finding.Advice.Localized(language))
		if finding.Evidence != "" {
			fmt.Fprintf(output, "  %s: %q\n", diagnosticLabel(language, "Evidence", "记录证据"), finding.Evidence)
		}
	}
}

// This command performs one authenticated GET to a local listener. It never
// follows redirects, uses proxies, sends credentials to a remote host, or binds
// a test listener. If unavailable, only local read-only observations are shown.
func readServiceDiagnostics(cfg config.Config, tokenPath string) (diagnostics.Report, error) {
	var empty diagnostics.Report
	host := cfg.Web.ListenIPv4
	if host == "" {
		host = cfg.Web.ListenIPv6
	}
	if host == "0.0.0.0" {
		host = "127.0.0.1"
	} else if host == "::" {
		host = "::1"
	}
	address, err := netip.ParseAddr(host)
	if err != nil || !localDiagnosticAddress(address) {
		return empty, errors.New("management listener is not a verified local address")
	}
	data, err := os.ReadFile(tokenPath) // #nosec G304 -- local diagnostic token path.
	if err != nil {
		return empty, err
	}
	token := strings.TrimSpace(string(data))
	if len(token) != 64 || (config.HashToken(token) != cfg.Web.AdminTokenSHA && config.HashToken(token) != cfg.Web.MonitorTokenSHA) {
		return empty, errors.New("diagnostic token is not a configured credential")
	}
	scheme := "http"
	transport := &http.Transport{Proxy: nil, ResponseHeaderTimeout: 3 * time.Second}
	defer transport.CloseIdleConnections()
	if cfg.Web.TLSCertFile != "" {
		scheme = "https"
		cert, err := os.ReadFile(cfg.Web.TLSCertFile) // #nosec G304 -- validated local configuration certificate path.
		if err != nil {
			return empty, err
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(cert) {
			return empty, errors.New("management certificate is not valid PEM")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	} else if !address.IsLoopback() {
		return empty, errors.New("diagnostic credentials require HTTPS on non-loopback listeners")
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequest(http.MethodGet, scheme+"://"+net.JoinHostPort(host, strconv.Itoa(cfg.Web.Port))+"/api/diagnostics", nil)
	if err != nil {
		return empty, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Do(request)
	if err != nil {
		return empty, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return empty, errors.New("live diagnostics not accepted")
	}
	const limit = 4 << 20
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || len(body) > limit {
		return empty, errors.New("live diagnostics response unavailable or too large")
	}
	var report diagnostics.Report
	if err := json.Unmarshal(body, &report); err != nil {
		return empty, err
	}
	if !report.ReadOnly || !report.RuntimeObserved || report.Source != "service" {
		return empty, errors.New("live response is not a service diagnostic snapshot")
	}
	return report, nil
}

func localDiagnosticAddress(address netip.Addr) bool {
	if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() {
		return false
	}
	if address.IsLoopback() {
		return true
	}
	interfaces, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, item := range interfaces {
		prefix, err := netip.ParsePrefix(item.String())
		if err == nil && prefix.Addr().Unmap() == address.Unmap() {
			return true
		}
	}
	return false
}
