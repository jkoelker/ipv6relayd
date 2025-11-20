package config

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	jsonparser "github.com/knadh/koanf/parsers/json"
	yamlparser "github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
	"golang.org/x/net/idna"
)

const (
	modeRelay    = "relay"
	modeServer   = "server"
	modeDisabled = "disabled"
)

const (
	pref64Len32    = 32
	pref64Len40    = 40
	pref64Len48    = 48
	pref64Len56    = 56
	pref64Len64    = 64
	pref64Len96    = 96
	maxDomainASCII = 255
)

const pref64SupportedLengths = "32,40,48,56,64,96"

var (
	// ErrAddressNotLinkLocal indicates a non-link-local address was provided where link-local is required.
	ErrAddressNotLinkLocal = errors.New("address must be IPv6 link-local")

	// ErrAddressEmpty indicates an address field was left empty.
	ErrAddressEmpty = errors.New("address must not be empty")

	// ErrAddressNotIPv6 signals that a value expected to be IPv6 was not.
	ErrAddressNotIPv6 = errors.New("address must be IPv6")

	// ErrTemplatePlaceholder indicates a template missing the required placeholders.
	ErrTemplatePlaceholder = errors.New(`template must contain at least one placeholder "{ifname}" or "{mac}"`)

	// ErrDomainEmpty indicates a required domain value was empty.
	ErrDomainEmpty = errors.New("domain must not be empty")

	// ErrDomainMissingLabel indicates a domain without at least one label.
	ErrDomainMissingLabel = errors.New("domain must contain at least one label")

	// ErrDomainTooLong indicates a domain value exceeded the allowed length.
	ErrDomainTooLong = errors.New("domain too long")

	// ErrUnsupportedExtension indicates an unsupported configuration file extension.
	ErrUnsupportedExtension = errors.New("unsupported config extension")
)

type Config struct {
	// Upstream describes the primary upstream interface.
	Upstream InterfaceConfig `json:"upstream"`

	// Downstreams lists downstream interfaces managed by the daemon.
	Downstreams []InterfaceConfig `json:"downstreams"`

	// RA configures the Router Advertisement service.
	RA RAConfig `json:"ra"`

	// DHCPv6 configures the DHCPv6 relay features.
	DHCPv6 DHCPv6Config `json:"dhcpv6"`

	// NDP configures the Neighbor Discovery relay features.
	NDP NDPConfig `json:"ndp"`
}

type InterfaceConfig struct {
	// IfName is the interface name (e.g. "eth0").
	IfName string `json:"ifname"`

	// LinkLocal overrides the detected IPv6 link-local address.
	LinkLocal string `json:"link_local,omitempty"`

	// AddressHints preloads additional addresses to speed up discovery.
	AddressHints []string `json:"address_hints,omitempty"`

	// Passive prevents the interface from being used for active traffic.
	Passive bool `json:"passive,omitempty"`
}

type RAConfig struct {
	// Mode selects relay, server, or disabled RA operation.
	Mode string `json:"mode"`

	// DNSRewrite overrides advertised RDNSS values.
	DNSRewrite []string `json:"dns_rewrite,omitempty"`

	// DNSSearchRewrite overrides advertised DNSSL domains.
	DNSSearchRewrite []string `json:"dnssl_rewrite,omitempty"`

	// Pref64Rewrite configures PREF64 rewrite prefixes.
	Pref64Rewrite []string `json:"pref64_rewrite,omitempty"`

	// UnsolicitedInterval controls unsolicited RA send frequency.
	UnsolicitedInterval time.Duration `json:"unsolicited_interval,omitempty"`
}

type DHCPv6Config struct {
	// Enabled toggles the DHCPv6 service.
	Enabled bool `json:"enabled"`

	// Upstream specifies the IPv6 address or hostname of the upstream DHCPv6 server.
	Upstream string `json:"upstream,omitempty"`

	// OverrideDNS injects DNS server addresses into relayed responses.
	OverrideDNS []string `json:"override_dns,omitempty"`

	// OverrideDNSSearch injects DNS search domains into relayed responses.
	OverrideDNSSearch []string `json:"override_domain_search,omitempty"`

	// ForceReplyDNSRewrite allows the relay to overwrite DNS/DNSSL options in
	// Reply messages. Disabled by default to keep RFC 8415 compliance.
	ForceReplyDNSRewrite bool `json:"force_reply_dns_rewrite,omitempty"`

	// InjectInterface controls whether the relay-interface-id option is added.
	InjectInterface *bool `json:"relay_interface_id,omitempty"`

	// RemoteID configures the relay remote-id option.
	RemoteID RemoteIDConfig `json:"remote_id"`
}

type NDPConfig struct {
	// Mode selects relay or disabled behavior for NDP.
	Mode string `json:"mode"`

	// StaticEntries adds persistent relay targets.
	StaticEntries []NDPStaticBinding `json:"static_entries,omitempty"`

	// TargetCacheTTL controls how long learned targets stay valid.
	TargetCacheTTL time.Duration `json:"target_cache_ttl,omitempty"`
}

type NDPStaticBinding struct {
	// Prefix is the IPv6 prefix that should resolve via the interface.
	Prefix string `json:"prefix"`

	// Interface is the downstream interface that hosts the prefix.
	Interface string `json:"interface"`
}

type RemoteIDConfig struct {
	// Disabled skips adding the remote-id option.
	Disabled bool `json:"disabled,omitempty"`

	// EnterpriseID overrides the remote-id enterprise number.
	EnterpriseID uint32 `json:"enterprise_id,omitempty"`

	// Template renders the remote-id payload; placeholders depend on interface state.
	Template string `json:"template,omitempty"`
}

type ValidationError struct {
	// Issues holds the human-readable validation failures.
	Issues []string
}

func (v *ValidationError) Error() string {
	return "invalid configuration: " + strings.Join(v.Issues, "; ")
}

// Default returns a sample configuration that is safe to edit and load.
func Default() *Config {
	return &Config{
		Upstream:    InterfaceConfig{IfName: "wan"},
		Downstreams: []InterfaceConfig{{IfName: "lan0"}},
		RA:          RAConfig{Mode: modeRelay},
		DHCPv6:      DHCPv6Config{Enabled: true},
		NDP:         NDPConfig{Mode: modeRelay},
	}
}

func parserFor(path string) (koanf.Parser, error) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml", "":
		return yamlparser.Parser(), nil
	case ".json":
		return jsonparser.Parser(), nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedExtension, filepath.Ext(path))
	}
}

func Load(path string) (*Config, error) {
	parser, err := parserFor(path)
	if err != nil {
		return nil, err
	}

	konf := koanf.New(".")
	if err := konf.Load(file.Provider(path), parser); err != nil {
		return nil, fmt.Errorf("load config file: %w", err)
	}

	cfg := &Config{}
	unmarshalConf := koanf.UnmarshalConf{
		Tag: "json",
		DecoderConfig: &mapstructure.DecoderConfig{
			TagName:          "json",
			WeaklyTypedInput: true,
			ErrorUnused:      true,
			Result:           cfg,
			DecodeHook: mapstructure.ComposeDecodeHookFunc(
				mapstructure.StringToTimeDurationHookFunc(),
			),
		},
	}

	if err := konf.UnmarshalWithConf("", cfg, unmarshalConf); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}

	cfg.ApplyDefaults()

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return cfg, nil
}

func (c *Config) Validate() error {
	var issues []string

	issues = append(issues, validateUpstream(c)...)
	issues = append(issues, validateDownstreams(c)...)
	issues = append(issues, validateRA(c)...)
	issues = append(issues, validateNDP(c)...)
	issues = append(issues, validateDHCPv6(c)...)

	if len(issues) > 0 {
		return &ValidationError{Issues: issues}
	}

	return nil
}

// ApplyDefaults populates unset configuration fields with their defaults.
func (c *Config) ApplyDefaults() {
	if c.RA.Mode == "" {
		if len(c.Downstreams) > 0 {
			c.RA.Mode = modeRelay
		} else {
			c.RA.Mode = modeDisabled
		}
	}

	if c.NDP.Mode == "" {
		if len(c.Downstreams) > 0 {
			c.NDP.Mode = modeRelay
		} else {
			c.NDP.Mode = modeDisabled
		}
	}
}

func validateUpstream(cfg *Config) []string {
	var issues []string

	if cfg.Upstream.IfName == "" {
		issues = append(issues, "upstream.ifname is required")
	}

	if err := validateLinkLocal(cfg.Upstream.LinkLocal); err != nil {
		issues = append(issues, fmt.Sprintf("upstream.link_local: %v", err))
	}

	for hintIdx, hint := range cfg.Upstream.AddressHints {
		if err := validateIPAddress(hint); err != nil {
			issues = append(issues, fmt.Sprintf("upstream.address_hints[%d]: %v", hintIdx, err))
		}
	}

	return issues
}

func validateDownstreams(cfg *Config) []string {
	var issues []string

	seenDownstreams := map[string]struct{}{}

	for downstreamIdx, downstream := range cfg.Downstreams {
		if downstream.IfName == "" {
			issues = append(issues, fmt.Sprintf("downstreams[%d].ifname is required", downstreamIdx))

			continue
		}

		if err := validateLinkLocal(downstream.LinkLocal); err != nil {
			issues = append(issues, fmt.Sprintf("downstreams[%d].link_local: %v", downstreamIdx, err))
		}

		for hintIdx, hint := range downstream.AddressHints {
			if err := validateIPAddress(hint); err != nil {
				issues = append(issues, fmt.Sprintf("downstreams[%d].address_hints[%d]: %v", downstreamIdx, hintIdx, err))
			}
		}

		if downstream.IfName == cfg.Upstream.IfName {
			issues = append(
				issues,
				fmt.Sprintf("downstreams[%d] duplicates upstream interface %q", downstreamIdx, downstream.IfName),
			)
		}

		if _, ok := seenDownstreams[downstream.IfName]; ok {
			issues = append(issues, fmt.Sprintf("downstreams[%d] duplicate interface %q", downstreamIdx, downstream.IfName))
		}

		seenDownstreams[downstream.IfName] = struct{}{}
	}

	return issues
}

func validateRA(cfg *Config) []string {
	var issues []string

	switch cfg.RA.Mode {
	case "", modeRelay, modeDisabled:
	case modeServer:
		issues = append(issues, "ra.mode \"server\" is not supported")
	default:
		issues = append(issues, fmt.Sprintf("ra.mode %q is invalid", cfg.RA.Mode))
	}

	issues = append(issues, validateDNSSearch(cfg.RA.DNSSearchRewrite)...)
	issues = append(issues, validatePref64(cfg.RA.Pref64Rewrite)...)

	if cfg.RA.Mode != modeDisabled && len(cfg.Downstreams) == 0 {
		issues = append(issues, "router advertisements enabled but no downstream interfaces configured")
	}

	return issues
}

func validateNDP(cfg *Config) []string {
	var issues []string

	switch cfg.NDP.Mode {
	case "", modeRelay, modeDisabled:
	default:
		issues = append(issues, fmt.Sprintf("ndp.mode %q is invalid", cfg.NDP.Mode))
	}

	if cfg.NDP.TargetCacheTTL < 0 {
		issues = append(issues, "ndp.target_cache_ttl must be non-negative")
	}

	if cfg.NDP.Mode != modeDisabled && len(cfg.Downstreams) == 0 {
		issues = append(issues, "ndp enabled but no downstream interfaces configured")
	}

	return issues
}

func validateDHCPv6(cfg *Config) []string {
	var issues []string

	if err := validateRemoteID(cfg.DHCPv6.RemoteID); err != nil {
		issues = append(issues, fmt.Sprintf("dhcpv6.remote_id: %v", err))
	}

	for domainIdx, domain := range cfg.DHCPv6.OverrideDNSSearch {
		if err := validateDomainName(domain); err != nil {
			issues = append(issues, fmt.Sprintf("dhcpv6.override_domain_search[%d]: %v", domainIdx, err))
		}
	}

	return issues
}

func (c DHCPv6Config) InterfaceIDEnabled() bool {
	if c.InjectInterface == nil {
		return true
	}

	return *c.InjectInterface
}

func BoolPtr(v bool) *bool {
	return &v
}

func validateDNSSearch(domains []string) []string {
	var issues []string

	for domainIdx, domain := range domains {
		if err := validateDomainName(domain); err != nil {
			issues = append(issues, fmt.Sprintf("ra.dnssl_rewrite[%d]: %v", domainIdx, err))
		}
	}

	return issues
}

func validatePref64(values []string) []string {
	var issues []string

	for rewriteIdx, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			issues = append(issues, fmt.Sprintf("ra.pref64_rewrite[%d]: %v", rewriteIdx, err))

			continue
		}

		if !prefix.Addr().Is6() {
			issues = append(issues, fmt.Sprintf("ra.pref64_rewrite[%d]: prefix must be IPv6", rewriteIdx))

			continue
		}

		switch prefix.Bits() {
		case pref64Len32, pref64Len40, pref64Len48, pref64Len56, pref64Len64, pref64Len96:
		default:
			issues = append(issues, fmt.Sprintf(
				"ra.pref64_rewrite[%d]: prefix length %d not supported (must be %s)",
				rewriteIdx,
				prefix.Bits(),
				pref64SupportedLengths,
			))
		}
	}

	return issues
}

func validateDomainName(domain string) error {
	_, err := CanonicalDomain(domain)

	return err
}

func validateLinkLocal(value string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}

	addr, err := netip.ParseAddr(value)
	if err != nil {
		return fmt.Errorf("invalid address: %w", err)
	}

	if !addr.Is6() || !addr.IsLinkLocalUnicast() {
		return ErrAddressNotLinkLocal
	}

	return nil
}

func validateIPAddress(value string) error {
	if strings.TrimSpace(value) == "" {
		return ErrAddressEmpty
	}

	addr, err := netip.ParseAddr(value)
	if err != nil {
		return fmt.Errorf("invalid address: %w", err)
	}

	if !addr.Is6() {
		return ErrAddressNotIPv6
	}

	return nil
}

func validateRemoteID(cfg RemoteIDConfig) error {
	if cfg.Disabled {
		return nil
	}

	if cfg.Template == "" {
		return nil
	}

	if !strings.Contains(cfg.Template, "{ifname}") && !strings.Contains(cfg.Template, "{mac}") {
		return ErrTemplatePlaceholder
	}

	return nil
}

func canonicalizeDomain(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", ErrDomainEmpty
	}

	hasDot := strings.HasSuffix(trimmed, ".")

	if hasDot {
		trimmed = strings.TrimSuffix(trimmed, ".")
		if trimmed == "" {
			return "", ErrDomainMissingLabel
		}
	}

	profile := idna.New(
		idna.MapForLookup(),
		idna.Transitional(false),
		idna.StrictDomainName(true),
		idna.VerifyDNSLength(true),
	)

	ascii, err := profile.ToASCII(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid domain: %w", err)
	}

	if len(ascii) > maxDomainASCII {
		return "", ErrDomainTooLong
	}

	if hasDot {
		ascii += "."
	}

	return strings.ToLower(ascii), nil
}

// CanonicalDomain converts the provided domain to lowercase ASCII using IDNA rules.
func CanonicalDomain(value string) (string, error) {
	return canonicalizeDomain(value)
}
