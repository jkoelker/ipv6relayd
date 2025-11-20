package dhcpv6

import (
	"log/slog"
	"net"
	"strings"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/rfc1035label"

	"github.com/jkoelker/ipv6relayd/pkg/config"
	"github.com/jkoelker/ipv6relayd/pkg/netutil"
)

// RewriteReplyOptions applies DNS and DNSSL overrides if authentication is absent.
func (s *Service) RewriteReplyOptions(msg *dhcpv6.Message) bool {
	if msg == nil || !s.cfg.ForceReplyDNSRewrite || !s.hasDNSOverrides() {
		return false
	}

	if hasAuthenticationOption(msg) {
		if s.log != nil {
			s.log.Debug("skip dhcpv6 dns override due to authentication option")
		}

		return false
	}

	var changed bool

	if len(s.dnsOverride) > 0 {
		msg.Options.Update(dhcpv6.OptDNS(netutil.CloneSlice(s.dnsOverride)...))
		changed = true
	}

	if labels := cloneLabels(s.dnsslOverride); labels != nil && len(labels.Labels) > 0 {
		msg.Options.Update(dhcpv6.OptDomainSearchList(labels))
		changed = true
	}

	return changed
}

func hasAuthenticationOption(msg *dhcpv6.Message) bool {
	if msg == nil {
		return false
	}

	authOpts := msg.Options.Get(dhcpv6.OptionAuth)
	for _, opt := range authOpts {
		if opt == nil {
			continue
		}

		if len(opt.ToBytes()) > 0 {
			return true
		}
	}

	return false
}

func (s *Service) hasDNSOverrides() bool {
	return len(s.dnsOverride) > 0 || (s.dnsslOverride != nil && len(s.dnsslOverride.Labels) > 0)
}

func cloneLabels(src *rfc1035label.Labels) *rfc1035label.Labels {
	if src == nil || len(src.Labels) == 0 {
		return nil
	}

	return &rfc1035label.Labels{Labels: append([]string(nil), src.Labels...)}
}

func normalizeDNSOverride(entries []string, logger *slog.Logger) []net.IP {
	if len(entries) == 0 {
		return nil
	}

	result := make([]net.IP, 0, len(entries))
	for _, entry := range entries {
		value := strings.TrimSpace(entry)
		if value == "" {
			continue
		}

		parsedIP := net.ParseIP(value)
		if parsedIP == nil {
			if logger != nil {
				logger.Warn("ignoring invalid override_dns entry", "value", entry)
			}

			continue
		}

		ipv6Addr := parsedIP.To16()
		if ipv6Addr == nil || parsedIP.To4() != nil {
			if logger != nil {
				logger.Warn("ignoring non-ipv6 override_dns entry", "value", entry)
			}

			continue
		}

		result = append(result, netutil.CloneAddr(ipv6Addr))
	}

	if len(result) == 0 {
		return nil
	}

	return result
}

func buildDomainSearchLabels(domains []string, logger *slog.Logger) *rfc1035label.Labels {
	if len(domains) == 0 {
		return nil
	}

	labels := &rfc1035label.Labels{Labels: make([]string, 0, len(domains))}
	for _, domain := range domains {
		canonical, err := config.CanonicalDomain(domain)
		if err != nil {
			if logger != nil {
				logger.Warn("ignoring invalid override_domain_search entry", "value", domain, "err", err)
			}

			continue
		}

		canonical = strings.TrimSuffix(canonical, ".")
		if canonical == "" {
			if logger != nil {
				logger.Warn("ignoring empty override_domain_search entry", "value", domain)
			}

			continue
		}

		labels.Labels = append(labels.Labels, canonical)
	}

	if len(labels.Labels) == 0 {
		return nil
	}

	return labels
}

func (s *Service) remoteIDEnterprise() uint32 {
	return s.cfg.RemoteID.EnterpriseID
}

// GenerateRemoteIDPayload renders the remote-id option payload for the given interface.
func GenerateRemoteIDPayload(cfg config.RemoteIDConfig, iface *net.Interface) []byte {
	if cfg.Disabled {
		return nil
	}

	if cfg.Template == "" {
		return defaultRemoteIDPayload(iface)
	}

	name := ""
	if iface != nil {
		name = iface.Name
	}

	mac := ""
	if iface != nil && len(iface.HardwareAddr) > 0 {
		mac = strings.ToUpper(iface.HardwareAddr.String())
	}

	result := strings.ReplaceAll(cfg.Template, "{ifname}", name)
	result = strings.ReplaceAll(result, "{mac}", mac)

	return []byte(result)
}

func defaultRemoteIDPayload(iface *net.Interface) []byte {
	if iface == nil {
		return nil
	}

	if len(iface.HardwareAddr) == 0 {
		return []byte(iface.Name)
	}

	return []byte(iface.Name + "/" + strings.ToUpper(iface.HardwareAddr.String()))
}
