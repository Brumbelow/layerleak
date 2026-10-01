package registry

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const (
	// defaultDialTimeout bounds one connection attempt (all validated addresses
	// of a host share it) when no request timeout is configured.
	defaultDialTimeout = 30 * time.Second
	// defaultResponseHeaderTimeout bounds the time to the first response byte
	// when no request timeout is configured; blob bodies stay bounded by the
	// caller's context.
	defaultResponseHeaderTimeout = 30 * time.Second
	// defaultTLSHandshakeTimeout mirrors http.DefaultTransport.
	defaultTLSHandshakeTimeout = 10 * time.Second
)

// pinnedTransport is the single long-lived hardened transport of a Client. It
// resolves and policy-checks every destination once per request and pins the
// dial to those validated addresses from DialContext, so the hostname stays in
// the URL (connection reuse, TLS ServerName and proxy CONNECT targets all key
// on it) while the connection can only go to an address that passed the
// policy. When the configured proxy function selects a proxy, the proxy is the
// egress control: the request keeps its hostname, local resolution is skipped
// and only the proxy itself may be dialed.
type pinnedTransport struct {
	base        *http.Transport
	client      *Client
	dial        func(ctx context.Context, network, address string) (net.Conn, error)
	dialTimeout time.Duration
}

type dialPolicyKey struct{}

// dialPolicy is attached to the request context so DialContext knows which
// destinations the round trip validated. Exactly one of pin or proxy is set.
type dialPolicy struct {
	pin   *pinnedAddresses
	proxy string
}

type pinnedAddresses struct {
	host      string
	port      string
	addresses []net.IPAddr
}

// hardenHTTPClient replaces the configured transport with the pinned
// transport. It fails for transports that cannot be hardened: a RoundTripper
// that is not an *http.Transport (allowed only with the AllowPrivateHosts test
// override) or one that skips TLS verification.
func (c *Client) hardenHTTPClient() error {
	if c.httpClient == nil || c.allowPrivateHosts {
		return nil
	}
	client := *c.httpClient
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	base, ok := transport.(*http.Transport)
	if !ok {
		return fmt.Errorf("custom registry transport requires explicit AllowPrivateHosts test override")
	}
	if base.TLSClientConfig != nil && base.TLSClientConfig.InsecureSkipVerify {
		return fmt.Errorf("registry transport must verify TLS certificates")
	}
	hardened := base.Clone()
	if hardened.TLSClientConfig == nil {
		hardened.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else if hardened.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		hardened.TLSClientConfig.MinVersion = tls.VersionTLS12
	}
	if hardened.MaxResponseHeaderBytes <= 0 || hardened.MaxResponseHeaderBytes > maxRegistryResponseHeaderBytes {
		hardened.MaxResponseHeaderBytes = maxRegistryResponseHeaderBytes
	}

	pinned := &pinnedTransport{
		base:        hardened,
		client:      c,
		dialTimeout: boundedTimeout(0, defaultDialTimeout, c.requestTimeout),
	}
	rawDial := base.DialContext
	if rawDial == nil {
		rawDial = (&net.Dialer{Timeout: pinned.dialTimeout, KeepAlive: 30 * time.Second}).DialContext
	}
	pinned.dial = rawDial
	hardened.DialContext = pinned.dialContext
	hardened.DialTLS = nil //nolint:staticcheck // clear the deprecated hook so the pinned dialer and TLSClientConfig are authoritative
	hardened.DialTLSContext = nil
	hardened.TLSHandshakeTimeout = boundedTimeout(base.TLSHandshakeTimeout, defaultTLSHandshakeTimeout, c.requestTimeout)
	hardened.ResponseHeaderTimeout = boundedTimeout(base.ResponseHeaderTimeout, defaultResponseHeaderTimeout, c.requestTimeout)

	client.Transport = pinned
	c.httpClient = &client
	return nil
}

// boundedTimeout returns the configured transport timeout (or the fallback when
// unset), never longer than the request timeout when one is configured.
func boundedTimeout(configured, fallback, requestTimeout time.Duration) time.Duration {
	value := configured
	if value <= 0 {
		value = fallback
	}
	if requestTimeout > 0 && requestTimeout < value {
		value = requestTimeout
	}
	return value
}

func (t *pinnedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	ctx := request.Context()
	kind := requestKindFromContext(ctx)
	policy := &dialPolicy{}

	proxyURL, err := t.proxyFor(request)
	if err != nil {
		return nil, fmt.Errorf("select %s proxy: %w", kind, err)
	}
	if proxyURL != nil {
		// The proxy resolves and reaches the destination; the hostname stays in
		// the URL so hostname-policy proxies see `CONNECT host:port`. Scheme and
		// allowlist checks already ran in validateOutboundURL; address literals
		// are still classified here because they need no resolution.
		if err := t.client.checkLiteralAddress(request.URL, kind); err != nil {
			return nil, err
		}
		policy.proxy = proxyHostPort(proxyURL)
	} else {
		addresses, err := t.client.resolveOutbound(ctx, request.URL, kind)
		if err != nil {
			return nil, err
		}
		if len(addresses) == 0 {
			return nil, fmt.Errorf("%s host %s did not resolve", kind, request.URL.Hostname())
		}
		policy.pin = &pinnedAddresses{
			host:      canonicalHostname(request.URL.Hostname()),
			port:      effectivePort(request.URL),
			addresses: addresses,
		}
	}

	pinnedRequest := request.WithContext(context.WithValue(ctx, dialPolicyKey{}, policy))
	response, err := t.base.RoundTrip(pinnedRequest)
	if response != nil {
		response.Request = request
	}
	return response, err
}

func (t *pinnedTransport) proxyFor(request *http.Request) (*url.URL, error) {
	if t.base.Proxy == nil {
		return nil, nil
	}
	return t.base.Proxy(request)
}

// dialContext is the hardened transport's DialContext. It refuses any dial the
// round trip did not validate and tries the validated addresses in order,
// sharing the dial budget between them so a dead first record (commonly IPv6)
// still leaves time for the next one.
func (t *pinnedTransport) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	policy, _ := ctx.Value(dialPolicyKey{}).(*dialPolicy)
	if policy == nil {
		return nil, fmt.Errorf("registry transport refused an unpinned dial")
	}
	if policy.pin == nil {
		if policy.proxy == "" || !strings.EqualFold(address, policy.proxy) {
			return nil, fmt.Errorf("registry transport refused a dial outside the selected proxy")
		}
		dialCtx, cancel := context.WithTimeout(ctx, t.dialTimeout)
		defer cancel()
		return t.dial(dialCtx, network, address)
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil || canonicalHostname(host) != policy.pin.host || port != policy.pin.port {
		return nil, fmt.Errorf("registry transport refused a dial outside the pinned host")
	}

	deadline := time.Now().Add(t.dialTimeout)
	errs := make([]error, 0, len(policy.pin.addresses))
	for index, candidate := range policy.pin.addresses {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			errs = append(errs, context.DeadlineExceeded)
			break
		}
		budget := remaining / time.Duration(len(policy.pin.addresses)-index)
		dialCtx, cancel := context.WithTimeout(ctx, budget)
		conn, err := t.dial(dialCtx, network, net.JoinHostPort(ipString(candidate), port))
		cancel()
		if err == nil {
			return conn, nil
		}
		errs = append(errs, err)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.Join(errs...)
}

func ipString(address net.IPAddr) string {
	value := address.IP.String()
	if address.Zone != "" {
		value += "%" + address.Zone
	}
	return value
}

func canonicalHostname(host string) string {
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

// proxyHostPort mirrors net/http's canonical proxy address: host plus the
// explicit port or the scheme default.
func proxyHostPort(proxyURL *url.URL) string {
	port := proxyURL.Port()
	if port == "" {
		switch strings.ToLower(proxyURL.Scheme) {
		case "https":
			port = "443"
		case "socks5", "socks5h":
			port = "1080"
		default:
			port = "80"
		}
	}
	return net.JoinHostPort(canonicalHostname(proxyURL.Hostname()), port)
}

func sameURLHost(left, right *url.URL) bool {
	return strings.EqualFold(left.Hostname(), right.Hostname()) && effectivePort(left) == effectivePort(right)
}

func effectivePort(value *url.URL) string {
	if value.Port() != "" {
		return value.Port()
	}
	if value.Scheme == "https" {
		return "443"
	}
	if value.Scheme == "http" {
		return "80"
	}
	return ""
}

var nonPublicAddressPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2001:2::/48"),
	netip.MustParsePrefix("2001:10::/28"),
	netip.MustParsePrefix("2001:20::/28"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("fec0::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func isNonPublicAddress(value net.IP) bool {
	address, ok := netip.AddrFromSlice(value)
	if !ok {
		return true
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() {
		return true
	}
	for _, prefix := range nonPublicAddressPrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
