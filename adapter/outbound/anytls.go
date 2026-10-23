package outbound

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	N "github.com/ProjectClash/Clash/common/net"
	"github.com/ProjectClash/Clash/component/proxydialer"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/transport/anytls"
	"github.com/ProjectClash/Clash/transport/lxxhttp"
	"github.com/ProjectClash/Clash/transport/vmess"

	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/uot"
)

type AnyTLS struct {
	*Base
	clientMu    sync.Mutex
	client      *anytls.Client
	closed      bool
	buildClient func() *anytls.Client
	lxClient    *lxxhttp.Client
	option      *AnyTLSOption
}

var errOutboundClosed = errors.New("outbound is closed")

type AnyTLSOption struct {
	BasicOption
	Name                     string           `proxy:"name"`
	Server                   string           `proxy:"server"`
	Port                     int              `proxy:"port"`
	Password                 string           `proxy:"password"`
	ALPN                     []string         `proxy:"alpn,omitempty"`
	SNI                      string           `proxy:"sni,omitempty"`
	ECHOpts                  ECHOptions       `proxy:"ech-opts,omitempty"`
	ShadowTLSOpts            ShadowTLSOptions `proxy:"shadow-tls-opts,omitempty"`
	RestlsOpts               RestlsOptions    `proxy:"restls-opts,omitempty"`
	JLSOpts                  JLSOptions       `proxy:"jls-opts,omitempty"`
	ClientFingerprint        string           `proxy:"client-fingerprint,omitempty"`
	SkipCertVerify           bool             `proxy:"skip-cert-verify,omitempty"`
	NameCertVerify           string           `proxy:"name-cert-verify,omitempty"`
	Fingerprint              string           `proxy:"fingerprint,omitempty"`
	Certificate              string           `proxy:"certificate,omitempty"`
	PrivateKey               string           `proxy:"private-key,omitempty"`
	UDP                      bool             `proxy:"udp,omitempty"`
	ClientMetadata           string           `proxy:"client-metadata,omitempty"`
	IdleSessionCheckInterval int              `proxy:"idle-session-check-interval,omitempty"`
	IdleSessionTimeout       int              `proxy:"idle-session-timeout,omitempty"`
	MinIdleSession           int              `proxy:"min-idle-session,omitempty"`
	DisableReuse             bool             `proxy:"disable-reuse,omitempty"`
	// LightXtreme / 闪连: anytls 承载在私有 lx-xhttp 传输之上
	Transport LXHTTPOptions `proxy:"transport,omitempty"`

	// 兼容把传输参数平铺在节点上的写法（type: lightxtreme 常见）
	FlatObfsKey    string `proxy:"obfs-key,omitempty"`
	FlatPath       string `proxy:"path,omitempty"`
	FlatMode       string `proxy:"mode,omitempty"`
	FlatPaddingMin int    `proxy:"padding-min,omitempty"`
	FlatPaddingMax int    `proxy:"padding-max,omitempty"`
	FlatDownload   string `proxy:"download,omitempty"`
	FlatDownloadPath string `proxy:"download-path,omitempty"`
	FlatDownloadPort int    `proxy:"download-port,omitempty"`
}

// LXHTTPOptions 闪连私有 XHTTP 传输配置。
type LXHTTPOptions struct {
	Type       string                `proxy:"type,omitempty"`
	Path       string                `proxy:"path,omitempty"`
	Mode       string                `proxy:"mode,omitempty"`
	ObfsKey    string                `proxy:"obfs-key,omitempty"`
	PaddingMin int                   `proxy:"padding-min,omitempty"`
	PaddingMax int                   `proxy:"padding-max,omitempty"`
	Download   LXHTTPDownloadOptions `proxy:"download,omitempty"`
}

type LXHTTPDownloadOptions struct {
	Server string `proxy:"server,omitempty"`
	Port   int    `proxy:"port,omitempty"`
	Path   string `proxy:"path,omitempty"`
}

func (o LXHTTPOptions) Enabled() bool {
	switch strings.ToLower(strings.TrimSpace(o.Type)) {
	case "lx-xhttp", "xhttp", "lightxtreme", "闪电旋风劈":
		return true
	}
	return false
}

func (t *AnyTLS) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	client, err := t.lazyClient()
	if err != nil {
		return nil, err
	}
	c, err := client.CreateProxy(ctx, M.ParseSocksaddrHostPort(metadata.String(), metadata.DstPort))
	if err != nil {
		return nil, err
	}
	return NewConn(c, t), nil
}

func (t *AnyTLS) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = t.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}

	// create tcp
	client, err := t.lazyClient()
	if err != nil {
		return nil, err
	}
	c, err := client.CreateProxy(ctx, uot.RequestDestination(2))
	if err != nil {
		return nil, err
	}

	// create uot on tcp
	destination := M.SocksaddrFromNet(metadata.UDPAddr())
	return NewPacketConn(N.NewThreadSafePacketConn(uot.NewLazyConn(c, uot.Request{Destination: destination})), t), nil
}

// SupportUOT implements C.ProxyAdapter
func (t *AnyTLS) SupportUOT() bool {
	return true
}

// ProxyInfo implements C.ProxyAdapter
func (t *AnyTLS) ProxyInfo() C.ProxyInfo {
	info := t.Base.ProxyInfo()
	info.DialerProxy = t.option.DialerProxy
	return info
}

// Close implements C.ProxyAdapter
func (t *AnyTLS) Close() error {
	t.clientMu.Lock()
	defer t.clientMu.Unlock()
	t.closed = true
	if t.lxClient != nil {
		_ = t.lxClient.Close()
	}
	if t.client == nil {
		return nil
	}
	client := t.client
	t.client = nil
	return client.Close()
}

func NewAnyTLS(option AnyTLSOption) (*AnyTLS, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	outbound := &AnyTLS{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.AnyTLS,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: &option,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	singDialer := proxydialer.NewSingDialer(outbound.dialer)

	tOption := anytls.ClientConfig{
		Password:                 option.Password,
		Server:                   M.ParseSocksaddrHostPort(option.Server, uint16(option.Port)),
		Dialer:                   singDialer,
		ClientMetadata:           option.ClientMetadata,
		IdleSessionCheckInterval: time.Duration(option.IdleSessionCheckInterval) * time.Second,
		IdleSessionTimeout:       time.Duration(option.IdleSessionTimeout) * time.Second,
		MinIdleSession:           option.MinIdleSession,
		DisableReuse:             option.DisableReuse,
	}
	echConfig, err := option.ECHOpts.Parse()
	if err != nil {
		return nil, err
	}
	shadowTLSConfig, err := option.ShadowTLSOpts.Parse()
	if err != nil {
		return nil, err
	}
	restlsConfig, err := option.RestlsOpts.Parse(option.SNI, option.ClientFingerprint)
	if err != nil {
		return nil, err
	}
	jlsConfig, err := option.JLSOpts.Parse()
	if err != nil {
		return nil, err
	}
	securityModes := make([]string, 0, 3)
	if shadowTLSConfig != nil {
		securityModes = append(securityModes, "ShadowTLS")
	}
	if restlsConfig != nil {
		securityModes = append(securityModes, "Restls")
	}
	if jlsConfig != nil {
		securityModes = append(securityModes, "JLS")
	}
	if len(securityModes) > 1 {
		return nil, errors.New("security modes are mutually exclusive: " + strings.Join(securityModes, ", "))
	}
	tlsConfig := &vmess.TLSConfig{
		Host:              option.SNI,
		SkipCertVerify:    option.SkipCertVerify,
		NameCertVerify:    option.NameCertVerify,
		NextProtos:        option.ALPN,
		FingerPrint:       option.Fingerprint,
		Certificate:       option.Certificate,
		PrivateKey:        option.PrivateKey,
		ClientFingerprint: option.ClientFingerprint,
		ECH:               echConfig,
		ShadowTLS:         shadowTLSConfig,
		Restls:            restlsConfig,
		JLS:               jlsConfig,
	}
	if tlsConfig.Host == "" {
		tlsConfig.Host = option.Server
	}
	tOption.TLSConfig = tlsConfig

	// 平铺写法归一化进 Transport
	if option.Transport.Type == "" &&
		(option.FlatObfsKey != "" || option.FlatPath != "" || option.FlatDownload != "") {
		option.Transport.Type = "lx-xhttp"
	}
	if option.Transport.ObfsKey == "" {
		option.Transport.ObfsKey = option.FlatObfsKey
	}
	if option.Transport.Path == "" {
		option.Transport.Path = option.FlatPath
	}
	if option.Transport.Mode == "" {
		option.Transport.Mode = option.FlatMode
	}
	if option.Transport.PaddingMin == 0 {
		option.Transport.PaddingMin = option.FlatPaddingMin
	}
	if option.Transport.PaddingMax == 0 {
		option.Transport.PaddingMax = option.FlatPaddingMax
	}
	if option.Transport.Download.Server == "" && option.FlatDownload != "" {
		option.Transport.Download.Server = option.FlatDownload
		option.Transport.Download.Path = option.FlatDownloadPath
		option.Transport.Download.Port = option.FlatDownloadPort
	}

	// LightXtreme / 闪连: anytls 承载在私有 lx-xhttp 传输之上
	if option.Transport.Enabled() {
		lxConfig := lxxhttp.Config{
			Dialer:     outbound.dialer,
			Server:     addr,
			Path:       option.Transport.Path,
			ObfsKey:    option.Transport.ObfsKey,
			PaddingMin: option.Transport.PaddingMin,
			PaddingMax: option.Transport.PaddingMax,
			TLSConfig:  tlsConfig,
		}
		if download := option.Transport.Download; download.Server != "" {
			downloadPort := download.Port
			if downloadPort == 0 {
				downloadPort = option.Port
			}
			lxConfig.DownloadServer = net.JoinHostPort(download.Server, strconv.Itoa(downloadPort))
			lxConfig.DownloadPath = download.Path
		}
		lxClient, err := lxxhttp.NewClient(lxConfig)
		if err != nil {
			return nil, err
		}
		outbound.lxClient = lxClient
		tOption.Dial = lxClient.DialContext
	}

	outbound.buildClient = func() *anytls.Client {
		return anytls.NewClient(context.TODO(), tOption)
	}

	return outbound, nil
}

func (t *AnyTLS) lazyClient() (*anytls.Client, error) {
	t.clientMu.Lock()
	defer t.clientMu.Unlock()
	if t.closed {
		return nil, errOutboundClosed
	}
	if t.client == nil {
		t.client = t.buildClient()
	}
	return t.client, nil
}

func (t *AnyTLS) clientBuilt() bool {
	t.clientMu.Lock()
	defer t.clientMu.Unlock()
	return t.client != nil
}
