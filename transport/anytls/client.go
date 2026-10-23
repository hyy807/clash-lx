package anytls

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"sync/atomic"
	"time"

	"github.com/ProjectClash/Clash/common/buf"
	"github.com/ProjectClash/Clash/transport/anytls/padding"
	"github.com/ProjectClash/Clash/transport/anytls/session"
	"github.com/ProjectClash/Clash/transport/vmess"

	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

type ClientConfig struct {
	Password                 string
	ClientMetadata           string
	IdleSessionCheckInterval time.Duration
	IdleSessionTimeout       time.Duration
	MinIdleSession           int
	DisableReuse             bool
	Server                   M.Socksaddr
	Dialer                   N.Dialer
	TLSConfig                *vmess.TLSConfig
	// Dial 非空时底层流由外部传输提供（LightXtreme lx-xhttp），anytls 不再自建 TLS。
	Dial func(ctx context.Context) (net.Conn, error)
}

type Client struct {
	passwordSha256 []byte
	tlsConfig      *vmess.TLSConfig
	dialer         N.Dialer
	dial           func(ctx context.Context) (net.Conn, error)
	server         M.Socksaddr
	sessionClient  *session.Client
	padding        atomic.Pointer[padding.PaddingFactory]
}

func NewClient(ctx context.Context, config ClientConfig) *Client {
	pw := sha256.Sum256([]byte(config.Password))
	// LightXtreme / 闪连: 32 位 hex 口令走私有时间掩码变换
	if lxPW, ok := lxPasswordSHA256(config.Password); ok {
		pw = lxPW
	}
	c := &Client{
		passwordSha256: pw[:],
		tlsConfig:      config.TLSConfig,
		dialer:         config.Dialer,
		dial:           config.Dial,
		server:         config.Server,
	}
	// Initialize the padding state of this client
	padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &c.padding)
	c.sessionClient = session.NewClient(ctx, c.createOutboundTLSConnection, &c.padding, config.ClientMetadata, config.IdleSessionCheckInterval, config.IdleSessionTimeout, config.MinIdleSession, config.DisableReuse)
	return c
}

func (c *Client) CreateProxy(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	conn, err := c.sessionClient.CreateStream(ctx)
	if err != nil {
		return nil, err
	}
	err = M.SocksaddrSerializer.WriteAddrPort(conn, destination)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (c *Client) createOutboundTLSConnection(ctx context.Context) (net.Conn, error) {
	var conn net.Conn
	var err error
	if c.dial != nil {
		// 外部传输（LightXtreme lx-xhttp）已完成 TLS，直接给出流
		conn, err = c.dial(ctx)
		if err != nil {
			return nil, err
		}
	} else {
		conn, err = c.dialer.DialContext(ctx, N.NetworkTCP, c.server)
		if err != nil {
			return nil, err
		}
	}

	b := buf.NewPacket()
	defer b.Release()

	b.Write(c.passwordSha256)
	var paddingLen int
	if pad := c.padding.Load().GenerateRecordPayloadSizes(0); len(pad) > 0 {
		paddingLen = pad[0]
	}
	binary.BigEndian.PutUint16(b.Extend(2), uint16(paddingLen))
	if paddingLen > 0 {
		b.WriteZeroN(paddingLen)
	}

	tlsConn := conn
	if c.dial == nil {
		var tlsErr error
		tlsConn, tlsErr = vmess.StreamTLSConn(ctx, conn, c.tlsConfig)
		if tlsErr != nil {
			conn.Close()
			return nil, tlsErr
		}
	}

	_, err = b.WriteTo(tlsConn)
	if err != nil {
		tlsConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func (h *Client) Close() error {
	return h.sessionClient.Close()
}
