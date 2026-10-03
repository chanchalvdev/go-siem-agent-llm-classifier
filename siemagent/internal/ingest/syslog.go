// Package ingest receives logs from network senders (rsyslog, syslog-ng,
// network devices) so they no longer have to be posted to the HTTP API.
package ingest

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
)

const (
	// maxMessage bounds a single syslog message (UDP datagram or TCP line).
	maxMessage = 64 * 1024
	// maxTCPConns bounds concurrent TCP senders so a flood of idle
	// connections cannot exhaust file descriptors.
	maxTCPConns = 256
)

// Handler receives one log line. transport is "udp" or "tcp". It must not
// block for long: it runs on the listener's read path.
type Handler func(transport, line string)

// SyslogListener accepts RFC 3164 / RFC 5424 messages over UDP (one message
// per datagram) and TCP (newline-delimited, the rsyslog/syslog-ng default;
// octet-counted framing is not supported).
type SyslogListener struct {
	udp    net.PacketConn
	tcp    net.Listener
	handle Handler
	wg     sync.WaitGroup
}

// ListenSyslog binds the given addresses (either may be empty to disable that
// transport) and serves until ctx is cancelled.
func ListenSyslog(ctx context.Context, udpAddr, tcpAddr string, handle Handler) (*SyslogListener, error) {
	if udpAddr == "" && tcpAddr == "" {
		return nil, errors.New("no syslog address configured")
	}
	l := &SyslogListener{handle: handle}

	var lc net.ListenConfig
	if udpAddr != "" {
		pc, err := lc.ListenPacket(ctx, "udp", udpAddr)
		if err != nil {
			return nil, fmt.Errorf("syslog udp listen %s: %w", udpAddr, err)
		}
		l.udp = pc
	}
	if tcpAddr != "" {
		ln, err := lc.Listen(ctx, "tcp", tcpAddr)
		if err != nil {
			if l.udp != nil {
				_ = l.udp.Close()
			}
			return nil, fmt.Errorf("syslog tcp listen %s: %w", tcpAddr, err)
		}
		l.tcp = ln
	}

	if l.udp != nil {
		l.wg.Add(1)
		go l.serveUDP()
	}
	if l.tcp != nil {
		l.wg.Add(1)
		go l.serveTCP(ctx)
	}

	// Closing the sockets unblocks the read/accept loops on shutdown.
	context.AfterFunc(ctx, l.closeSockets)
	return l, nil
}

// UDPAddr returns the bound UDP address, or nil when UDP is disabled.
func (l *SyslogListener) UDPAddr() net.Addr {
	if l.udp == nil {
		return nil
	}
	return l.udp.LocalAddr()
}

// TCPAddr returns the bound TCP address, or nil when TCP is disabled.
func (l *SyslogListener) TCPAddr() net.Addr {
	if l.tcp == nil {
		return nil
	}
	return l.tcp.Addr()
}

// Wait blocks until every listener goroutine has exited after cancellation.
func (l *SyslogListener) Wait() { l.wg.Wait() }

func (l *SyslogListener) closeSockets() {
	if l.udp != nil {
		_ = l.udp.Close()
	}
	if l.tcp != nil {
		_ = l.tcp.Close()
	}
}

func (l *SyslogListener) serveUDP() {
	defer l.wg.Done()
	buf := make([]byte, maxMessage)
	for {
		n, _, err := l.udp.ReadFrom(buf)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				slog.Error("syslog udp read failed", "component", "ingest", "error", err)
			}
			return
		}
		// Some senders batch several newline-separated messages per datagram.
		for _, line := range strings.Split(string(buf[:n]), "\n") {
			l.emit("udp", line)
		}
	}
}

func (l *SyslogListener) serveTCP(ctx context.Context) {
	defer l.wg.Done()
	slots := make(chan struct{}, maxTCPConns)
	for {
		conn, err := l.tcp.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				slog.Error("syslog tcp accept failed", "component", "ingest", "error", err)
			}
			return
		}
		select {
		case slots <- struct{}{}:
		default:
			slog.Warn("syslog tcp connection limit reached", "component", "ingest", "limit", maxTCPConns)
			_ = conn.Close()
			continue
		}
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			defer func() { <-slots }()
			l.serveConn(ctx, conn)
		}()
	}
}

func (l *SyslogListener) serveConn(ctx context.Context, conn net.Conn) {
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	defer func() { _ = conn.Close() }()

	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 4096), maxMessage)
	for sc.Scan() {
		l.emit("tcp", sc.Text())
	}
	if err := sc.Err(); err != nil && !errors.Is(err, net.ErrClosed) {
		slog.Warn("syslog tcp connection closed", "component", "ingest", "error", err)
	}
}

func (l *SyslogListener) emit(transport, line string) {
	line = strings.TrimRight(line, "\r\x00 ")
	if strings.TrimSpace(line) != "" {
		l.handle(transport, line)
	}
}
