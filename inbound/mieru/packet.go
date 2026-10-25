package mieru

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// packetConn carries the datagrams of a UDP ASSOCIATE session over its stream.
// A frame on the wire is 0x00, the length (2 bytes, big endian), the datagram
// and 0xff; the datagram is a socks5 UDP packet: three zero bytes, the
// address and port, and the payload.
type packetConn struct {
	net.Conn
	wmu sync.Mutex
}

var _ N.PacketConn = (*packetConn)(nil)

func newPacketConn(conn net.Conn) *packetConn { return &packetConn{Conn: conn} }

const maxFrame = 65535

func (c *packetConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	for {
		var head [3]byte
		if _, err := io.ReadFull(c.Conn, head[:]); err != nil {
			return M.Socksaddr{}, err
		}
		if head[0] != 0x00 {
			return M.Socksaddr{}, E.New("bad packet prefix ", head[0])
		}
		size := int(binary.BigEndian.Uint16(head[1:]))
		if size > buffer.FreeLen()-1 {
			// Too large for the caller's buffer: drop the datagram, keep the stream.
			if _, err := io.CopyN(io.Discard, c.Conn, int64(size)+1); err != nil {
				return M.Socksaddr{}, err
			}

			continue
		}
		start := buffer.Len()
		if _, err := buffer.ReadFullFrom(c.Conn, size+1); err != nil {
			return M.Socksaddr{}, err
		}
		data := buffer.Bytes()[start:]
		if data[size] != 0xff {
			return M.Socksaddr{}, E.New("bad packet suffix")
		}
		buffer.Truncate(start + size)
		data = data[:size]
		if size < 4 || data[0] != 0 || data[1] != 0 || data[2] != 0 {
			return M.Socksaddr{}, E.New("bad udp header")
		}
		r := bytes.NewReader(data[3:])
		destination, err := M.SocksaddrSerializer.ReadAddrPort(r)
		if err != nil {
			return M.Socksaddr{}, err
		}
		header := size - r.Len()
		if start != 0 {
			return M.Socksaddr{}, E.New("packet buffer is not empty")
		}
		buffer.Advance(header)

		return destination.Unwrap(), nil
	}
}

func (c *packetConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	payload := buffer.Bytes()
	size := 3 + M.SocksaddrSerializer.AddrPortLen(destination) + len(payload)
	if size > maxFrame {
		return E.New("packet of ", size, " bytes does not fit a frame")
	}
	frame := buf.NewSize(size + 4)
	defer frame.Release()
	_ = frame.WriteByte(0x00)
	common16(frame, uint16(size))
	_, _ = frame.Write([]byte{0, 0, 0})
	if err := M.SocksaddrSerializer.WriteAddrPort(frame, destination); err != nil {
		return err
	}
	_, _ = frame.Write(payload)
	_ = frame.WriteByte(0xff)
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, err := c.Conn.Write(frame.Bytes())

	return err
}

func common16(b *buf.Buffer, v uint16) {
	var x [2]byte
	binary.BigEndian.PutUint16(x[:], v)
	_, _ = b.Write(x[:])
}
