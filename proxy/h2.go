package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fa33az/polysmuggler/mutator"
	"golang.org/x/net/http2/hpack"
)

type H2Frame struct {
	Length   uint32
	Type     byte
	Flags    byte
	StreamID uint32
	Payload  []byte
}

func writeFrame(w io.Writer, f H2Frame) error {
	buf := make([]byte, 9+f.Length)
	buf[0] = byte(f.Length >> 16)
	buf[1] = byte(f.Length >> 8)
	buf[2] = byte(f.Length)
	buf[3] = f.Type
	buf[4] = f.Flags
	buf[5] = byte(f.StreamID >> 24)
	buf[6] = byte(f.StreamID >> 16)
	buf[7] = byte(f.StreamID >> 8)
	buf[8] = byte(f.StreamID)
	copy(buf[9:], f.Payload)
	_, err := w.Write(buf)
	return err
}

func readFrame(r io.Reader) (H2Frame, error) {
	header := make([]byte, 9)
	_, err := io.ReadFull(r, header)
	if err != nil {
		return H2Frame{}, err
	}
	length := uint32(header[0])<<16 | uint32(header[1])<<8 | uint32(header[2])
	fType := header[3]
	flags := header[4]
	streamID := uint32(header[5]&0x7f)<<24 | uint32(header[6])<<16 | uint32(header[7])<<8 | uint32(header[8])

	payload := make([]byte, length)
	_, err = io.ReadFull(r, payload)
	if err != nil {
		return H2Frame{}, err
	}

	return H2Frame{
		Length:   length,
		Type:     fType,
		Flags:    flags,
		StreamID: streamID,
		Payload:  payload,
	}, nil
}

func encodeLiteral(name, value string) []byte {
	var buf bytes.Buffer
	buf.WriteByte(0x00) // Literal without indexing, index=0
	writeString(&buf, name)
	writeString(&buf, value)
	return buf.Bytes()
}

func writeString(buf *bytes.Buffer, s string) {
	writeVarInt(buf, len(s), 7)
	buf.WriteString(s)
}

func writeVarInt(buf *bytes.Buffer, val int, prefixLen uint) {
	mask := (1 << prefixLen) - 1
	if val < mask {
		buf.WriteByte(byte(val))
		return
	}
	buf.WriteByte(byte(mask))
	val -= mask
	for val >= 128 {
		buf.WriteByte(byte(val&127 | 128))
		val >>= 7
	}
	buf.WriteByte(byte(val))
}

func ForwardH2Request(w io.Writer, r io.Reader, req *http.Request, body []byte, targetURL *url.URL, mut *mutator.Mutator) (int, []byte, map[string]string, error) {
	// 1. Send Connection Preface
	_, err := w.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	if err != nil {
		return 0, nil, nil, fmt.Errorf("failed to send h2 preface: %w", err)
	}

	// 2. Send Empty SETTINGS Frame
	err = writeFrame(w, H2Frame{
		Length:   0,
		Type:     0x4, // SETTINGS
		Flags:    0x0,
		StreamID: 0,
		Payload:  nil,
	})
	if err != nil {
		return 0, nil, nil, fmt.Errorf("failed to send h2 settings: %w", err)
	}

	// 3. Build HTTP/2 Header Block
	var headerBlock bytes.Buffer

	// Pseudo-headers first (with case mutation if enabled)
	methodKey := ":method"
	pathKey := ":path"
	schemeKey := ":scheme"
	authorityKey := ":authority"

	if mut.Strat.HeaderCase {
		methodKey = ":Method"
		pathKey = ":Path"
		schemeKey = ":Scheme"
		authorityKey = ":Authority"
	}

	path := targetURL.Path
	if targetURL.RawQuery != "" {
		mutatedQuery := mut.TranslateUnicode(targetURL.RawQuery)
		path += "?" + mutatedQuery
	} else if mut.Strat.UnicodeHomoglyph {
		path = mut.TranslateUnicode(path)
	}
	if path == "" {
		path = "/"
	}

	headerBlock.Write(encodeLiteral(methodKey, req.Method))
	headerBlock.Write(encodeLiteral(pathKey, path))
	headerBlock.Write(encodeLiteral(schemeKey, targetURL.Scheme))
	headerBlock.Write(encodeLiteral(authorityKey, targetURL.Host))

	// Standard headers
	for k, vv := range req.Header {
		for _, v := range vv {
			kl := strings.ToLower(k)
			// Skip HTTP/1-specific connection headers in HTTP/2
			if kl == "connection" || kl == "keep-alive" || kl == "proxy-connection" || kl == "transfer-encoding" || kl == "upgrade" {
				continue
			}
			mutatedKey := mut.RandomCase(k)
			headerBlock.Write(encodeLiteral(mutatedKey, v))
		}
	}

	// 4. Send HEADERS Frame
	var headersFlags byte = 0x4 // END_HEADERS
	if len(body) == 0 {
		headersFlags |= 0x1 // END_STREAM
	}

	err = writeFrame(w, H2Frame{
		Length:   uint32(headerBlock.Len()),
		Type:     0x1, // HEADERS
		Flags:    headersFlags,
		StreamID: 1,
		Payload:  headerBlock.Bytes(),
	})
	if err != nil {
		return 0, nil, nil, fmt.Errorf("failed to send h2 headers: %w", err)
	}

	// 5. Send DATA Frame if body exists
	if len(body) > 0 {
		err = writeFrame(w, H2Frame{
			Length:   uint32(len(body)),
			Type:     0x0, // DATA
			Flags:    0x1, // END_STREAM
			StreamID: 1,
			Payload:  body,
		})
		if err != nil {
			return 0, nil, nil, fmt.Errorf("failed to send h2 data: %w", err)
		}
	}

	// 6. Read Response Frames
	var statusCode int
	var respBody bytes.Buffer
	respHeaders := make(map[string]string)
	endOfStream := false

	// Set a deadline for response reading to prevent hanging
	if conn, ok := w.(interface{ SetReadDeadline(time.Time) error }); ok {
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	}

	for !endOfStream {
		frame, err := readFrame(r)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return 0, nil, nil, fmt.Errorf("error reading h2 frame: %w", err)
		}

		switch frame.Type {
		case 0x0: // DATA
			if frame.StreamID == 1 {
				respBody.Write(frame.Payload)
				if (frame.Flags & 0x1) != 0 { // END_STREAM
					endOfStream = true
				}
			}
		case 0x1: // HEADERS
			if frame.StreamID == 1 {
				dec := hpack.NewDecoder(4096, func(f hpack.HeaderField) {
					respHeaders[f.Name] = f.Value
				})
				_, err = dec.Write(frame.Payload)
				if err != nil {
					return 0, nil, nil, fmt.Errorf("failed to decode response headers: %w", err)
				}

				if (frame.Flags & 0x1) != 0 { // END_STREAM
					endOfStream = true
				}
			}
		case 0x4: // SETTINGS
			if (frame.Flags & 0x1) == 0 { // Not ACK
				// Send SETTINGS ACK back
				writeFrame(w, H2Frame{
					Length:   0,
					Type:     0x4,
					Flags:    0x1, // ACK
					StreamID: 0,
					Payload:  nil,
				})
			}
		case 0x3: // RST_STREAM
			return 0, nil, nil, fmt.Errorf("stream reset by target: stream_id=%d error_code=%d", frame.StreamID, binaryBigEndian(frame.Payload))
		case 0x7: // GOAWAY
			return 0, nil, nil, fmt.Errorf("goaway received from target: error_code=%d", binaryBigEndian(frame.Payload[4:8]))
		}
	}

	// Extract status
	if statusVal, ok := respHeaders[":status"]; ok {
		fmt.Sscanf(statusVal, "%d", &statusCode)
	} else {
		statusCode = 200 // Fallback
	}

	return statusCode, respBody.Bytes(), respHeaders, nil
}

func binaryBigEndian(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
