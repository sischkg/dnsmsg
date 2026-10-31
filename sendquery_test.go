package dnsmsg

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// queryFor builds a one-question query message asking for the A record of
// name.
func queryFor(t *testing.T, name string) Message {
	t.Helper()
	var q Message
	q.ID = 0x1234
	q.QR = QRQuery
	q.OPCODE = QpcodeQuery
	q.RD = 1
	if err := q.SetQuery(name, CLASS_IN, TYPE_A); err != nil {
		t.Fatalf("queryFor(%q): SetQuery: %v", name, err)
	}
	return q
}

// answerFor builds a response to query that repeats the question and answers
// it with n A records, so that the wire format of the reply is long enough to
// exercise the TCP length prefix when n is large.
func answerFor(t *testing.T, query Message, n int) Message {
	t.Helper()
	if len(query.QuestionSection) == 0 {
		t.Fatal("answerFor: query has no question section")
	}
	q := query.QuestionSection[0]

	reply := Message{
		ID:              query.ID,
		QR:              QRResponse,
		OPCODE:          query.OPCODE,
		RA:              1,
		QDCOUNT:         query.QDCOUNT,
		ANCOUNT:         uint16(n),
		QuestionSection: query.QuestionSection,
	}
	for i := 0; i < n; i++ {
		reply.AnswerSection = append(reply.AnswerSection, ResourceRecord{
			Name:  q.QName,
			Class: q.Class,
			Type:  TYPE_A,
			TTL:   300,
			RData: RecordA{address: [4]byte{192, 0, 2, byte(i)}},
		})
	}
	return reply
}

// serveUDP answers every query sent to an ephemeral port on 127.0.0.1 with
// answer(query) until the test ends, and returns that port.
func serveUDP(t *testing.T, answer func(Message) Message) uint16 {
	t.Helper()
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("serveUDP: listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		buf := make([]byte, UDP_BUFFER_SIZE)
		for {
			n, from, err := ln.ReadFromUDP(buf)
			if err != nil {
				return
			}
			query, err := ParseWireFormat(WireFormat(buf[:n]))
			if err != nil {
				continue
			}
			var w WireFormat
			w.WriteWireFormat(answer(query))
			ln.WriteToUDP([]byte(w), from)
		}
	}()

	return uint16(ln.LocalAddr().(*net.UDPAddr).Port)
}

// serveTCP answers every query sent to an ephemeral port on 127.0.0.1 with
// answer(query) until the test ends, and returns that port.  The reply is
// written chunk bytes at a time, which makes the client read it in several
// pieces.
func serveTCP(t *testing.T, answer func(Message) Message, chunk int) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("serveTCP: listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()

				size := make([]byte, 2)
				if _, err := io.ReadFull(conn, size); err != nil {
					return
				}
				buf := make([]byte, binary.BigEndian.Uint16(size))
				if _, err := io.ReadFull(conn, buf); err != nil {
					return
				}
				query, err := ParseWireFormat(WireFormat(buf))
				if err != nil {
					return
				}

				var w WireFormat
				w.WriteWireFormat(answer(query))
				reply := binary.BigEndian.AppendUint16(nil, uint16(w.Size()))
				reply = append(reply, w...)
				for len(reply) > 0 {
					n := chunk
					if n > len(reply) {
						n = len(reply)
					}
					if _, err := conn.Write(reply[:n]); err != nil {
						return
					}
					reply = reply[n:]
				}
			}()
		}
	}()

	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

// serveQuiet reads queries on an ephemeral port on 127.0.0.1 over transport
// but never answers, so that a query sent to it times out.
func serveQuiet(t *testing.T, transport string) uint16 {
	t.Helper()
	if transport == DNSoverUDP {
		ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatalf("serveQuiet: listen: %v", err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			buf := make([]byte, UDP_BUFFER_SIZE)
			for {
				if _, _, err := ln.ReadFromUDP(buf); err != nil {
					return
				}
			}
		}()
		return uint16(ln.LocalAddr().(*net.UDPAddr).Port)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("serveQuiet: listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(io.Discard, conn)
			}()
		}
	}()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

func TestSendQueryWithTimeoutUDP(t *testing.T) {
	port := serveUDP(t, func(q Message) Message { return answerFor(t, q, 1) })

	reply, err := SendQueryWithTimeout(queryFor(t, "example.com."), "127.0.0.1", port, DNSoverUDP, 2*time.Second)
	if err != nil {
		t.Fatalf("SendQueryWithTimeout(): %v", err)
	}
	if reply.ID != 0x1234 || reply.QR != QRResponse || reply.ANCOUNT != 1 {
		t.Errorf("reply header = ID %#04x QR %d ANCOUNT %d, want ID 0x1234 QR 1 ANCOUNT 1", reply.ID, reply.QR, reply.ANCOUNT)
	}
	if len(reply.AnswerSection) != 1 || reply.AnswerSection[0].RData.String() != "192.0.2.0" {
		t.Errorf("reply answer = %v, want one A record for 192.0.2.0", reply.AnswerSection)
	}
}

func TestSendQueryWithTimeoutTCP(t *testing.T) {
	// The reply is longer than 255 bytes and arrives in seven-byte pieces, so
	// a client that reads the length prefix in the wrong byte order, or that
	// expects one read to return the whole reply, cannot parse it.
	port := serveTCP(t, func(q Message) Message { return answerFor(t, q, 20) }, 7)

	reply, err := SendQueryWithTimeout(queryFor(t, "example.com."), "127.0.0.1", port, DNSoverTCP, 2*time.Second)
	if err != nil {
		t.Fatalf("SendQueryWithTimeout(): %v", err)
	}
	if reply.ANCOUNT != 20 || len(reply.AnswerSection) != 20 {
		t.Fatalf("reply ANCOUNT = %d with %d answers, want 20", reply.ANCOUNT, len(reply.AnswerSection))
	}
	for i, rr := range reply.AnswerSection {
		if want := fmt.Sprintf("192.0.2.%d", i); rr.RData.String() != want {
			t.Errorf("answer %d = %s, want %s", i, rr.RData.String(), want)
		}
	}
}

func TestSendQuery(t *testing.T) {
	port := serveUDP(t, func(q Message) Message { return answerFor(t, q, 1) })

	reply, err := SendQuery(queryFor(t, "example.com."), "127.0.0.1", port, DNSoverUDP)
	if err != nil {
		t.Fatalf("SendQuery(): %v", err)
	}
	if reply.QR != QRResponse {
		t.Errorf("reply QR = %d, want 1", reply.QR)
	}
}

func TestSendQueryWithTimeoutNoReply(t *testing.T) {
	const timeout = 200 * time.Millisecond

	for _, transport := range []string{DNSoverUDP, DNSoverTCP} {
		t.Run(transport, func(t *testing.T) {
			port := serveQuiet(t, transport)

			start := time.Now()
			_, err := SendQueryWithTimeout(queryFor(t, "example.com."), "127.0.0.1", port, transport, timeout)
			elapsed := time.Since(start)
			if err == nil {
				t.Fatal("SendQueryWithTimeout() with an unanswered query returned no error")
			}
			if !strings.Contains(err.Error(), "cannot receive") {
				t.Errorf("error = %v, want a receive error", err)
			}
			if elapsed > 5*timeout {
				t.Errorf("query returned after %v, want about %v", elapsed, timeout)
			}
		})
	}
}

func TestSendQueryWithTimeoutUnknownTransport(t *testing.T) {
	_, err := SendQueryWithTimeout(queryFor(t, "example.com."), "127.0.0.1", 53, "quic", time.Second)
	if err == nil || !strings.Contains(err.Error(), "unknown transport") {
		t.Errorf("error = %v, want an unknown transport error", err)
	}
}

// TestExchangeReportsTheExchange checks the QueryExchange Exchange reports for a
// query that is answered: the octets that went on the wire and the times they
// were written and read.
func TestExchangeReportsTheExchange(t *testing.T) {
	for _, transport := range []string{DNSoverUDP, DNSoverTCP} {
		t.Run(transport, func(t *testing.T) {
			var port uint16
			if transport == DNSoverUDP {
				port = serveUDP(t, func(q Message) Message { return answerFor(t, q, 1) })
			} else {
				port = serveTCP(t, func(q Message) Message { return answerFor(t, q, 1) }, 512)
			}

			query := queryFor(t, "example.com.")
			ex, err := Exchange(query, "127.0.0.1", port, transport, 2*time.Second)
			if err != nil {
				t.Fatalf("Exchange(): %v", err)
			}
			if ex.Transport != transport {
				t.Errorf("ex.Transport = %q, want %q", ex.Transport, transport)
			}
			var want WireFormat
			want.WriteWireFormat(query)
			if string(ex.QueryWire) != string(want) {
				t.Errorf("ex.QueryWire = %d octets, want the %d octets of the query", ex.QueryWire.Size(), want.Size())
			}
			if ex.ReplyWire.Size() == 0 || ex.Reply.ID != query.ID || ex.Reply.ANCOUNT != 1 {
				t.Fatalf("ex.ReplyWire/ex.Reply = %d octets / ID %#04x ANCOUNT %d, want a parsed one-answer reply", ex.ReplyWire.Size(), ex.Reply.ID, ex.Reply.ANCOUNT)
			}
			if ex.SentAt.IsZero() || ex.ReceivedAt.IsZero() || ex.ReceivedAt.Before(ex.SentAt) {
				t.Errorf("ex.SentAt=%v ex.ReceivedAt=%v, want both times and the reply after the query", ex.SentAt, ex.ReceivedAt)
			}
		})
	}
}

// TestExchangeWithConnectTimeoutSeparatesTheDeadlines is the reason the two
// deadlines are separate: a connect deadline much shorter than the time the
// server takes to answer must not end the exchange, and a read deadline must
// not limit the connect.
func TestExchangeWithConnectTimeoutSeparatesTheDeadlines(t *testing.T) {
	const (
		connectTimeout = 50 * time.Millisecond
		queryTimeout   = 3 * time.Second
		answerDelay    = 400 * time.Millisecond
	)

	for _, transport := range []string{DNSoverUDP, DNSoverTCP} {
		t.Run(transport, func(t *testing.T) {
			answer := func(q Message) Message {
				time.Sleep(answerDelay)
				return answerFor(t, q, 1)
			}
			var port uint16
			if transport == DNSoverUDP {
				port = serveUDP(t, answer)
			} else {
				port = serveTCP(t, answer, 512)
			}

			ex, err := ExchangeWithConnectTimeout(queryFor(t, "example.com."), "127.0.0.1", port, transport, connectTimeout, queryTimeout)
			if err != nil {
				t.Fatalf("ExchangeWithConnectTimeout(%s, connect %v, query %v): %v", transport, connectTimeout, queryTimeout, err)
			}
			if ex.Reply.ANCOUNT != 1 {
				t.Errorf("reply ANCOUNT = %d, want 1", ex.Reply.ANCOUNT)
			}
			if ex.SentAt.IsZero() {
				t.Error("ex.SentAt is the zero time, want the time the query was written")
			}
		})
	}
}

// TestExchangeWithConnectTimeoutLimitsConnecting checks that a server that never
// completes a connection is given up on at connectTimeout, not at queryTimeout:
// 192.0.2.1 is the RFC 5737 TEST-NET-1 address, so nothing answers its SYNs.
func TestExchangeWithConnectTimeoutLimitsConnecting(t *testing.T) {
	const (
		target         = "192.0.2.1"
		connectTimeout = 200 * time.Millisecond
		queryTimeout   = 5 * time.Second
	)

	query := queryFor(t, "example.com.")
	start := time.Now()
	ex, err := ExchangeWithConnectTimeout(query, target, 53, DNSoverTCP, connectTimeout, queryTimeout)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("ExchangeWithConnectTimeout(%s) returned a reply from a server that does not answer", target)
	}
	if !strings.Contains(err.Error(), "cannot send message to") {
		t.Errorf("error = %v, want a send/connect error", err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("gave up after %v, want about the %v connect timeout, not the %v query timeout", elapsed, connectTimeout, queryTimeout)
	}
	if !ex.SentAt.IsZero() {
		t.Errorf("ex.SentAt = %v, want the zero time: nothing was written", ex.SentAt)
	}
	if ex.ReplyWire != nil {
		t.Errorf("ex.ReplyWire = %d octets, want nil", ex.ReplyWire.Size())
	}
	var want WireFormat
	want.WriteWireFormat(query)
	if string(ex.QueryWire) != string(want) {
		t.Error("ex.QueryWire does not hold the query that could not be sent")
	}
}

// TestExchangeWithConnectTimeoutRefusedConnection checks what a connect that
// fails for a reason of its own reports: the failed exchange and its query,
// with no deadline reached.
func TestExchangeWithConnectTimeoutRefusedConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	ln.Close()

	query := queryFor(t, "example.com.")
	ex, err := ExchangeWithConnectTimeout(query, "127.0.0.1", port, DNSoverTCP, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "cannot send message to") {
		t.Fatalf("error = %v, want a connect error", err)
	}
	if !ex.SentAt.IsZero() || ex.ReplyWire != nil {
		t.Errorf("ex.SentAt = %v ex.ReplyWire = %d octets, want the zero time and nothing read", ex.SentAt, ex.ReplyWire.Size())
	}
	if ex.QueryWire.Size() == 0 {
		t.Error("ex.QueryWire is empty, want the query that was not sent")
	}
}

// TestExchangeMatchesExchangeWithConnectTimeout keeps Exchange a call to
// ExchangeWithConnectTimeout with one value for both steps: the two report the
// same exchange, whether the query was answered or not.
func TestExchangeMatchesExchangeWithConnectTimeout(t *testing.T) {
	const timeout = 2 * time.Second

	t.Run("answered", func(t *testing.T) {
		port := serveTCP(t, func(q Message) Message { return answerFor(t, q, 2) }, 11)
		query := queryFor(t, "example.com.")

		a, err := Exchange(query, "127.0.0.1", port, DNSoverTCP, timeout)
		if err != nil {
			t.Fatalf("Exchange(): %v", err)
		}
		b, err := ExchangeWithConnectTimeout(query, "127.0.0.1", port, DNSoverTCP, timeout, timeout)
		if err != nil {
			t.Fatalf("ExchangeWithConnectTimeout(): %v", err)
		}
		if a.Transport != b.Transport || string(a.QueryWire) != string(b.QueryWire) || string(a.ReplyWire) != string(b.ReplyWire) {
			t.Error("Exchange and ExchangeWithConnectTimeout reported different octets")
		}
		if a.Reply.ANCOUNT != 2 || b.Reply.ANCOUNT != 2 {
			t.Errorf("ANSWER counts = %d and %d, want 2 each", a.Reply.ANCOUNT, b.Reply.ANCOUNT)
		}
	})

	t.Run("unanswered", func(t *testing.T) {
		port := serveQuiet(t, DNSoverTCP)
		query := queryFor(t, "example.com.")

		_, errA := Exchange(query, "127.0.0.1", port, DNSoverTCP, 200*time.Millisecond)
		_, errB := ExchangeWithConnectTimeout(query, "127.0.0.1", port, DNSoverTCP, 200*time.Millisecond, 200*time.Millisecond)
		if errA == nil || errB == nil {
			t.Fatalf("errors = %v and %v, want a timeout from both", errA, errB)
		}
		for _, err := range []error{errA, errB} {
			if !strings.Contains(err.Error(), "cannot receive") {
				t.Errorf("error = %v, want a receive error", err)
			}
		}
	})
}
