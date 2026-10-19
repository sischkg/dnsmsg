package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sischkg/dnsmsg"
)

// stubAnswer builds a response to query that repeats the question and answers it
// with n A records, so that the wire format of the reply is long enough to be
// split over several TCP segments when n is large.
func stubAnswer(query dnsmsg.Message, n int) dnsmsg.Message {
	if len(query.QuestionSection) == 0 {
		return query
	}
	q := query.QuestionSection[0]

	reply := dnsmsg.Message{
		ID:              query.ID,
		QR:              dnsmsg.QRResponse,
		OPCODE:          query.OPCODE,
		RA:              1,
		QDCOUNT:         query.QDCOUNT,
		ANCOUNT:         uint16(n),
		QuestionSection: query.QuestionSection,
	}
	for i := 0; i < n; i++ {
		reply.AnswerSection = append(reply.AnswerSection, dnsmsg.ResourceRecord{
			Name:  q.QName,
			Class: q.Class,
			Type:  dnsmsg.TYPE_A,
			TTL:   300,
			RData: dnsmsg.NewRecordA([4]byte{192, 0, 2, byte(i)}),
		})
	}
	return reply
}

// serveUDPRaw answers every query sent to an ephemeral port on 127.0.0.1 with
// the wire format that answer makes from the query octets, and returns that
// port.  It is the raw form of serveUDP, for the tests that need the exact
// octets the client sent.
func serveUDPRaw(t *testing.T, answer func(dnsmsg.WireFormat) dnsmsg.WireFormat) uint16 {
	t.Helper()
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("serveUDPRaw: listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		buf := make([]byte, 1<<12)
		for {
			n, from, err := ln.ReadFromUDP(buf)
			if err != nil {
				return
			}
			query := make(dnsmsg.WireFormat, n)
			copy(query, buf[:n])
			reply := answer(query)
			if len(reply) == 0 {
				continue
			}
			ln.WriteToUDP([]byte(reply), from)
		}
	}()

	return uint16(ln.LocalAddr().(*net.UDPAddr).Port)
}

// serveUDP answers every query sent to an ephemeral port on 127.0.0.1 with
// answer(query) until the test ends, and returns that port.
func serveUDP(t *testing.T, answer func(dnsmsg.Message) dnsmsg.Message) uint16 {
	t.Helper()
	return serveUDPRaw(t, func(query dnsmsg.WireFormat) dnsmsg.WireFormat {
		msg, err := dnsmsg.ParseWireFormat(query)
		if err != nil {
			return nil
		}
		var w dnsmsg.WireFormat
		w.WriteWireFormat(answer(msg))
		return w
	})
}

// serveTCPRaw answers every query sent to an ephemeral port on 127.0.0.1 with
// the wire format that answer makes from the query octets, and returns that
// port.  The reply is written chunk bytes at a time, which makes dq read it in
// several pieces.  It is the raw form of serveTCP.
func serveTCPRaw(t *testing.T, answer func(dnsmsg.WireFormat) dnsmsg.WireFormat, chunk int) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("serveTCPRaw: listen: %v", err)
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

				reply := answer(dnsmsg.WireFormat(buf))
				if len(reply) == 0 {
					return
				}
				framed := binary.BigEndian.AppendUint16(nil, uint16(reply.Size()))
				framed = append(framed, reply...)
				for len(framed) > 0 {
					n := chunk
					if n > len(framed) {
						n = len(framed)
					}
					if _, err := conn.Write(framed[:n]); err != nil {
						return
					}
					framed = framed[n:]
				}
			}()
		}
	}()

	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

// serveTCP answers every query sent to an ephemeral port on 127.0.0.1 with
// answer(query) until the test ends, and returns that port.  The reply is
// written chunk bytes at a time, which makes dq read it in several pieces.
func serveTCP(t *testing.T, answer func(dnsmsg.Message) dnsmsg.Message, chunk int) uint16 {
	t.Helper()
	return serveTCPRaw(t, func(query dnsmsg.WireFormat) dnsmsg.WireFormat {
		msg, err := dnsmsg.ParseWireFormat(query)
		if err != nil {
			return nil
		}
		var w dnsmsg.WireFormat
		w.WriteWireFormat(answer(msg))
		return w
	}, chunk)
}

// closedTCPPort returns a port on 127.0.0.1 that a TCP connection to it is
// immediately refused on.
func closedTCPPort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("closedTCPPort: listen: %v", err)
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	ln.Close()
	return port
}

// tempResolvConf writes a resolver configuration containing lines and returns
// its path.  The file is created under tmp/ as the repository conventions ask.
func tempResolvConf(t *testing.T, lines ...string) string {
	t.Helper()
	if err := os.MkdirAll("tmp", 0o755); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("tmp", strings.ReplaceAll(t.Name(), "/", "-")+"-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	path := dir + "/resolv.conf"
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// decodeOutput parses what dq printed on stdout as the JSON document of the json
// output format.
func decodeOutput(t *testing.T, data []byte) jsonDocument {
	t.Helper()
	if !json.Valid(data) {
		t.Fatalf("the output is not a JSON document:\n%s", data)
	}
	var out jsonDocument
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("cannot parse the JSON output: %v\n%s", err, data)
	}
	return out
}

// TestReorderArgs checks that options are accepted on either side of the domain
// name, and that the value of an option stays with that option.
func TestReorderArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "options already in front",
			args: []string{"-s", "192.0.2.1", "-r", "example.com"},
			want: []string{"-s", "192.0.2.1", "-r", "example.com"},
		},
		{
			name: "options after the domain name",
			args: []string{"example.com", "-r", "-p", "5353", "-nsid"},
			want: []string{"-r", "-p", "5353", "-nsid", "example.com"},
		},
		{
			name: "an option value stays with its option",
			args: []string{"example.com", "-s", "192.0.2.1", "extra"},
			want: []string{"-s", "192.0.2.1", "example.com", "extra"},
		},
		{
			name: "the = form is one argument",
			args: []string{"example.com", "-p=5353"},
			want: []string{"-p=5353", "example.com"},
		},
		{
			name: "-timeout keeps its value",
			args: []string{"example.com", "-timeout", "2", "-r"},
			want: []string{"-timeout", "2", "-r", "example.com"},
		},
		{
			name: "everything after -- is a positional argument",
			args: []string{"--", "-r"},
			want: []string{"--", "-r"},
		},
		{
			name: "an option after -- is a positional argument",
			args: []string{"-r", "--", "-p", "5353"},
			want: []string{"-r", "--", "-p", "5353"},
		},
	}

	for _, tt := range tests {
		got := reorderArgs(tt.args)
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s: reorderArgs(%q) = %q, want %q", tt.name, tt.args, got, tt.want)
		}
	}
}

func TestParseArgs(t *testing.T) {
	defaults := options{
		port:      defaultPort,
		qclass:    defaultQClass,
		qtype:     defaultQType,
		output:    defaultOutput,
		edns:      true,
		name:      "example.com",
		transport: dnsmsg.DNSoverUDP,
		timeout:   dnsmsg.DefaultQueryTimeout,
	}

	tests := []struct {
		name    string
		args    []string
		want    options
		wantErr string
	}{
		{
			name: "defaults",
			args: []string{"example.com"},
			want: defaults,
		},
		{
			name: "all options",
			args: []string{"-s", "ns.example", "-p", "5353", "-c", "CH", "-t", "AAAA", "-r", "-tcp", "example.com"},
			want: options{
				server:    "ns.example",
				port:      5353,
				qclass:    "CH",
				qtype:     "AAAA",
				rd:        true,
				output:    defaultOutput,
				edns:      true,
				name:      "example.com",
				transport: dnsmsg.DNSoverTCP,
				timeout:   dnsmsg.DefaultQueryTimeout,
			},
		},
		{
			name: "explicit -udp",
			args: []string{"-udp", "example.com"},
			want: defaults,
		},
		{
			name: "-no-edns",
			args: []string{"-no-edns", "example.com"},
			want: func() options {
				o := defaults
				o.edns = false
				return o
			}(),
		},
		{
			name: "-edns=false",
			args: []string{"-edns=false", "example.com"},
			want: func() options {
				o := defaults
				o.edns = false
				return o
			}(),
		},
		{
			name: "-nsid",
			args: []string{"-nsid", "example.com"},
			want: func() options {
				o := defaults
				o.nsid = true
				return o
			}(),
		},
		{
			name: "-o json",
			args: []string{"-o", "json", "example.com"},
			want: defaults,
		},
		{
			name: "-timeout in whole seconds",
			args: []string{"-timeout", "2", "example.com"},
			want: func() options {
				o := defaults
				o.timeout = 2 * time.Second
				return o
			}(),
		},
		{
			name: "-timeout in a fraction of a second",
			args: []string{"example.com", "-timeout", "0.25"},
			want: func() options {
				o := defaults
				o.timeout = 250 * time.Millisecond
				return o
			}(),
		},
		{
			name: "-timeout 0 means no timeout",
			args: []string{"-timeout=0", "example.com"},
			want: func() options {
				o := defaults
				o.timeout = 0
				return o
			}(),
		},
		{
			name:    "no domain name",
			args:    []string{"-r"},
			wantErr: "ドメイン名を 1 つ指定してください",
		},
		{
			name:    "two domain names",
			args:    []string{"example.com", "example.org"},
			wantErr: "ドメイン名を 1 つ指定してください",
		},
		{
			name: "options after the domain name",
			args: []string{"example.com", "-r", "-p", "5353"},
			want: func() options {
				o := defaults
				o.rd = true
				o.port = 5353
				return o
			}(),
		},
		{
			name: "-- separates the domain name from the options",
			args: []string{"--", "example.com"},
			want: defaults,
		},
		{
			name: "a domain name that looks like an option",
			args: []string{"-r", "--", "-example.com"},
			want: func() options {
				o := defaults
				o.rd = true
				o.name = "-example.com"
				return o
			}(),
		},
		{
			name:    "-tcp and -udp",
			args:    []string{"-tcp", "-udp", "example.com"},
			wantErr: "-tcp と -udp は同時に指定できません",
		},
		{
			name:    "-edns and -no-edns",
			args:    []string{"-edns", "-no-edns", "example.com"},
			wantErr: "-edns と -no-edns は同時に指定できません",
		},
		{
			name:    "-nsid and -no-edns",
			args:    []string{"-nsid", "-no-edns", "example.com"},
			wantErr: "-nsid は -no-edns と同時に指定できません",
		},
		{
			name: "-o base64",
			args: []string{"-o", "base64", "example.com"},
			want: func() options {
				o := defaults
				o.output = "base64"
				return o
			}(),
		},
		{
			name:    "unsupported output format",
			args:    []string{"-o", "yaml", "example.com"},
			wantErr: `出力形式 "yaml" には対応していません (base64, json のみ)`,
		},
		{
			name:    "port 0",
			args:    []string{"-p", "0", "example.com"},
			wantErr: "ポート番号 0 が範囲外です",
		},
		{
			name:    "port out of range",
			args:    []string{"-p", "65536", "example.com"},
			wantErr: "ポート番号 65536 が範囲外です",
		},
		{
			name:    "port is not a number",
			args:    []string{"-p", "abc", "example.com"},
			wantErr: "invalid value",
		},
		{
			name:    "negative timeout",
			args:    []string{"-timeout", "-1", "example.com"},
			wantErr: "-timeout -1 は 0 秒以上で指定してください",
		},
		{
			name:    "timeout is not a number",
			args:    []string{"-timeout", "abc", "example.com"},
			wantErr: "invalid value",
		},
		{
			name:    "unknown option",
			args:    []string{"-quic", "example.com"},
			wantErr: "flag provided but not defined",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stderr bytes.Buffer
			got, err := parseArgs(tt.args, &stderr)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("parseArgs(%v) returned no error, want %q", tt.args, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("parseArgs(%v) error = %v, want one containing %q", tt.args, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseArgs(%v): %v", tt.args, err)
			}
			if *got != tt.want {
				t.Errorf("parseArgs(%v) = %+v, want %+v", tt.args, *got, tt.want)
			}
		})
	}
}

func TestParseArgsHelp(t *testing.T) {
	// Options are documented with one "-", but the flag package accepts the
	// doubled form too, so both spellings print the usage.
	for _, arg := range []string{"-h", "--help"} {
		var stderr bytes.Buffer
		_, err := parseArgs([]string{arg, "example.com"}, &stderr)
		if !errors.Is(err, flag.ErrHelp) {
			t.Errorf("parseArgs(%q) error = %v, want flag.ErrHelp", arg, err)
		}
		if !strings.Contains(stderr.String(), "usage: dq") {
			t.Errorf("parseArgs(%q) printed %q, want the usage", arg, stderr.String())
		}
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"-h"}, &stdout, &stderr); code != 0 {
		t.Errorf("run(-h) exit code = %d, want 0", code)
	}
	if !strings.Contains(stderr.String(), "usage: dq") {
		t.Errorf("run(-h) printed %q on stderr, want the usage", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("run(-h) printed %q on stdout, want nothing", stdout.String())
	}
}

func TestParseQClass(t *testing.T) {
	tests := []struct {
		in      string
		want    dnsmsg.ResourceClass
		wantErr bool
	}{
		{in: "IN", want: dnsmsg.CLASS_IN},
		{in: "CH", want: dnsmsg.CLASS_CHAOS},
		{in: "HS", want: dnsmsg.CLASS_HESIOD},
		{in: "ANY", want: dnsmsg.CLASS_ANY},
		{in: "CLASS99", want: dnsmsg.ResourceClass(99)},
		{in: "3", want: dnsmsg.CLASS_CHAOS},
		{in: "255", want: dnsmsg.CLASS_ANY},
		{in: "65535", want: dnsmsg.ResourceClass(65535)},
		{in: "BOGUS", wantErr: true},
		{in: "", wantErr: true},
		{in: "70000", wantErr: true},
	}

	for _, tt := range tests {
		got, err := parseQClass(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseQClass(%q) = %d, want an error", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseQClass(%q): %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("parseQClass(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestParseQType(t *testing.T) {
	tests := []struct {
		in      string
		want    dnsmsg.ResourceType
		wantErr bool
	}{
		{in: "A", want: dnsmsg.TYPE_A},
		{in: "AAAA", want: dnsmsg.TYPE_AAAA},
		{in: "NS", want: dnsmsg.TYPE_NS},
		{in: "SOA", want: dnsmsg.TYPE_SOA},
		{in: "DNSKEY", want: dnsmsg.TYPE_DNSKEY},
		{in: "TYPE99", want: dnsmsg.ResourceType(99)},
		{in: "15", want: dnsmsg.TYPE_MX},
		{in: "65535", want: dnsmsg.ResourceType(65535)},
		{in: "BOGUS", wantErr: true},
		{in: "", wantErr: true},
		{in: "70000", wantErr: true},
	}

	for _, tt := range tests {
		got, err := parseQType(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseQType(%q) = %d, want an error", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseQType(%q): %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("parseQType(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestBuildQuery(t *testing.T) {
	base := options{
		port:      defaultPort,
		qclass:    defaultQClass,
		qtype:     defaultQType,
		output:    defaultOutput,
		transport: dnsmsg.DNSoverUDP,
		timeout:   dnsmsg.DefaultQueryTimeout,
	}

	t.Run("plain query", func(t *testing.T) {
		o := base
		msg, err := buildQuery(&o, "example.com", 0x1234)
		if err != nil {
			t.Fatalf("buildQuery(): %v", err)
		}
		if msg.ID != 0x1234 || msg.QR != dnsmsg.QRQuery || msg.OPCODE != dnsmsg.QpcodeQuery {
			t.Errorf("header = ID %#04x QR %d OPCODE %d, want ID 0x1234 QR 0 OPCODE 0", msg.ID, msg.QR, msg.OPCODE)
		}
		if msg.RD != 0 {
			t.Errorf("RD = %d, want 0", msg.RD)
		}
		if msg.QDCOUNT != 1 || len(msg.QuestionSection) != 1 {
			t.Fatalf("QDCOUNT = %d with %d questions, want 1", msg.QDCOUNT, len(msg.QuestionSection))
		}
		q := msg.QuestionSection[0]
		if q.QName.String() != "example.com." || q.Class != dnsmsg.CLASS_IN || q.Type != dnsmsg.TYPE_A {
			t.Errorf("question = %s %s %s, want example.com. IN A", q.QName.String(), q.Class, q.Type)
		}
		if msg.ARCOUNT != 0 || len(msg.AdditionalSection) != 0 {
			t.Errorf("ARCOUNT = %d with %d records, want 0", msg.ARCOUNT, len(msg.AdditionalSection))
		}
	})

	t.Run("RD=1", func(t *testing.T) {
		o := base
		o.rd = true
		msg, err := buildQuery(&o, "example.com", 1)
		if err != nil {
			t.Fatalf("buildQuery(): %v", err)
		}
		if msg.RD != 1 {
			t.Errorf("RD = %d, want 1", msg.RD)
		}
	})

	t.Run("class and type", func(t *testing.T) {
		o := base
		o.qclass = "CH"
		o.qtype = "15"
		msg, err := buildQuery(&o, "example.com", 1)
		if err != nil {
			t.Fatalf("buildQuery(): %v", err)
		}
		q := msg.QuestionSection[0]
		if q.Class != dnsmsg.CLASS_CHAOS || q.Type != dnsmsg.TYPE_MX {
			t.Errorf("question class and type = %s %s, want CH MX", q.Class, q.Type)
		}
	})

	t.Run("EDNS0", func(t *testing.T) {
		o := base
		o.edns = true
		msg, err := buildQuery(&o, "example.com", 1)
		if err != nil {
			t.Fatalf("buildQuery(): %v", err)
		}
		if msg.ARCOUNT != 1 || len(msg.AdditionalSection) != 1 {
			t.Fatalf("ARCOUNT = %d with %d records, want 1", msg.ARCOUNT, len(msg.AdditionalSection))
		}
		rr := msg.AdditionalSection[0]
		if rr.Type != dnsmsg.TYPE_OPT || rr.Name.String() != "." || rr.TTL != dnsmsg.EDNS0DefaultPayloadSize {
			t.Errorf("OPT record = %s %s TTL %d, want . OPT payload size %d",
				rr.Name.String(), rr.Type, rr.TTL, dnsmsg.EDNS0DefaultPayloadSize)
		}
		opt, ok := rr.RData.(dnsmsg.RecordOPT)
		if !ok {
			t.Fatalf("OPT RDATA is a %T, want a dnsmsg.RecordOPT", rr.RData)
		}
		if opt.Version != dnsmsg.EDNS0Version || opt.Flags != 0 {
			t.Errorf("OPT version and flags = %d %#04x, want 0 0000", opt.Version, opt.Flags)
		}
		if len(opt.Options) != 0 {
			t.Errorf("OPT options = %v, want none", opt.Options)
		}
	})

	t.Run("NSID", func(t *testing.T) {
		o := base
		o.edns = true
		o.nsid = true
		msg, err := buildQuery(&o, "example.com", 1)
		if err != nil {
			t.Fatalf("buildQuery(): %v", err)
		}
		opt, ok := msg.AdditionalSection[0].RData.(dnsmsg.RecordOPT)
		if !ok {
			t.Fatalf("OPT RDATA is a %T, want a dnsmsg.RecordOPT", msg.AdditionalSection[0].RData)
		}
		if len(opt.Options) != 1 {
			t.Fatalf("OPT options = %v, want one NSID option", opt.Options)
		}
		nsid, ok := opt.Options[0].(dnsmsg.EDNSOptionNSID)
		if !ok {
			t.Fatalf("the EDNS option is a %T, want a dnsmsg.EDNSOptionNSID", opt.Options[0])
		}
		if nsid.Code() != dnsmsg.EDNSOptionCodeNSID || nsid.ID != "" || len(nsid.Data()) != 0 {
			t.Errorf("NSID option = code %d id %q data %d bytes, want code 3 with no id", nsid.Code(), nsid.ID, len(nsid.Data()))
		}
	})

	t.Run("bad class", func(t *testing.T) {
		o := base
		o.qclass = "BOGUS"
		if _, err := buildQuery(&o, "example.com", 1); err == nil {
			t.Error("buildQuery() with an unknown QCLASS returned no error")
		}
	})

	t.Run("bad type", func(t *testing.T) {
		o := base
		o.qtype = "BOGUS"
		if _, err := buildQuery(&o, "example.com", 1); err == nil {
			t.Error("buildQuery() with an unknown QTYPE returned no error")
		}
	})

	t.Run("bad domain name", func(t *testing.T) {
		o := base
		if _, err := buildQuery(&o, "example..com", 1); err == nil {
			t.Error("buildQuery() with an empty label returned no error")
		}
	})
}

func TestNewMessageID(t *testing.T) {
	seen := make(map[uint16]bool)
	for i := 0; i < 200; i++ {
		id, err := newMessageID()
		if err != nil {
			t.Fatalf("newMessageID(): %v", err)
		}
		seen[id] = true
	}
	if len(seen) < 100 {
		t.Errorf("200 message ids produced only %d different values, want many different values", len(seen))
	}
}

// TestRunJSON runs dq against a stub name server over both transports and
// checks the JSON document it prints.
func TestRunJSON(t *testing.T) {
	for _, transport := range []string{"-tcp", "-udp"} {
		t.Run(transport, func(t *testing.T) {
			var port uint16
			if transport == "-tcp" {
				// A reply of several hundred bytes arrives in small pieces.
				port = serveTCP(t, func(q dnsmsg.Message) dnsmsg.Message { return stubAnswer(q, 20) }, 7)
			} else {
				port = serveUDP(t, func(q dnsmsg.Message) dnsmsg.Message { return stubAnswer(q, 2) })
			}

			var stdout, stderr bytes.Buffer
			args := []string{"-s", "127.0.0.1", "-p", strconv.Itoa(int(port)), transport, "-r", "-nsid", "example.com"}
			if code := run(args, &stdout, &stderr); code != 0 {
				t.Fatalf("run(%v) exit code = %d, want 0\nstderr: %s", args, code, stderr.String())
			}
			if stderr.Len() != 0 {
				t.Errorf("run() printed %q on stderr, want nothing", stderr.String())
			}

			out := stdout.Bytes()
			if !bytes.HasSuffix(out, []byte("\n")) {
				t.Error("the JSON output does not end with a newline")
			}
			if !bytes.Contains(out, []byte("\n  \"query\": {")) {
				t.Errorf("the JSON output is not indented:\n%s", out)
			}

			doc := decodeOutput(t, out)

			q := doc.Query
			if q.QR != dnsmsg.QRQuery || q.RD != 1 || q.QDCOUNT != 1 {
				t.Errorf("query header = QR %d RD %d QDCOUNT %d, want QR 0 RD 1 QDCOUNT 1", q.QR, q.RD, q.QDCOUNT)
			}
			if len(q.QuestionSection) != 1 || q.QuestionSection[0].QName.String() != "example.com." {
				t.Fatalf("query question section = %v, want one question for example.com.", q.QuestionSection)
			}
			if len(q.AdditionalSection) != 1 || q.AdditionalSection[0].Type != dnsmsg.TYPE_OPT {
				t.Fatalf("query additional section = %v, want one OPT record", q.AdditionalSection)
			}
			opt, ok := q.AdditionalSection[0].RData.(*dnsmsg.RecordOPT)
			if !ok {
				t.Fatalf("the OPT RDATA is a %T, want a *dnsmsg.RecordOPT", q.AdditionalSection[0].RData)
			}
			if len(opt.Options) != 1 || opt.Options[0].Code() != dnsmsg.EDNSOptionCodeNSID {
				t.Errorf("OPT options = %v, want one NSID option", opt.Options)
			}

			if doc.Response == nil {
				t.Fatal("response is null, want the stub answer")
			}
			r := doc.Response
			if r.ID != q.ID || r.QR != dnsmsg.QRResponse || r.RA != 1 {
				t.Errorf("response header = ID %#04x QR %d RA %d, want ID %#04x QR 1 RA 1", r.ID, r.QR, r.RA, q.ID)
			}
			wantAnswers := 20
			if transport == "-udp" {
				wantAnswers = 2
			}
			if r.ANCOUNT != uint16(wantAnswers) || len(r.AnswerSection) != wantAnswers {
				t.Fatalf("response ANCOUNT = %d with %d answers, want %d", r.ANCOUNT, len(r.AnswerSection), wantAnswers)
			}
			for i, rr := range r.AnswerSection {
				want := "192.0.2." + strconv.Itoa(i)
				if rr.RData.String() != want {
					t.Errorf("answer %d = %s, want %s", i, rr.RData.String(), want)
				}
			}
		})
	}
}

// base64Line is one line of the base64 output format: the kind of message the
// line reports, the time it was sent or received, the transport it travelled
// over, and its octets.
type base64Line struct {
	kind      string
	at        time.Time
	transport string
	wire      dnsmsg.WireFormat
}

// parseBase64Output splits what dq printed with -o base64 into its lines.
func parseBase64Output(t *testing.T, data []byte) []base64Line {
	t.Helper()

	text := string(data)
	if !strings.HasSuffix(text, "\n") {
		t.Errorf("the base64 output does not end with a newline:\n%s", text)
	}

	var lines []base64Line
	for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		fields := strings.Split(line, ",")
		if len(fields) != 4 {
			t.Fatalf("base64 line %q has %d comma separated fields, want 4", line, len(fields))
		}
		at, err := time.Parse(time.RFC3339Nano, fields[1])
		if err != nil {
			t.Errorf("base64 line %q does not carry an RFC 3339 time: %v", line, err)
		}
		wire, err := base64.StdEncoding.DecodeString(fields[3])
		if err != nil {
			t.Fatalf("base64 line %q does not carry base64: %v\n%s", line, err, text)
		}
		lines = append(lines, base64Line{
			kind:      fields[0],
			at:        at,
			transport: fields[2],
			wire:      dnsmsg.WireFormat(wire),
		})
	}
	return lines
}

// TestRunBase64 runs dq with -o base64 against a stub name server over both
// transports and checks that the two lines carry the exact octets that went on
// the wire: the query the stub name server read, and the reply it wrote after
// its length prefix.
func TestRunBase64(t *testing.T) {
	for _, transport := range []string{"-tcp", "-udp"} {
		t.Run(transport, func(t *testing.T) {
			var mu sync.Mutex
			var received, answered dnsmsg.WireFormat

			answer := func(query dnsmsg.WireFormat) dnsmsg.WireFormat {
				msg, err := dnsmsg.ParseWireFormat(query)
				if err != nil {
					t.Errorf("the stub name server cannot parse the query: %v", err)
					return nil
				}
				var w dnsmsg.WireFormat
				w.WriteWireFormat(stubAnswer(msg, 3))

				mu.Lock()
				received = append(received[:0], query...)
				answered = append(answered[:0], w...)
				mu.Unlock()
				return w
			}

			var port uint16
			if transport == "-tcp" {
				// A reply of several hundred bytes arrives in small pieces.
				port = serveTCPRaw(t, answer, 9)
			} else {
				port = serveUDPRaw(t, answer)
			}

			var stdout, stderr bytes.Buffer
			args := []string{"-s", "127.0.0.1", "-p", strconv.Itoa(int(port)), transport, "-r", "-o", "base64", "example.com"}

			start := time.Now()
			if code := run(args, &stdout, &stderr); code != 0 {
				t.Fatalf("run(%v) exit code = %d, want 0\nstderr: %s", args, code, stderr.String())
			}
			if stderr.Len() != 0 {
				t.Errorf("run() printed %q on stderr, want nothing", stderr.String())
			}

			mu.Lock()
			wantQuery, wantReply := received, answered
			mu.Unlock()
			if len(wantQuery) == 0 {
				t.Fatal("the stub name server did not read a query")
			}

			lines := parseBase64Output(t, stdout.Bytes())
			if len(lines) != 2 {
				t.Fatalf("the base64 output has %d lines, want a sent line and a recv line:\n%s",
					len(lines), stdout.String())
			}

			wantTransport := strings.TrimPrefix(transport, "-")
			wantKinds := []string{"sent", "recv"}
			for i, line := range lines {
				if line.kind != wantKinds[i] {
					t.Errorf("base64 line %d reports %q, want %q", i, line.kind, wantKinds[i])
				}
				if line.transport != wantTransport {
					t.Errorf("base64 line %d reports transport %q, want %q", i, line.transport, wantTransport)
				}
				if line.at.Before(start.Add(-time.Second)) || line.at.After(time.Now().Add(time.Second)) {
					t.Errorf("base64 line %d is timed at %s, which is outside the time window of this run",
						i, line.at.Format(time.RFC3339Nano))
				}
			}
			if lines[1].at.Before(lines[0].at) {
				t.Errorf("the recv line is timed at %s, before the sent line at %s",
					lines[1].at.Format(time.RFC3339Nano), lines[0].at.Format(time.RFC3339Nano))
			}

			if !bytes.Equal(lines[0].wire, wantQuery) {
				t.Errorf("the sent line carries %d octets, want the %d octets the stub name server read",
					len(lines[0].wire), len(wantQuery))
			}
			if !bytes.Equal(lines[1].wire, wantReply) {
				t.Errorf("the recv line carries %d octets, want the %d octets the stub name server wrote",
					len(lines[1].wire), len(wantReply))
			}

			// The octets are the DNS messages themselves, so they parse as such.
			q, err := dnsmsg.ParseWireFormat(lines[0].wire)
			if err != nil {
				t.Fatalf("the sent line does not carry a DNS message: %v", err)
			}
			if q.QR != dnsmsg.QRQuery || q.RD != 1 || len(q.QuestionSection) != 1 {
				t.Errorf("the sent line carries QR %d RD %d with %d questions, want a query with one question",
					q.QR, q.RD, len(q.QuestionSection))
			}
			r, err := dnsmsg.ParseWireFormat(lines[1].wire)
			if err != nil {
				t.Fatalf("the recv line does not carry a DNS message: %v", err)
			}
			if r.ID != q.ID || r.QR != dnsmsg.QRResponse {
				t.Errorf("the recv line carries ID %#04x QR %d, want ID %#04x QR 1", r.ID, r.QR, q.ID)
			}
			if r.ANCOUNT != 3 || len(r.AnswerSection) != 3 {
				t.Errorf("the recv line carries ANCOUNT %d with %d answers, want 3", r.ANCOUNT, len(r.AnswerSection))
			}
		})
	}
}

// TestRunBase64WithoutResponse checks that the base64 format prints only the
// lines for the messages that really went on the wire: the sent line when no
// response was read, and no line at all when the query was never sent.
func TestRunBase64WithoutResponse(t *testing.T) {
	t.Run("no response", func(t *testing.T) {
		port := noAnswerListener(t)

		const timeout = 200 * time.Millisecond
		old := queryTimeout
		queryTimeout = timeout
		t.Cleanup(func() { queryTimeout = old })

		var stdout, stderr bytes.Buffer
		args := []string{"-s", "127.0.0.1", "-p", strconv.Itoa(int(port)), "-tcp", "-o", "base64", "example.com"}
		if code := run(args, &stdout, &stderr); code != 1 {
			t.Fatalf("run(%v) exit code = %d, want 1\nstderr: %s", args, code, stderr.String())
		}
		if !strings.Contains(stderr.String(), "dq:") {
			t.Errorf("run() printed %q on stderr, want an error message", stderr.String())
		}

		lines := parseBase64Output(t, stdout.Bytes())
		if len(lines) != 1 {
			t.Fatalf("the base64 output has %d lines, want only the sent line:\n%s", len(lines), stdout.String())
		}
		if lines[0].kind != "sent" || lines[0].transport != "tcp" {
			t.Errorf("the base64 line reports kind %q transport %q, want kind sent transport tcp",
				lines[0].kind, lines[0].transport)
		}
		msg, err := dnsmsg.ParseWireFormat(lines[0].wire)
		if err != nil {
			t.Fatalf("the sent line does not carry a DNS message: %v", err)
		}
		if msg.QR != dnsmsg.QRQuery || len(msg.QuestionSection) != 1 {
			t.Errorf("the sent line carries QR %d with %d questions, want a query with one question",
				msg.QR, len(msg.QuestionSection))
		}
	})

	t.Run("query not sent", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		args := []string{"-s", "127.0.0.1", "-p", strconv.Itoa(int(closedTCPPort(t))), "-tcp", "-o", "base64", "example.com"}
		if code := run(args, &stdout, &stderr); code != 1 {
			t.Fatalf("run(%v) exit code = %d, want 1\nstderr: %s", args, code, stderr.String())
		}
		if stdout.Len() != 0 {
			t.Errorf("run() printed %q on stdout, want nothing because no message went on the wire", stdout.String())
		}
		if !strings.Contains(stderr.String(), "dq:") {
			t.Errorf("run() printed %q on stderr, want an error message", stderr.String())
		}
	})
}

// TestRunDefaultServer checks that dq reads the name server it queries from the
// resolver configuration when -s is not given.
func TestRunDefaultServer(t *testing.T) {
	t.Run("from resolv.conf", func(t *testing.T) {
		port := serveUDP(t, func(q dnsmsg.Message) dnsmsg.Message { return stubAnswer(q, 1) })
		path := tempResolvConf(t, "# comment", "search example.org", "nameserver 127.0.0.1")

		old := resolvConfPath
		resolvConfPath = path
		t.Cleanup(func() { resolvConfPath = old })

		var stdout, stderr bytes.Buffer
		args := []string{"-p", strconv.Itoa(int(port)), "example.com"}
		if code := run(args, &stdout, &stderr); code != 0 {
			t.Fatalf("run(%v) exit code = %d, want 0\nstderr: %s", args, code, stderr.String())
		}
		if !strings.Contains(stderr.String(), "127.0.0.1 に問い合わせます") {
			t.Errorf("run() printed %q on stderr, want a note about the name server", stderr.String())
		}
		doc := decodeOutput(t, stdout.Bytes())
		if doc.Response == nil || doc.Response.ANCOUNT != 1 {
			t.Errorf("response = %v, want one answer", doc.Response)
		}
	})

	t.Run("no resolv.conf", func(t *testing.T) {
		port := serveUDP(t, func(q dnsmsg.Message) dnsmsg.Message { return stubAnswer(q, 1) })

		old := resolvConfPath
		resolvConfPath = "tmp/does-not-exist/resolv.conf"
		t.Cleanup(func() { resolvConfPath = old })

		var stdout, stderr bytes.Buffer
		args := []string{"-p", strconv.Itoa(int(port)), "example.com"}
		if code := run(args, &stdout, &stderr); code != 0 {
			t.Fatalf("run(%v) exit code = %d, want 0\nstderr: %s", args, code, stderr.String())
		}
		if !strings.Contains(stderr.String(), fallbackServer+" に問い合わせます") {
			t.Errorf("run() printed %q on stderr, want a note about %s", stderr.String(), fallbackServer)
		}
		doc := decodeOutput(t, stdout.Bytes())
		if doc.Response == nil || doc.Response.ANCOUNT != 1 {
			t.Errorf("response = %v, want one answer", doc.Response)
		}
	})
}

// TestRunQueryFailure checks that dq still prints the query it sent, with a
// null response, when the query fails.
func TestRunQueryFailure(t *testing.T) {
	port := closedTCPPort(t)

	var stdout, stderr bytes.Buffer
	args := []string{"-s", "127.0.0.1", "-p", strconv.Itoa(int(port)), "-tcp", "example.com"}
	if code := run(args, &stdout, &stderr); code != 1 {
		t.Fatalf("run(%v) exit code = %d, want 1\nstderr: %s", args, code, stderr.String())
	}
	if stderr.Len() == 0 {
		t.Error("run() printed nothing on stderr, want the query error")
	}

	doc := decodeOutput(t, stdout.Bytes())
	if len(doc.Query.QuestionSection) != 1 || doc.Query.QuestionSection[0].QName.String() != "example.com." {
		t.Errorf("query = %v, want the question that was sent", doc.Query.QuestionSection)
	}
	if doc.Response != nil {
		t.Errorf("response = %v, want null", doc.Response)
	}
	if !bytes.Contains(stdout.Bytes(), []byte(`"response": null`)) {
		t.Errorf("the JSON output does not carry a null response:\n%s", stdout.String())
	}
}

// noAnswerListener opens a TCP port that accepts connections and reads what
// they send but never answers, so that a query sent to it has to time out.
func noAnswerListener(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
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

// TestRunNoAnswer checks that a query that is never answered gives up after the
// query timeout instead of waiting forever.
func TestRunNoAnswer(t *testing.T) {
	port := noAnswerListener(t)

	const timeout = 200 * time.Millisecond
	old := queryTimeout
	queryTimeout = timeout
	t.Cleanup(func() { queryTimeout = old })

	var stdout, stderr bytes.Buffer
	args := []string{"-s", "127.0.0.1", "-p", strconv.Itoa(int(port)), "-tcp", "example.com"}

	start := time.Now()
	code := run(args, &stdout, &stderr)
	elapsed := time.Since(start)

	if code != 1 {
		t.Fatalf("run(%v) exit code = %d, want 1\nstderr: %s", args, code, stderr.String())
	}
	if elapsed < timeout {
		t.Errorf("run() returned after %v, before the %v query timeout", elapsed, timeout)
	}
	if elapsed > timeout+2*time.Second {
		t.Errorf("run() returned after %v, want about %v", elapsed, timeout)
	}
	doc := decodeOutput(t, stdout.Bytes())
	if doc.Response != nil {
		t.Errorf("response = %v, want null", doc.Response)
	}
}

// TestRunTimeoutOption checks that -timeout replaces the default query timeout:
// a short -timeout gives up on a server that answers late, and -timeout 0
// keeps waiting for it even though the default timeout is shorter than the
// answer delay.
func TestRunTimeoutOption(t *testing.T) {
	const defaultTimeout = 100 * time.Millisecond
	old := queryTimeout
	queryTimeout = defaultTimeout
	t.Cleanup(func() { queryTimeout = old })

	tests := []struct {
		name     string
		timeout  string
		delay    time.Duration
		wantMin  time.Duration
		wantCode int
		wantResp bool
	}{
		{
			name:     "a short -timeout outlives the default one",
			timeout:  "0.2",
			delay:    600 * time.Millisecond,
			wantMin:  200 * time.Millisecond,
			wantCode: 1,
			wantResp: false,
		},
		{
			name:     "-timeout 0 waits as long as the server takes",
			timeout:  "0",
			delay:    300 * time.Millisecond,
			wantCode: 0,
			wantResp: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port := serveTCP(t, func(q dnsmsg.Message) dnsmsg.Message {
				time.Sleep(tt.delay)
				return stubAnswer(q, 1)
			}, 4096)

			var stdout, stderr bytes.Buffer
			args := []string{"-s", "127.0.0.1", "-p", strconv.Itoa(int(port)), "-tcp",
				"-timeout", tt.timeout, "example.com"}

			start := time.Now()
			code := run(args, &stdout, &stderr)
			elapsed := time.Since(start)

			if code != tt.wantCode {
				t.Fatalf("run(%v) exit code = %d, want %d\nstderr: %s", args, code, tt.wantCode, stderr.String())
			}
			doc := decodeOutput(t, stdout.Bytes())
			if (doc.Response != nil) != tt.wantResp {
				t.Errorf("response present = %v, want %v\n%s", doc.Response != nil, tt.wantResp, stdout.String())
			}
			if tt.wantCode == 1 {
				// The default timeout is shorter than -timeout, so reaching the
				// -timeout deadline means the option replaced it.
				if elapsed < tt.wantMin {
					t.Errorf("run() gave up after %v, before the %v -timeout", elapsed, tt.wantMin)
				}
				if elapsed > tt.delay {
					t.Errorf("run() returned after %v, want about %v", elapsed, tt.wantMin)
				}
			}
			if tt.wantCode == 0 && elapsed < tt.delay {
				t.Errorf("run() returned after %v, before the %v the server took to answer", elapsed, tt.delay)
			}
		})
	}
}

func TestRunUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-o", "yaml", "example.com"}, &stdout, &stderr); code != 2 {
		t.Errorf("run() exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "dq:") {
		t.Errorf("run() printed %q on stderr, want an error prefixed with dq:", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("run() printed %q on stdout, want nothing", stdout.String())
	}
}

func TestFirstNameserver(t *testing.T) {
	path := tempResolvConf(t, "", "# nameserver 10.0.0.1", "nameserver 192.0.2.53", "nameserver 192.0.2.54")
	got, err := firstNameserver(path)
	if err != nil {
		t.Fatalf("firstNameserver(): %v", err)
	}
	if got != "192.0.2.53" {
		t.Errorf("firstNameserver() = %q, want 192.0.2.53", got)
	}

	path = tempResolvConf(t, "search example.org", "options ndots:1")
	if _, err := firstNameserver(path); err == nil {
		t.Error("firstNameserver() with no nameserver entry returned no error")
	}

	if _, err := firstNameserver("tmp/does-not-exist/resolv.conf"); err == nil {
		t.Error("firstNameserver() with a missing file returned no error")
	}
}

// TestUsageOptions checks that the usage text names every option with a single
// "-", states the -timeout default that parseArgs actually uses, and names every
// output format that parseArgs accepts.
func TestUsageOptions(t *testing.T) {
	if queryTimeout != dnsmsg.DefaultQueryTimeout {
		t.Errorf("queryTimeout = %v, want the documented default %v", queryTimeout, dnsmsg.DefaultQueryTimeout)
	}

	for _, name := range []string{"tcp", "udp", "edns", "no-edns", "nsid", "timeout"} {
		if !strings.Contains(usage, "  -"+name) {
			t.Errorf("usage does not list -%s", name)
		}
		if strings.Contains(usage, "--"+name) {
			t.Errorf("usage lists --%s, want -%s", name, name)
		}
	}

	if strings.Contains(usage, "--") {
		t.Errorf("usage contains a doubled \"-\": %s", usage)
	}

	wantDefault := "(既定: " + strconv.Itoa(int(queryTimeout.Seconds())) + ")"
	if !strings.Contains(usage, wantDefault) {
		t.Errorf("usage does not state the -timeout default %q", wantDefault)
	}

	oLine := ""
	for _, line := range strings.Split(usage, "\n") {
		if strings.HasPrefix(line, "  -o ") {
			oLine = line
		}
	}
	if oLine == "" {
		t.Fatal("usage does not list -o")
	}
	for _, name := range formatNames() {
		if !strings.Contains(oLine, name) {
			t.Errorf("the -o line %q does not name the output format %q", oLine, name)
		}
	}
	if !strings.Contains(oLine, defaultOutput) {
		t.Errorf("the -o line %q does not state the default output format %q", oLine, defaultOutput)
	}
}
