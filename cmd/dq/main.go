// Command dq sends a DNS query to a name server and prints, in the requested
// output format, both the query message it sent and the response message it
// received.
//
// The query is built from the command line options: the domain name is the
// single positional argument, and -c and -t select the QCLASS and QTYPE.  The
// messages are printed exactly as they were sent and received; dq does not
// retry a truncated (TC=1) answer over another transport.
//
// The output formats are the values of the outputFormat interface registered in
// outputFormats: json prints the parsed messages, base64 prints the octets they
// had on the wire.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sischkg/dnsmsg"
)

const (
	defaultPort   = 53
	defaultQClass = "IN"
	defaultQType  = "A"
	defaultOutput = "json"

	// fallbackServer is used when -s is not given and no name server can be
	// read from the resolver configuration.
	fallbackServer = "127.0.0.1"
)

// resolvConfPath is the resolver configuration that the default name server is
// read from.  It is a variable so that tests can point it at a scratch file.
var resolvConfPath = "/etc/resolv.conf"

// queryTimeout is the default value of -timeout: how long a query waits for a
// reply.  It is a variable so that tests can shorten it.
var queryTimeout = dnsmsg.DefaultQueryTimeout

const usage = `usage: dq [options] <domain-name>

  -s <server>   問い合わせ先サーバのアドレスまたはホスト名
                (既定: /etc/resolv.conf の最初の nameserver)
  -p <port>     問い合わせ先のポート番号 (既定: 53)
  -c <class>    QCLASS (既定: IN)
  -t <type>     QTYPE (既定: A)
  -r            RD=1 (再帰的問い合わせ) を設定する
  -tcp          トランスポートに TCP を使う
  -udp          トランスポートに UDP を使う (既定)
  -o <format>   出力形式: json または base64 (既定: json)
  -edns         EDNS0 を問い合わせに含める (既定)
  -no-edns      EDNS0 を問い合わせに含めない
  -nsid         問い合わせに長さ 0 の NSID オプションを含める
  -timeout <n>  接続・送信・応答待ちの上限を秒で指定する (既定: 5)
                0 は無制限
`

// options is the parsed command line.  transport is not an option of its own:
// it is derived from -tcp and -udp.  timeout is the query timeout, which is
// queryTimeout unless -timeout gives another value.
type options struct {
	server    string
	port      uint16
	qclass    string
	qtype     string
	rd        bool
	output    string
	edns      bool
	nsid      bool
	name      string
	transport string
	timeout   time.Duration
}

// valueFlags are the options that take their value from the argument that
// follows them.
var valueFlags = map[string]bool{"s": true, "p": true, "c": true, "t": true, "o": true, "timeout": true}

// reorderArgs moves options to the front of args so that "dq example.com -r"
// means the same thing as "dq -r example.com", as it does for dig.  Everything
// after a "--" separator is a positional argument.
func reorderArgs(args []string) []string {
	opts := []string{}
	names := []string{}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			// The separator is kept in front of the positional arguments:
			// flag.Parse stops there, so that a domain name that looks like an
			// option ("-example.com") is still taken as a name.
			return append(append(append(opts, "--"), names...), args[i+1:]...)
		}
		if len(arg) > 1 && arg[0] == '-' {
			name := strings.TrimLeft(arg, "-")
			if j := strings.IndexByte(name, '='); j >= 0 {
				name = name[:j]
			}
			opts = append(opts, arg)
			if valueFlags[name] && i+1 < len(args) {
				i++
				opts = append(opts, args[i])
			}
			continue
		}
		names = append(names, arg)
	}

	return append(opts, names...)
}

// parseArgs parses args as the dq command line.  Usage errors are reported on
// stderr, and flag.ErrHelp is returned unchanged for -h.
func parseArgs(args []string, stderr io.Writer) (*options, error) {
	fs := flag.NewFlagSet("dq", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { io.WriteString(stderr, usage) }

	var (
		server  = fs.String("s", "", "問い合わせ先サーバのアドレスまたはホスト名")
		port    = fs.Uint("p", defaultPort, "問い合わせ先のポート番号")
		qclass  = fs.String("c", defaultQClass, "QCLASS")
		qtype   = fs.String("t", defaultQType, "QTYPE")
		rd      = fs.Bool("r", false, "RD=1 を設定する")
		tcp     = fs.Bool("tcp", false, "TCP を使う")
		udp     = fs.Bool("udp", false, "UDP を使う")
		output  = fs.String("o", defaultOutput, "出力形式")
		edns    = fs.Bool("edns", true, "EDNS0 を使う")
		noEDNS  = fs.Bool("no-edns", false, "EDNS0 を使わない")
		nsid    = fs.Bool("nsid", false, "NSID オプションを含める")
		timeout = fs.Float64("timeout", queryTimeout.Seconds(), "応答を待つ時間（秒）")
	)

	if err := fs.Parse(reorderArgs(args)); err != nil {
		return nil, err
	}

	// Only options the command line actually carries count as given, so that
	// the defaults of -edns and -udp do not look like conflicts.
	given := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })

	if fs.NArg() != 1 {
		fs.Usage()
		return nil, errors.New("ドメイン名を 1 つ指定してください")
	}
	if given["tcp"] && given["udp"] {
		return nil, errors.New("-tcp と -udp は同時に指定できません")
	}
	if given["edns"] && given["no-edns"] {
		return nil, errors.New("-edns と -no-edns は同時に指定できません")
	}
	if *nsid && *noEDNS {
		return nil, errors.New("-nsid は -no-edns と同時に指定できません")
	}
	if *port == 0 || *port > 65535 {
		return nil, fmt.Errorf("ポート番号 %d が範囲外です", *port)
	}
	if _, ok := outputFormats[*output]; !ok {
		return nil, fmt.Errorf("出力形式 %q には対応していません (%s のみ)", *output, strings.Join(formatNames(), ", "))
	}
	if *timeout < 0 {
		return nil, fmt.Errorf("-timeout %v は 0 秒以上で指定してください", *timeout)
	}

	o := &options{
		server:    *server,
		qclass:    *qclass,
		qtype:     *qtype,
		rd:        *rd,
		output:    *output,
		edns:      *edns && !*noEDNS,
		nsid:      *nsid,
		name:      fs.Arg(0),
		transport: dnsmsg.DNSoverUDP,
		// A zero timeout means "no timeout", which is what SendQueryWithTimeout
		// does with a timeout that is not positive.  The addition rounds the
		// number of nanoseconds to the nearest integer.
		timeout: time.Duration(*timeout*float64(time.Second) + 0.5),
	}
	if *tcp {
		o.transport = dnsmsg.DNSoverTCP
	} else if *udp {
		o.transport = dnsmsg.DNSoverUDP
	}
	o.port = uint16(*port)
	return o, nil
}

// parseQClass parses a QCLASS given on the command line: the names dnsmsg
// knows, such as IN, or a decimal number such as 255.
func parseQClass(s string) (dnsmsg.ResourceClass, error) {
	class, err := dnsmsg.NewClass(s)
	if err == nil {
		return class, nil
	}
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("QCLASS %q が分かりません", s)
	}
	return dnsmsg.ResourceClass(n), nil
}

// parseQType parses a QTYPE given on the command line: the names dnsmsg knows,
// such as A or DNSKEY, or a decimal number such as 15.
func parseQType(s string) (dnsmsg.ResourceType, error) {
	t, err := dnsmsg.NewType(s)
	if err == nil {
		return t, nil
	}
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("QTYPE %q が分かりません", s)
	}
	return dnsmsg.ResourceType(n), nil
}

// buildQuery builds the query message that dq sends: a one-question query for
// name with the QCLASS, QTYPE, and RD flag of o, and an OPT pseudo-record when
// EDNS0 is enabled.
func buildQuery(o *options, name string, id uint16) (dnsmsg.Message, error) {
	var msg dnsmsg.Message
	msg.ID = id
	msg.QR = dnsmsg.QRQuery
	msg.OPCODE = dnsmsg.QpcodeQuery
	if o.rd {
		msg.RD = 1
	}

	qclass, err := parseQClass(o.qclass)
	if err != nil {
		return msg, err
	}
	qtype, err := parseQType(o.qtype)
	if err != nil {
		return msg, err
	}
	if err := msg.SetQuery(name, qclass, qtype); err != nil {
		return msg, err
	}

	if o.edns {
		var opts []dnsmsg.EDNSOption
		if o.nsid {
			// A query-side NSID is an empty option: it asks the name server to
			// report its node id in the response (RFC 7873 Section 3).
			opts = append(opts, dnsmsg.EDNSOptionNSID{})
		}
		msg.SetEDNS0(dnsmsg.EDNS0DefaultPayloadSize, 0, opts...)
	}
	return msg, nil
}

// newMessageID returns a random DNS message ID.
func newMessageID() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("cannot make a message id: %w", err)
	}
	return binary.BigEndian.Uint16(b[:]), nil
}

// firstNameserver returns the first "nameserver" entry of the resolver
// configuration file at path.
func firstNameserver(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %w", path, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			return fields[1], nil
		}
	}
	return "", fmt.Errorf("no nameserver in %s", path)
}

// jsonDocument is the document of the json output format: the message dq sent
// and the message it received.  Response is null when no response was received.
type jsonDocument struct {
	Query    dnsmsg.Message  `json:"query"`
	Response *dnsmsg.Message `json:"response"`
}

// exchange is one query and response exchange, in the form the output formats
// read it.  It is the dnsmsg.QueryExchange of a finished exchange, with the
// response replaced by a pointer so that "no response" has a value of its own.
//
// sentAt is the zero time when nothing was written, and recvAt is the zero time
// when nothing was read.  reply is nil unless a response was parsed, which is
// not the same as recvAt being the zero time: a response that was read but
// could not be parsed is still on the wire, and a format that prints the wire
// can still print it.
type exchange struct {
	transport string
	query     dnsmsg.Message
	queryWire dnsmsg.WireFormat
	sentAt    time.Time
	reply     *dnsmsg.Message
	replyWire dnsmsg.WireFormat
	recvAt    time.Time
}

// newExchange reports the exchange ex as the output formats need it.  err is
// the error Exchange reported for ex, if any.
func newExchange(ex dnsmsg.QueryExchange, err error) *exchange {
	e := &exchange{
		transport: ex.Transport,
		query:     ex.Query,
		queryWire: ex.QueryWire,
		sentAt:    ex.SentAt,
		replyWire: ex.ReplyWire,
		recvAt:    ex.ReceivedAt,
	}
	if err == nil {
		e.reply = &ex.Reply
	}
	return e
}

// outputFormat writes one query and response exchange to w in one of the output
// formats of dq.  A format that has no response to show leaves the response out
// of its output; a format that has nothing at all to show writes nothing.
type outputFormat interface {
	write(w io.Writer, ex *exchange) error
}

// jsonFormat is the json output format: the two messages as the members of one
// JSON document.
type jsonFormat struct{}

func (jsonFormat) write(w io.Writer, ex *exchange) error {
	data, err := json.MarshalIndent(jsonDocument{Query: ex.query, Response: ex.reply}, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot format the messages: %w", err)
	}
	if _, err = w.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("cannot write the messages: %w", err)
	}
	return nil
}

// base64Format is the base64 output format: one line per message, as
//
//	sent,<送信時刻>,<トランスポート>,<DNS メッセージの BASE64>
//	recv,<受信時刻>,<トランスポート>,<DNS メッセージの BASE64>
//
// The times are RFC 3339 times with nanoseconds, the transport is tcp or udp,
// and the message is the base64 of the octets that went on the wire, without
// the two-octet length prefix that TCP adds.  The recv line is left out when no
// response was read.
type base64Format struct{}

func (base64Format) write(w io.Writer, ex *exchange) error {
	var text strings.Builder
	if !ex.sentAt.IsZero() {
		fmt.Fprintf(&text, "sent,%s,%s,%s\n", ex.sentAt.Format(time.RFC3339Nano), ex.transport,
			base64.StdEncoding.EncodeToString(ex.queryWire))
	}
	if !ex.recvAt.IsZero() {
		fmt.Fprintf(&text, "recv,%s,%s,%s\n", ex.recvAt.Format(time.RFC3339Nano), ex.transport,
			base64.StdEncoding.EncodeToString(ex.replyWire))
	}
	if _, err := io.WriteString(w, text.String()); err != nil {
		return fmt.Errorf("cannot write the messages: %w", err)
	}
	return nil
}

// outputFormats are the output formats dq accepts, keyed by the name given to
// -o.  Add an entry here to add an output format.
var outputFormats = map[string]outputFormat{
	"json":   jsonFormat{},
	"base64": base64Format{},
}

// formatNames returns the names of the output formats, in order, for use in a
// message about an unknown one.
func formatNames() []string {
	names := make([]string, 0, len(outputFormats))
	for name := range outputFormats {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// run is the dq command with its streams replaced, so that tests can capture
// what it prints.  It returns the process exit code.
func run(args []string, stdout, stderr io.Writer) int {
	o, err := parseArgs(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(stderr, "dq: %v\n", err)
		return 2
	}

	if o.server == "" {
		server, err := firstNameserver(resolvConfPath)
		if err != nil {
			server = fallbackServer
			fmt.Fprintf(stderr, "dq: %v: %s に問い合わせます\n", err, server)
		} else {
			fmt.Fprintf(stderr, "dq: -s が指定されていないので %s に問い合わせます\n", server)
		}
		o.server = server
	}

	id, err := newMessageID()
	if err != nil {
		fmt.Fprintf(stderr, "dq: %v\n", err)
		return 1
	}
	query, err := buildQuery(o, o.name, id)
	if err != nil {
		fmt.Fprintf(stderr, "dq: %v\n", err)
		return 1
	}

	ex, err := dnsmsg.Exchange(query, o.server, o.port, o.transport, o.timeout)
	if err != nil {
		fmt.Fprintf(stderr, "dq: %v\n", err)
	}
	// The messages are printed even when the exchange failed, because the query
	// side of a failed exchange is still the message dq sent.
	if werr := outputFormats[o.output].write(stdout, newExchange(ex, err)); werr != nil {
		fmt.Fprintf(stderr, "dq: %v\n", werr)
		return 1
	}
	if err != nil {
		return 1
	}
	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
