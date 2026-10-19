// Command dq sends a DNS query to a name server and prints, in the requested
// output format, both the query message it sent and the response message it
// received.
//
// The query is built from the command line options: the domain name is the
// single positional argument, and -c and -t select the QCLASS and QTYPE.  The
// messages are printed exactly as they were sent and received; dq does not
// retry a truncated (TC=1) answer over another transport.
package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
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

// queryTimeout is how long a query waits for a reply when --timeout is not
// given.  It is a variable so that tests can shorten it.
var queryTimeout = dnsmsg.DefaultQueryTimeout

const usage = `usage: dq [options] <domain-name>

  -s <server>   問い合わせ先サーバのアドレスまたはホスト名
                (既定: /etc/resolv.conf の最初の nameserver)
  -p <port>     問い合わせ先のポート番号 (既定: 53)
  -c <class>    QCLASS (既定: IN)
  -t <type>     QTYPE (既定: A)
  -r            RD=1 (再帰的問い合わせ) を設定する
  --tcp         トランスポートに TCP を使う
  --udp         トランスポートに UDP を使う (既定)
  -o <format>   出力形式 (現在 json のみ)
  --edns        EDNS0 を問い合わせに含める (既定)
  --no-edns     EDNS0 を問い合わせに含めない
  --nsid        問い合わせに長さ 0 の NSID オプションを含める
  --timeout <n> 接続・送信・応答待ちの上限を秒で指定する (既定: 5)
                0 は無制限
`

// options is the parsed command line.  transport is not an option of its own:
// it is derived from --tcp and --udp.  timeout is the query timeout, which
// comes from queryTimeout unless --timeout gives another value.
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
		timeout = fs.Float64("timeout", 0, "応答を待つ時間（秒）")
	)

	if err := fs.Parse(reorderArgs(args)); err != nil {
		return nil, err
	}

	// Only options the command line actually carries count as given, so that
	// the defaults of --edns and --udp do not look like conflicts.
	given := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })

	if fs.NArg() != 1 {
		fs.Usage()
		return nil, errors.New("ドメイン名を 1 つ指定してください")
	}
	if given["tcp"] && given["udp"] {
		return nil, errors.New("--tcp と --udp は同時に指定できません")
	}
	if given["edns"] && given["no-edns"] {
		return nil, errors.New("--edns と --no-edns は同時に指定できません")
	}
	if *nsid && *noEDNS {
		return nil, errors.New("--nsid は --no-edns と同時に指定できません")
	}
	if *port == 0 || *port > 65535 {
		return nil, fmt.Errorf("ポート番号 %d が範囲外です", *port)
	}
	if *output != defaultOutput {
		return nil, fmt.Errorf("出力形式 %q には対応していません (%s のみ)", *output, defaultOutput)
	}
	if given["timeout"] && *timeout < 0 {
		return nil, fmt.Errorf("--timeout %v は 0 秒以上で指定してください", *timeout)
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
		timeout:   queryTimeout,
	}
	if *tcp {
		o.transport = dnsmsg.DNSoverTCP
	} else if *udp {
		o.transport = dnsmsg.DNSoverUDP
	}
	o.port = uint16(*port)
	if given["timeout"] {
		// A zero timeout means "no timeout", which is what SendQueryWithTimeout
		// does with a timeout that is not positive.
		o.timeout = time.Duration(*timeout * float64(time.Second))
	}
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

// outputMessage is what dq prints: the message it sent and the message it
// received.  Response is null when no response was received.
type outputMessage struct {
	Query    dnsmsg.Message  `json:"query"`
	Response *dnsmsg.Message `json:"response"`
}

// emitJSON writes query and reply as the JSON document of the json output
// format.  reply is nil when no response was received.
func emitJSON(w io.Writer, query dnsmsg.Message, reply *dnsmsg.Message) error {
	data, err := json.MarshalIndent(outputMessage{Query: query, Response: reply}, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot format the messages: %w", err)
	}
	if _, err = w.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("cannot write the messages: %w", err)
	}
	return nil
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

	reply, err := dnsmsg.SendQueryWithTimeout(query, o.server, o.port, o.transport, o.timeout)
	if err != nil {
		fmt.Fprintf(stderr, "dq: %v\n", err)
		if e := emitJSON(stdout, query, nil); e != nil {
			fmt.Fprintf(stderr, "dq: %v\n", e)
		}
		return 1
	}

	if err := emitJSON(stdout, query, &reply); err != nil {
		fmt.Fprintf(stderr, "dq: %v\n", err)
		return 1
	}
	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
