package dnsmsg

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

func TestParseRecordOPT(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		begin   uint32
		end     uint32
		want    RecordOPT
		wantEnd uint32
		wantErr bool
	}{
		{
			name:    "no options",
			input:   []byte{}, // RDLENGTH 0: an OPT record with no EDNS options
			begin:   0,
			end:     0,
			want:    NewRecordOPT(0, 0),
			wantEnd: 0,
		},
		{
			name:    "EDNS0 options",
			input:   []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x05, 'e', 'd', 'n', 's', 'x'}, // DNSSEC, NSID "ednsx"
			begin:   0,
			end:     13,
			want:    NewRecordOPT(0, 0, EDNSOptionDNSSEC{}, EDNSOptionNSID{ID: "ednsx"}),
			wantEnd: 13,
		},
		{
			name:    "EDE option with extra text",
			input:   []byte{0x00, 0x0f, 0x00, 0x07, 0x00, 0x06, 'b', 'o', 'g', 'u', 's'}, // EDE code 6 "bogus"
			begin:   0,
			end:     11,
			want:    NewRecordOPT(0, 0, NewEDNSOptionEDE(6, "bogus")),
			wantEnd: 11,
		},
		{
			name:    "EDE option with empty extra text",
			input:   []byte{0x00, 0x0f, 0x00, 0x02, 0x00, 0x13}, // EDE code 19
			begin:   0,
			end:     6,
			want:    NewRecordOPT(0, 0, NewEDNSOptionEDE(19, "")),
			wantEnd: 6,
		},
		{
			name:    "truncated EDE option",
			input:   []byte{0x00, 0x0f, 0x00, 0x01, 0x41}, // EDE with a 1-byte payload
			begin:   0,
			end:     5,
			want:    NewRecordOPT(0, 0, EDNSOptionRaw{OptionCode: 15, OptionData: []byte{0x41}}),
			wantEnd: 5,
		},
		{
			name:    "client subnet option",
			input:   []byte{0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x01, 0x18, 0x01, 0xc6, 0x33, 0x64}, // ECS 198.51.100.0/24
			begin:   0,
			end:     12,
			want:    NewRecordOPT(0, 0, EDNSOptionRaw{OptionCode: 8, OptionData: []byte{0x00, 0x00, 0x01, 0x18, 0x01, 0xc6, 0x33, 0x64}}),
			wantEnd: 12,
		},
		{
			name:    "begin offset",
			input:   []byte{0xff, 0x00, 0x01, 0x00, 0x00, 0xff}, // junk before and after RDATA
			begin:   1,
			end:     5,
			want:    NewRecordOPT(0, 0, EDNSOptionDNSSEC{}),
			wantEnd: 5,
		},
		{
			name:    "truncated option",
			input:   []byte{0x00, 0x01, 0x00},
			begin:   0,
			end:     3,
			want:    RecordOPT{},
			wantErr: true,
		},
		{
			name:    "option length exceeds RDATA",
			input:   []byte{0x00, 0x01, 0x00, 0x50},
			begin:   0,
			end:     4,
			want:    RecordOPT{},
			wantErr: true,
		},
		{
			name:    "option data exceeds RDATA",
			input:   []byte{0x00, 0x03, 0x00, 0x05, 'e', 'd', 'n'},
			begin:   0,
			end:     7,
			want:    RecordOPT{},
			wantErr: true,
		},
		{
			name:    "end beyond message size",
			input:   []byte{0x00, 0x03, 0x00, 0x00},
			begin:   0,
			end:     10,
			want:    RecordOPT{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, end, err := ParseRecordOPT(tt.input, tt.begin, tt.end)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRecordOPT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseRecordOPT() got = %v, want %v", got, tt.want)
			}
			if end != tt.wantEnd {
				t.Errorf("ParseRecordOPT() end = %v, want %v", end, tt.wantEnd)
			}
		})
	}
}

func TestNewRecordOPTFromString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    RecordOPT
		wantErr bool
	}{
		{
			name:  "DO",
			input: "0x8000",
			want:  NewRecordOPT(0, 0x8000),
		},
		{
			name:  "decimal flags",
			input: "32768",
			want:  NewRecordOPT(0, 0x8000),
		},
		{
			name:  "DNSSEC option",
			input: "0x8000 DO",
			want:  NewRecordOPT(0, 0x8000, EDNSOptionDNSSEC{}),
		},
		{
			name:  "NSID option",
			input: "0x0000 3 43444546", // 3 NSID "CDEF"
			want:  NewRecordOPT(0, 0, EDNSOptionNSID{ID: "CDEF"}),
		},
		{
			name:  "EDE option",
			input: "0x8000 15 0006626f677573", // 15 EDE code 6 "bogus"
			want:  NewRecordOPT(0, 0x8000, NewEDNSOptionEDE(6, "bogus")),
		},
		{
			name:    "option code without data",
			input:   "0x8000 DO 3",
			want:    RecordOPT{},
			wantErr: true,
		},
		{
			name:    "invalid flags",
			input:   "bad",
			want:    RecordOPT{},
			wantErr: true,
		},
		{
			name:    "invalid option code",
			input:   "0x8000 xx 4142",
			want:    RecordOPT{},
			wantErr: true,
		},
		{
			name:    "invalid option data",
			input:   "0x8000 42 4142 zz",
			want:    RecordOPT{},
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   "",
			want:    RecordOPT{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewRecordOPTFromString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewRecordOPTFromString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewRecordOPTFromString() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRecordOPT_String(t *testing.T) {
	tests := []struct {
		name string
		opt  RecordOPT
		want string
	}{
		{
			name: "DO",
			opt:  NewRecordOPT(0, 0x8000),
			want: "8000",
		},
		{
			name: "options",
			opt:  NewRecordOPT(0, 0, EDNSOptionDNSSEC{}, EDNSOptionNSID{ID: "CDEF"}),
			want: "0000 DO NSID 43444546",
		},
		{
			name: "EDE with extra text",
			opt:  NewRecordOPT(0, 0x8000, NewEDNSOptionEDE(6, "bogus")),
			want: `8000 EDE 6 "bogus"`,
		},
		{
			name: "EDE without extra text",
			opt:  NewRecordOPT(0, 0, NewEDNSOptionEDE(EDECodeStaleNXDOMAINAnswer, "")),
			want: "0000 EDE 19",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.opt.String(); got != tt.want {
				t.Errorf("RecordOPT.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRecordOPT_AppendWireFormat(t *testing.T) {
	// The RDATA of an OPT record holds only the EDNS options: the version
	// and the flags are written in the record's TTL field by
	// AppendResourceRecord (RFC 6891 Section 6.1.2 and 6.1.3).
	r := NewRecordOPT(0, 0x8000, EDNSOptionNSID{ID: "abcd"})
	w := new(WireFormat)
	db := NewNameCompressionDB()

	size := r.AppendWireFormat(w, db)

	expected := []byte{0x00, 0x03, 0x00, 0x04, 'a', 'b', 'c', 'd'}
	if !bytes.Equal(*w, expected) {
		t.Errorf("RecordOPT.AppendWireFormat() = %v, want %v", *w, expected)
	}
	if size != uint32(len(expected)) {
		t.Errorf("RecordOPT.AppendWireFormat() size = %d, want %d", size, len(expected))
	}
}

func TestRecordOPT_CanonicalWireFormat(t *testing.T) {
	tests := []struct {
		name string
		opt  RecordOPT
		want []byte
	}{
		{
			name: "no options",
			opt:  NewRecordOPT(0, 0x8000),
			want: []byte{},
		},
		{
			name: "options",
			opt:  NewRecordOPT(0, 0x8000, EDNSOptionDNSSEC{}, EDNSOptionNSID{ID: "abcd"}),
			want: []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x04, 'a', 'b', 'c', 'd'},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.opt.CanonicalWireFormat()
			if !bytes.Equal(got, tt.want) {
				t.Errorf("RecordOPT.CanonicalWireFormat() = %v, want %v", got, tt.want)
			}
			w := new(WireFormat)
			tt.opt.AppendCanonicalWireFormat(w)
			if !bytes.Equal(*w, tt.want) {
				t.Errorf("RecordOPT.AppendCanonicalWireFormat() = %v, want %v", *w, tt.want)
			}
		})
	}
}

// TestOPTRecord_WireFields checks the translation between the OPT record's
// wire fields and the RecordOPT struct that AppendResourceRecord and
// ParseResourceRecord apply (RFC 6891 Section 6.1.1 and 6.1.3).
func TestOPTRecord_WireFields(t *testing.T) {
	tests := []struct {
		name string
		rr   ResourceRecord
		want string // the whole record as it must appear on the wire
	}{
		{
			// The OPT record this package builds for a query: the payload
			// size 1232 (0x04d0) is written in the CLASS field, the version
			// and flags in the TTL field, and the NSID option in the RDATA.
			name: "query with NSID option",
			rr: ResourceRecord{
				Name:  testDomainName(t, "."),
				Class: CLASS_IN,
				Type:  TYPE_OPT,
				TTL:   1232,
				RData: NewRecordOPT(0, 0, EDNSOptionNSID{}),
			},
			want: "00 00 29 04 d0 00 00 00 00 00 04 00 03 00 00",
		},
		{
			// The OPT record a server that supports EDNS(0) but sends no
			// options answers with, which is what a real server puts in a
			// reply to a query that asks for EDNS(0).
			name: "reply with no options",
			rr: ResourceRecord{
				Name:  testDomainName(t, "."),
				Class: CLASS_IN,
				Type:  TYPE_OPT,
				TTL:   1232,
				RData: NewRecordOPT(0, 0),
			},
			want: "00 00 29 04 d0 00 00 00 00 00 00",
		},
		{
			name: "DO bit and version 0",
			rr: ResourceRecord{
				Name:  testDomainName(t, "."),
				Class: CLASS_IN,
				Type:  TYPE_OPT,
				TTL:   512,
				RData: NewRecordOPT(0, EDNS0FlagDO),
			},
			want: "00 00 29 02 00 00 00 80 00 00 00",
		},
		{
			name: "EDNS version 1",
			rr: ResourceRecord{
				Name:  testDomainName(t, "."),
				Class: CLASS_IN,
				Type:  TYPE_OPT,
				TTL:   1232,
				RData: NewRecordOPT(1, 0),
			},
			want: "00 00 29 04 d0 00 01 00 00 00 00",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := new(WireFormat)
			AppendResourceRecord(w, tt.rr, NewNameCompressionDB())

			want, err := hex.DecodeString(strings.ReplaceAll(tt.want, " ", ""))
			if err != nil {
				t.Fatalf("bad test fixture: %v", err)
			}
			if !bytes.Equal(*w, want) {
				t.Errorf("AppendResourceRecord() = %s, want %s",
					hex.EncodeToString(*w), tt.want)
			}

			got, end, err := ParseResourceRecord(*w, 0)
			if err != nil {
				t.Fatalf("ParseResourceRecord() error = %v", err)
			}
			if end != uint32(w.Size()) {
				t.Errorf("ParseResourceRecord() end = %d, want %d", end, w.Size())
			}
			if got.Name.String() != tt.rr.Name.String() {
				t.Errorf("parsed name = %q, want %q", got.Name.String(), tt.rr.Name.String())
			}
			if got.Type != TYPE_OPT {
				t.Errorf("parsed type = %v, want TYPE_OPT", got.Type)
			}
			// The record is normalized to the form this package uses in
			// memory: Class CLASS_IN and TTL set to the UDP payload size.
			if got.Class != CLASS_IN {
				t.Errorf("parsed class = %v, want CLASS_IN", got.Class)
			}
			if got.TTL != tt.rr.TTL {
				t.Errorf("parsed TTL = %d, want %d (the UDP payload size)", got.TTL, tt.rr.TTL)
			}
			opt, ok := got.RData.(RecordOPT)
			if !ok {
				t.Fatalf("RData is %T, want RecordOPT", got.RData)
			}
			wantOpt := tt.rr.RData.(RecordOPT)
			if opt.Version != wantOpt.Version {
				t.Errorf("parsed version = %d, want %d", opt.Version, wantOpt.Version)
			}
			if opt.Flags != wantOpt.Flags {
				t.Errorf("parsed flags = %#04x, want %#04x", opt.Flags, wantOpt.Flags)
			}
			if !reflect.DeepEqual(opt.Options, wantOpt.Options) {
				t.Errorf("parsed options = %v, want %v", opt.Options, wantOpt.Options)
			}
		})
	}
}

// TestParseOPTRecord_ServerReply parses the exact OPT record a EDNS(0)
// capable server answers with: RDLENGTH 0, and the requestor's UDP payload
// size in the CLASS field.
func TestParseOPTRecord_ServerReply(t *testing.T) {
	wire, err := hex.DecodeString("00002904d0000000000000")
	if err != nil {
		t.Fatal(err)
	}

	rr, end, err := ParseResourceRecord(wire, 0)
	if err != nil {
		t.Fatalf("ParseResourceRecord() error = %v", err)
	}
	if end != uint32(len(wire)) {
		t.Errorf("ParseResourceRecord() end = %d, want %d", end, len(wire))
	}
	if rr.TTL != 1232 {
		t.Errorf("rr.TTL = %d, want 1232 (the CLASS field is the UDP payload size)", rr.TTL)
	}
	opt, ok := rr.RData.(RecordOPT)
	if !ok {
		t.Fatalf("RData is %T, want RecordOPT", rr.RData)
	}
	if opt.Version != 0 || opt.Flags != 0 {
		t.Errorf("parsed OPT = version %d flags %#04x, want version 0 flags 0000", opt.Version, opt.Flags)
	}
	if len(opt.Options) != 0 {
		t.Errorf("parsed %d EDNS options, want 0", len(opt.Options))
	}
}

func TestRecordOPT_RoundTripsInResourceRecord(t *testing.T) {
	rr := ResourceRecord{
		Name:  testDomainName(t, "."),
		Class: CLASS_IN,
		Type:  TYPE_OPT,
		TTL:   1232, // EDNS(0) UDP payload size
		RData: NewRecordOPT(0, 0x8000, EDNSOptionNSID{ID: "abcd"}),
	}

	w := new(WireFormat)
	db := NewNameCompressionDB()
	AppendResourceRecord(w, rr, db)

	got, _, err := ParseResourceRecord(*w, 0)
	if err != nil {
		t.Fatalf("ParseResourceRecord() error = %v", err)
	}
	opt, ok := got.RData.(RecordOPT)
	if !ok {
		t.Fatalf("RData is %T, want RecordOPT", got.RData)
	}
	if !reflect.DeepEqual(opt, rr.RData.(RecordOPT)) {
		t.Errorf("round trip OPT = %v, want %v", opt, rr.RData)
	}
}

func TestEDNSOptionNSID_RoundTrip(t *testing.T) {
	nsid, err := NewEDNSOptionNSID("ednsx")
	if err != nil {
		t.Fatalf("NewEDNSOptionNSID() error = %v", err)
	}

	r := NewRecordOPT(EDNS0Version, EDNS0FlagDO, nsid)

	// The version and the flags travel in the record's TTL field, so the
	// round trip is taken through a complete OPT resource record.
	rr := ResourceRecord{
		Name:  testDomainName(t, "."),
		Class: CLASS_IN,
		Type:  TYPE_OPT,
		TTL:   EDNS0DefaultPayloadSize,
		RData: r,
	}

	w := new(WireFormat)
	AppendResourceRecord(w, rr, NewNameCompressionDB())

	got, pos, err := ParseResourceRecord(*w, 0)
	if err != nil {
		t.Fatalf("ParseResourceRecord() error = %v", err)
	}
	if pos != uint32(w.Size()) {
		t.Fatalf("ParseResourceRecord() pos = %d, want %d", pos, w.Size())
	}
	gotOpt, ok := got.RData.(RecordOPT)
	if !ok {
		t.Fatalf("RData is %T, want RecordOPT", got.RData)
	}
	if len(gotOpt.Options) != 1 {
		t.Fatalf("parsed %d options, want 1", len(gotOpt.Options))
	}

	parsed, ok := gotOpt.Options[0].(EDNSOptionNSID)
	if !ok {
		t.Fatalf("option is %T, want EDNSOptionNSID", gotOpt.Options[0])
	}
	if parsed.ID != nsid.ID {
		t.Errorf("NSID ID = %q, want %q", parsed.ID, nsid.ID)
	}
	if s := parsed.String(); s != "NSID 65646e7378" {
		t.Errorf("NSID String() = %q, want %q", s, "NSID 65646e7378")
	}
	if gotOpt.String() != "8000 NSID 65646e7378" {
		t.Errorf("RecordOPT String() = %q, want %q", gotOpt.String(), "8000 NSID 65646e7378")
	}
}

func TestEDNSOptionEDE_RoundTrip(t *testing.T) {
	e := NewEDNSOptionEDE(EDECodeDNSSECBogus, "bogus RRSIG")

	r := NewRecordOPT(EDNS0Version, EDNS0FlagDO, e)

	// The version and the flags travel in the record's TTL field, so the
	// round trip is taken through a complete OPT resource record.
	rr := ResourceRecord{
		Name:  testDomainName(t, "."),
		Class: CLASS_IN,
		Type:  TYPE_OPT,
		TTL:   EDNS0DefaultPayloadSize,
		RData: r,
	}

	w := new(WireFormat)
	AppendResourceRecord(w, rr, NewNameCompressionDB())

	got, pos, err := ParseResourceRecord(*w, 0)
	if err != nil {
		t.Fatalf("ParseResourceRecord() error = %v", err)
	}
	if pos != uint32(w.Size()) {
		t.Fatalf("ParseResourceRecord() pos = %d, want %d", pos, w.Size())
	}
	gotOpt, ok := got.RData.(RecordOPT)
	if !ok {
		t.Fatalf("RData is %T, want RecordOPT", got.RData)
	}
	if len(gotOpt.Options) != 1 {
		t.Fatalf("parsed %d options, want 1", len(gotOpt.Options))
	}

	parsed, ok := gotOpt.Options[0].(EDNSOptionEDE)
	if !ok {
		t.Fatalf("option is %T, want EDNSOptionEDE", gotOpt.Options[0])
	}
	if parsed.ErrorCode != EDECodeDNSSECBogus {
		t.Errorf("EDE ErrorCode = %d, want %d", parsed.ErrorCode, EDECodeDNSSECBogus)
	}
	if parsed.ExtraText != "bogus RRSIG" {
		t.Errorf("EDE ExtraText = %q, want %q", parsed.ExtraText, "bogus RRSIG")
	}
	if s := parsed.String(); s != `EDE 6 "bogus RRSIG"` {
		t.Errorf("EDE String() = %q, want %q", s, `EDE 6 "bogus RRSIG"`)
	}
	if gotOpt.String() != `8000 EDE 6 "bogus RRSIG"` {
		t.Errorf("RecordOPT String() = %q, want %q", gotOpt.String(), `8000 EDE 6 "bogus RRSIG"`)
	}
}

// customEDNSOption is a library-user-defined option that satisfies the
// EDNSOption interface. It proves that new EDNS(0) options can be
// registered and carried through serialization, presentation format and
// parsing without changing this package's core record handling.
type customEDNSOption struct {
	payload []byte
}

func (customEDNSOption) Code() uint16 {
	return 100 // 0x64, a code not handled by this library's own registry
}
func (o customEDNSOption) Data() []byte {
	return o.payload
}
func (o customEDNSOption) String() string {
	return "CUSTOM " + hex.EncodeToString(o.payload)
}

func TestCustomEDNSOption(t *testing.T) {
	opt := customEDNSOption{payload: []byte("hi")}

	// AppendWireFormat must apply the common code(2)+length(2)+data framing
	// using the option's Code() and Data().
	w := new(WireFormat)
	NewRecordOPT(EDNS0Version, EDNS0FlagDO, opt).AppendWireFormat(w, NewNameCompressionDB())
	expected := []byte{0x00, 0x64, 0x00, 0x02, 'h', 'i'}
	if !bytes.Equal(*w, expected) {
		t.Fatalf("wire format = %v, want %v", *w, expected)
	}

	// A parser registered by the user decodes the code back to the custom
	// type when the OPT record is interpreted.
	RegisterEDNSOptionParser(100, func(data []byte) EDNSOption {
		return customEDNSOption{payload: data}
	})

	got, _, err := ParseRecordOPT(*w, 0, uint32(w.Size()))
	if err != nil {
		t.Fatalf("ParseRecordOPT() error = %v", err)
	}
	parsed, ok := got.Options[0].(customEDNSOption)
	if !ok {
		t.Fatalf("option is %T, want customEDNSOption", got.Options[0])
	}
	if !bytes.Equal(parsed.payload, []byte("hi")) {
		t.Errorf("payload = %q, want %q", parsed.payload, "hi")
	}

	fromString, err := NewRecordOPTFromString("8000 100 6869")
	if err != nil {
		t.Fatalf("NewRecordOPTFromString() error = %v", err)
	}
	if _, ok := fromString.Options[0].(customEDNSOption); !ok {
		t.Errorf("from-string option is %T, want customEDNSOption", fromString.Options[0])
	}
}
