package dnsmsg

import (
	"bytes"
	"encoding/hex"
	"reflect"
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
			name:    "EDNS0 DO",
			input:   []byte{0x00, 0x80, 0x00}, // Version 0, Flags DO
			begin:   0,
			end:     3,
			want:    NewRecordOPT(0, 0x8000),
			wantEnd: 3,
		},
		{
			name:    "EDNS0 options",
			input:   []byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x05, 'e', 'd', 'n', 's', 'x'}, // Version 0, Flags 0, DNSSEC, NSID "ednsx"
			begin:   0,
			end:     16,
			want:    NewRecordOPT(0, 0, EDNSOptionDNSSEC{}, EDNSOptionNSID{ID: "ednsx"}),
			wantEnd: 16,
		},
		{
			name:    "client subnet option",
			input:   []byte{0x00, 0x80, 0x00, 0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x01, 0x18, 0x01, 0xc6, 0x33, 0x64}, // Version 0, Flags DO, ECS 198.51.100.0/24
			begin:   0,
			end:     15,
			want:    NewRecordOPT(0, 0x8000, EDNSOptionRaw{OptionCode: 8, OptionData: []byte{0x00, 0x00, 0x01, 0x18, 0x01, 0xc6, 0x33, 0x64}}),
			wantEnd: 15,
		},
		{
			name:    "begin offset",
			input:   []byte{0xff, 0x00, 0x80, 0x00, 0xff}, // junk before RDATA
			begin:   1,
			end:     4,
			want:    NewRecordOPT(0, 0x8000),
			wantEnd: 4,
		},
		{
			name:    "not enough size",
			input:   []byte{0x00, 0x80},
			begin:   0,
			end:     5,
			want:    RecordOPT{},
			wantErr: true,
		},
		{
			name:    "truncated option",
			input:   []byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x00},
			begin:   0,
			end:     6,
			want:    RecordOPT{},
			wantErr: true,
		},
		{
			name:    "option length exceeds RDATA",
			input:   []byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x50},
			begin:   0,
			end:     7,
			want:    RecordOPT{},
			wantErr: true,
		},
		{
			name:    "version mismatch",
			input:   []byte{0x00, 0x00, 0x01}, // Version 0 but flags carry EDNS version 1
			begin:   0,
			end:     3,
			want:    RecordOPT{},
			wantErr: true,
		},
		{
			name:    "end beyond message size",
			input:   []byte{0x00, 0x80, 0x00},
			begin:   0,
			end:     10,
			want:    RecordOPT{},
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   []byte{},
			begin:   0,
			end:     0,
			want:    RecordOPT{},
			wantEnd: 0,
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
	r := NewRecordOPT(0, 0x8000, EDNSOptionNSID{ID: "abcd"})
	w := new(WireFormat)
	db := NewNameCompressionDB()

	r.AppendWireFormat(w, db)

	expected := []byte{0x00, 0x80, 0x00, 0x00, 0x03, 0x00, 0x04, 'a', 'b', 'c', 'd'}
	if !bytes.Equal(*w, expected) {
		t.Errorf("RecordOPT.AppendWireFormat() = %v, want %v", *w, expected)
	}
}

func TestRecordOPT_CanonicalWireFormat(t *testing.T) {
	r := NewRecordOPT(0, 0x8000)
	expected := []byte{0x00, 0x80, 0x00}
	if !bytes.Equal(r.CanonicalWireFormat(), expected) {
		t.Errorf("RecordOPT.CanonicalWireFormat() = %v, want %v", r.CanonicalWireFormat(), expected)
	}
}

func TestRecordOPT_RoundTripsInResourceRecord(t *testing.T) {
	rr := ResourceRecord{
		Name:  testDomainName(t, "."),
		Class: CLASS_IN,
		Type:  TYPE_OPT,
		TTL:   1232, // EDNS(0) UDP payload size
		RData: NewRecordOPT(0, 0x8000),
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

	w := new(WireFormat)
	r.AppendWireFormat(w, NewNameCompressionDB())

	got, pos, err := ParseRecordOPT(*w, 0, uint32(w.Size()))
	if err != nil {
		t.Fatalf("ParseRecordOPT() error = %v", err)
	}
	if pos != uint32(w.Size()) {
		t.Fatalf("ParseRecordOPT() pos = %d, want %d", pos, w.Size())
	}
	if len(got.Options) != 1 {
		t.Fatalf("parsed %d options, want 1", len(got.Options))
	}

	parsed, ok := got.Options[0].(EDNSOptionNSID)
	if !ok {
		t.Fatalf("option is %T, want EDNSOptionNSID", got.Options[0])
	}
	if parsed.ID != nsid.ID {
		t.Errorf("NSID ID = %q, want %q", parsed.ID, nsid.ID)
	}
	if s := parsed.String(); s != "NSID 65646e7378" {
		t.Errorf("NSID String() = %q, want %q", s, "NSID 65646e7378")
	}
	if got.String() != "8000 NSID 65646e7378" {
		t.Errorf("RecordOPT String() = %q, want %q", got.String(), "8000 NSID 65646e7378")
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
	expected := []byte{0x00, 0x80, 0x00, 0x00, 0x64, 0x00, 0x02, 'h', 'i'}
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
