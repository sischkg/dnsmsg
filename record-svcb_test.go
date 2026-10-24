package dnsmsg

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

// mustSvcParam returns the SvcParam of the given key and presentation-format
// value, for the SVCB and HTTPS test tables below.  It fails the test if the
// value is not a valid value for the key.
func mustSvcParam(t *testing.T, key SvcParamKey, value string) SvcParam {
	t.Helper()
	p, err := NewSvcParam(key, value)
	if err != nil {
		t.Fatalf("NewSvcParam(%s, %q): %v", key, value, err)
	}
	return p
}

// svcbRDATA is the RDATA the parse tests below read: SvcPriority 1, target name
// "svcb.example.com.", and the alpn and port SvcParams of the example of
// RFC 9460 Section 2.1.
var svcbRDATA = WireFormat{
	0x00, 0x01, // SvcPriority: 1
	0x04, 's', 'v', 'c', 'b', // target name: svcb
	0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // ...example
	0x03, 'c', 'o', 'm', // ...com
	0x00,                   // root label
	0x00, 0x01, 0x00, 0x06, // SvcParamKey=alpn, value of 6 octets
	0x02, 'h', '2', 0x02, 'h', '3', // ALPN IDs "h2" and "h3"
	0x00, 0x03, 0x00, 0x02, // SvcParamKey=port, value of 2 octets
	0x20, 0xFB, // port 8443
}

// svcbWant is the record svcbRDATA is the RDATA of.
func svcbWant(t *testing.T) RecordSVCB {
	t.Helper()
	return RecordSVCB{
		SvcPriority: 1,
		TargetName:  testDomainName(t, "svcb.example.com."),
		SvcParams: []SvcParam{
			{Key: KeyAlpn, Value: []byte{0x02, 'h', '2', 0x02, 'h', '3'}},
			{Key: KeyPort, Value: []byte{0x20, 0xFB}},
		},
	}
}

func TestSvcParamKeyString(t *testing.T) {
	tests := []struct {
		key  SvcParamKey
		want string
	}{
		{KeyMandatory, "mandatory"},
		{KeyAlpn, "alpn"},
		{KeyNoDefaultAlpn, "no-default-alpn"},
		{KeyPort, "port"},
		{KeyIPv4Hint, "ipv4hint"},
		{KeyECH, "ech"},
		{KeyIPv6Hint, "ipv6hint"},
		{SvcParamKey(7), "key7"},
		{SvcParamKey(65535), "key65535"},
	}

	for _, tt := range tests {
		if got := tt.key.String(); got != tt.want {
			t.Errorf("SvcParamKey(%d).String() = %q, want %q", tt.key, got, tt.want)
		}
	}
}

func TestNewSvcParamKey(t *testing.T) {
	tests := []struct {
		input   string
		want    SvcParamKey
		wantErr bool
	}{
		{input: "mandatory", want: KeyMandatory},
		{input: "alpn", want: KeyAlpn},
		{input: "no-default-alpn", want: KeyNoDefaultAlpn},
		{input: "port", want: KeyPort},
		{input: "ipv4hint", want: KeyIPv4Hint},
		{input: "ech", want: KeyECH},
		{input: "ipv6hint", want: KeyIPv6Hint},
		// A key this library does not register is named by its number.
		{input: "key7", want: SvcParamKey(7)},
		{input: "key65535", want: SvcParamKey(65535)},
		// A registered key is read by its number as well.
		{input: "key1", want: KeyAlpn},
		{input: "no-default-alpn-x", wantErr: true},
		{input: "ALPN", wantErr: true},
		{input: "al pn", wantErr: true},
		{input: "zzz", wantErr: true},
		{input: "key", wantErr: true},
		{input: "keyNNNNN", wantErr: true},
		{input: "key65536", wantErr: true},
		{input: "", wantErr: true},
	}

	for _, tt := range tests {
		got, err := NewSvcParamKey(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("NewSvcParamKey(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
		}
		if err == nil && got != tt.want {
			t.Errorf("NewSvcParamKey(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestNewSvcParam(t *testing.T) {
	tests := []struct {
		name  string
		key   SvcParamKey
		value string
		want  []byte
	}{
		{
			name:  "alpn is the sequence of length-prefixed ALPN IDs",
			key:   KeyAlpn,
			value: "h2,h3",
			want:  []byte{0x02, 'h', '2', 0x02, 'h', '3'},
		},
		{
			// NewSvcParam is given the value of Appendix A.1, which is what
			// the character-string decoding of Appendix A produces, so the
			// comma of the ALPN ID "a,b" is the escaped comma "\," here.
			name:  "an escaped comma belongs to the ALPN ID",
			key:   KeyAlpn,
			value: `a\,b`,
			want:  []byte{0x03, 'a', ',', 'b'},
		},
		{
			name:  "port is a 16-bit number",
			key:   KeyPort,
			value: "8443",
			want:  []byte{0x20, 0xFB},
		},
		{
			name:  "no-default-alpn has an empty value",
			key:   KeyNoDefaultAlpn,
			value: "",
			want:  nil,
		},
		{
			// In the presentation format the keys of a mandatory= list may
			// appear in any order, but in the wire format they are the
			// 16-bit key numbers in strictly increasing order.
			name:  "mandatory is the sequence of 16-bit key numbers",
			key:   KeyMandatory,
			value: "port,alpn",
			want:  []byte{0x00, 0x01, 0x00, 0x03},
		},
		{
			name:  "ipv4hint is a sequence of IPv4 addresses",
			key:   KeyIPv4Hint,
			value: "192.0.2.1,192.0.2.2",
			want:  []byte{192, 0, 2, 1, 192, 0, 2, 2},
		},
		{
			name:  "ipv6hint is a sequence of IPv6 addresses",
			key:   KeyIPv6Hint,
			value: "2001:db8::1",
			want: []byte{
				0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 1,
			},
		},
		{
			name:  "the value of an unregistered key is kept as it is given",
			key:   SvcParamKey(7),
			value: "ab",
			want:  []byte{'a', 'b'},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewSvcParam(tt.key, tt.value)
			if err != nil {
				t.Fatalf("NewSvcParam(%s, %q) error = %v", tt.key, tt.value, err)
			}
			if !reflect.DeepEqual(p.Value, tt.want) {
				t.Errorf("NewSvcParam(%s, %q) value = %v, want %v", tt.key, tt.value, p.Value, tt.want)
			}
			if err := p.validate(); err != nil {
				t.Errorf("validate() error = %v", err)
			}
		})
	}
}

func TestNewSvcParamErrors(t *testing.T) {
	tests := []struct {
		name  string
		key   SvcParamKey
		value string
	}{
		{name: "alpn with no ALPN IDs", key: KeyAlpn, value: ""},
		{name: "alpn with an empty item", key: KeyAlpn, value: "h2,,h3"},
		{name: "alpn ending with a comma", key: KeyAlpn, value: "h2,"},
		{name: "alpn with an item above 255 octets", key: KeyAlpn, value: strings.Repeat("x", 256)},
		{name: "mandatory with no key", key: KeyMandatory, value: ""},
		{name: "mandatory with the mandatory key", key: KeyMandatory, value: "mandatory"},
		{name: "mandatory with a key twice", key: KeyMandatory, value: "alpn,alpn"},
		{name: "mandatory with an unknown key", key: KeyMandatory, value: "zzz"},
		{name: "no-default-alpn with a value", key: KeyNoDefaultAlpn, value: "x"},
		{name: "port above 65535", key: KeyPort, value: "65536"},
		{name: "port that is not a number", key: KeyPort, value: "0x21"},
		{name: "negative port", key: KeyPort, value: "-1"},
		{name: "ipv4hint with no address", key: KeyIPv4Hint, value: ""},
		{name: "ipv4hint with an IPv6 address", key: KeyIPv4Hint, value: "2001:db8::1"},
		{name: "ipv4hint with a name", key: KeyIPv4Hint, value: "example.com"},
		{name: "ipv6hint with an IPv4 address", key: KeyIPv6Hint, value: "192.0.2.1"},
		{name: "an empty list item", key: KeyMandatory, value: "alpn,,port"},
		{name: "a list ending with a backslash", key: KeyMandatory, value: "alpn,\\"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewSvcParam(tt.key, tt.value); err == nil {
				t.Errorf("NewSvcParam(%s, %q) did not report an error", tt.key, tt.value)
			}
		})
	}
}

func TestSvcParamValidate(t *testing.T) {
	tests := []struct {
		name    string
		param   SvcParam
		wantErr bool
	}{
		{
			name:  "alpn with a complete sequence of ALPN IDs",
			param: SvcParam{Key: KeyAlpn, Value: []byte{0x02, 'h', '2', 0x02, 'h', '3'}},
		},
		{
			name:    "alpn with a truncated ALPN ID",
			param:   SvcParam{Key: KeyAlpn, Value: []byte{0x02, 'h', '2', 0x03}},
			wantErr: true,
		},
		{
			name:    "alpn with an ALPN ID of length 0",
			param:   SvcParam{Key: KeyAlpn, Value: []byte{0x00}},
			wantErr: true,
		},
		{
			name:    "alpn with an ALPN ID of 256 octets",
			param:   SvcParam{Key: KeyAlpn, Value: append([]byte{0x00}, bytes.Repeat([]byte{'x'}, 256)...)},
			wantErr: true,
		},
		{name: "port of two octets", param: SvcParam{Key: KeyPort, Value: []byte{0x20, 0xFB}}},
		{
			name:    "port of one octet",
			param:   SvcParam{Key: KeyPort, Value: []byte{0xFB}},
			wantErr: true,
		},
		{name: "no-default-alpn with an empty value", param: SvcParam{Key: KeyNoDefaultAlpn}},
		{
			name:    "no-default-alpn with a value",
			param:   SvcParam{Key: KeyNoDefaultAlpn, Value: []byte{'x'}},
			wantErr: true,
		},
		{name: "mandatory with a key present in the record", param: SvcParam{Key: KeyMandatory, Value: []byte{0x00, 0x01}}},
		{
			name:    "mandatory with a key named twice",
			param:   SvcParam{Key: KeyMandatory, Value: []byte{0x00, 0x01, 0x00, 0x01}},
			wantErr: true,
		},
		{name: "ipv4hint with two addresses", param: SvcParam{Key: KeyIPv4Hint, Value: []byte{192, 0, 2, 1, 192, 0, 2, 2}}},
		{
			name:    "ipv4hint of five octets",
			param:   SvcParam{Key: KeyIPv4Hint, Value: []byte{192, 0, 2, 1, 2}},
			wantErr: true,
		},
		{
			name:    "ipv6hint of eight octets",
			param:   SvcParam{Key: KeyIPv6Hint, Value: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0}},
			wantErr: true,
		},
		{name: "ech with an opaque value", param: SvcParam{Key: KeyECH, Value: []byte{0x00, 0x01, 0x02}}},
		{name: "an unregistered key with an opaque value", param: SvcParam{Key: SvcParamKey(7), Value: []byte{'a', 'b'}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.param.validate(); (err != nil) != tt.wantErr {
				t.Errorf("validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseRecordSVCB(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		begin   uint32
		end     uint32
		want    RecordSVCB
		wantPos uint32
		wantErr bool
	}{
		{
			name:    "record with alpn and port",
			input:   svcbRDATA,
			begin:   0,
			want:    svcbWant(t),
			wantPos: uint32(len(svcbRDATA)),
		},
		{
			name:    "record at nonzero begin",
			input:   append([]byte{0xFF, 0xFF, 0xFF}, svcbRDATA...),
			begin:   3,
			want:    svcbWant(t),
			wantPos: 3 + uint32(len(svcbRDATA)),
		},
		{
			name:    "record followed by the next record",
			input:   append(append([]byte{}, svcbRDATA...), 0xAA, 0xBB),
			begin:   0,
			end:     uint32(len(svcbRDATA)),
			want:    svcbWant(t),
			wantPos: uint32(len(svcbRDATA)),
		},
		{
			name: "AliasMode record without SvcParams",
			input: []byte{
				0x00, 0x00, // SvcPriority: 0
				0x03, 'f', 'o', 'o', 0x00, // target name: foo.
			},
			begin: 0,
			want: RecordSVCB{
				SvcPriority: 0,
				TargetName:  testDomainName(t, "foo."),
			},
			wantPos: 7,
		},
		{
			name: "record with the root target name and no-default-alpn",
			input: []byte{
				0x00, 0x01,
				0x00,                   // target name: the root
				0x00, 0x02, 0x00, 0x00, // SvcParamKey=no-default-alpn, empty value
			},
			begin: 0,
			want: RecordSVCB{
				SvcPriority: 1,
				TargetName:  testDomainName(t, "."),
				SvcParams:   []SvcParam{{Key: KeyNoDefaultAlpn}},
			},
			wantPos: 7,
		},
		{
			name: "record with an unregistered SvcParamKey",
			input: []byte{
				0x00, 0x01,
				0x01, 'x', 0x00, // target name: x.
				0x00, 0x07, 0x00, 0x02, 'a', 'b', // SvcParamKey=7 with an opaque value
			},
			begin: 0,
			want: RecordSVCB{
				SvcPriority: 1,
				TargetName:  testDomainName(t, "x."),
				SvcParams:   []SvcParam{{Key: SvcParamKey(7), Value: []byte{'a', 'b'}}},
			},
			wantPos: 11,
		},
		{
			name: "record with a mandatory param",
			input: []byte{
				0x00, 0x01,
				0x01, 'x', 0x00,
				0x00, 0x00, 0x00, 0x02, 0x00, 0x03, // mandatory=port
				0x00, 0x03, 0x00, 0x02, 0x01, 0xBB, // port=443
			},
			begin: 0,
			want: RecordSVCB{
				SvcPriority: 1,
				TargetName:  testDomainName(t, "x."),
				SvcParams: []SvcParam{
					{Key: KeyMandatory, Value: []byte{0x00, 0x03}},
					{Key: KeyPort, Value: []byte{0x01, 0xBB}},
				},
			},
			wantPos: 17,
		},
		{
			name:    "empty RDATA",
			input:   []byte{},
			begin:   0,
			wantErr: true,
		},
		{
			name:    "RDATA with half a SvcPriority",
			input:   []byte{0x00},
			begin:   0,
			wantErr: true,
		},
		{
			name: "target name without a root label",
			input: []byte{
				0x00, 0x01,
				0x03, 'f', 'o', 'o',
			},
			begin:   0,
			wantErr: true,
		},
		{
			name: "target name written as a compression pointer",
			input: []byte{
				0x00, 0x01,
				0xC0, 0x0C,
			},
			begin:   0,
			wantErr: true,
		},
		{
			name:    "SvcParam header truncated at the end of the RDATA",
			input:   append(append([]byte{}, svcbRDATA...), 0x00, 0x01, 0x00),
			begin:   0,
			wantErr: true,
		},
		{
			name: "SvcParam value beyond the end of the RDATA",
			input: []byte{
				0x00, 0x01,
				0x01, 'x', 0x00,
				0x00, 0x01, 0x00, 0x06, 0x02, 'h', '2',
			},
			begin:   0,
			wantErr: true,
		},
		{
			name: "SvcParamKeys not in increasing order",
			input: []byte{
				0x00, 0x01,
				0x01, 'x', 0x00,
				0x00, 0x03, 0x00, 0x02, 0x01, 0xBB, // port=443
				0x00, 0x01, 0x00, 0x03, 0x02, 'h', '2', // alpn, which is a lower key
			},
			begin:   0,
			wantErr: true,
		},
		{
			name: "record has the same SvcParamKey twice",
			input: []byte{
				0x00, 0x01,
				0x01, 'x', 0x00,
				0x00, 0x03, 0x00, 0x02, 0x01, 0xBB, // port=443
				0x00, 0x03, 0x00, 0x02, 0x00, 0x50, // port=80
			},
			begin:   0,
			wantErr: true,
		},
		{
			name: "alpn value with a truncated ALPN ID",
			input: []byte{
				0x00, 0x01,
				0x01, 'x', 0x00,
				0x00, 0x01, 0x00, 0x04, 0x02, 'h', '2', 0x03,
			},
			begin:   0,
			wantErr: true,
		},
		{
			name: "alpn value with an ALPN ID of length 0",
			input: []byte{
				0x00, 0x01,
				0x01, 'x', 0x00,
				0x00, 0x01, 0x00, 0x01, 0x00,
			},
			begin:   0,
			wantErr: true,
		},
		{
			name: "port value of three octets",
			input: []byte{
				0x00, 0x01,
				0x01, 'x', 0x00,
				0x00, 0x03, 0x00, 0x03, 0x00, 0x01, 0x02,
			},
			begin:   0,
			wantErr: true,
		},
		{
			name: "ipv4hint value of five octets",
			input: []byte{
				0x00, 0x01,
				0x01, 'x', 0x00,
				0x00, 0x04, 0x00, 0x05, 192, 0, 2, 1, 2,
			},
			begin:   0,
			wantErr: true,
		},
		{
			name: "no-default-alpn with a value",
			input: []byte{
				0x00, 0x01,
				0x01, 'x', 0x00,
				0x00, 0x02, 0x00, 0x01, 'x',
			},
			begin:   0,
			wantErr: true,
		},
		{
			name: "AliasMode record with SvcParams",
			input: []byte{
				0x00, 0x00, // SvcPriority: 0
				0x01, 'x', 0x00,
				0x00, 0x01, 0x00, 0x02, 0x02, 'h', '2', // alpn=h2
			},
			begin:   0,
			wantErr: true,
		},
		{
			name: "mandatory param naming a key the record does not have",
			input: []byte{
				0x00, 0x01,
				0x01, 'x', 0x00,
				0x00, 0x00, 0x00, 0x02, 0x00, 0x03, // mandatory=port, and no port
			},
			begin:   0,
			wantErr: true,
		},
		{
			name:    "RDATA end beyond the wire format",
			input:   svcbRDATA,
			begin:   0,
			end:     60,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			end := tt.end
			if end == 0 {
				end = uint32(len(tt.input))
			}
			w := WireFormat(tt.input)

			got, pos, err := ParseRecordSVCB(w, tt.begin, end)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseRecordSVCB() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if pos != tt.wantPos {
				t.Errorf("ParseRecordSVCB() pos = %v, want %v", pos, tt.wantPos)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseRecordSVCB() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewRecordSVCB(t *testing.T) {
	t.Run("SvcParams are sorted into the order the wire format requires", func(t *testing.T) {
		got, err := NewRecordSVCB(1, testDomainName(t, "svcb.example.com."),
			mustSvcParam(t, KeyPort, "8443"),
			mustSvcParam(t, KeyAlpn, "h2,h3"),
		)
		if err != nil {
			t.Fatalf("NewRecordSVCB() error = %v", err)
		}
		if !reflect.DeepEqual(got, svcbWant(t)) {
			t.Errorf("NewRecordSVCB() got = %v, want %v", got, svcbWant(t))
		}
		if got.Type() != TYPE_SVCB {
			t.Errorf("Type() = %v, want TYPE_SVCB", got.Type())
		}
	})

	t.Run("a record without SvcParams has no SvcParams", func(t *testing.T) {
		got, err := NewRecordSVCB(0, testDomainName(t, "alias.example.com."))
		if err != nil {
			t.Fatalf("NewRecordSVCB() error = %v", err)
		}
		if got.SvcParams != nil {
			t.Errorf("NewRecordSVCB() SvcParams = %v, want none", got.SvcParams)
		}
	})

	t.Run("an RDATA that fills RDLENGTH", func(t *testing.T) {
		p := mustSvcParam(t, SvcParamKey(65535), strings.Repeat("x", 65528))
		if _, err := NewRecordSVCB(1, testDomainName(t, "."), p); err != nil {
			t.Errorf("NewRecordSVCB() with a RDATA of 65535 octets error = %v", err)
		}
	})

	t.Run("an RDATA larger than RDLENGTH", func(t *testing.T) {
		p := mustSvcParam(t, SvcParamKey(65535), strings.Repeat("x", 65529))
		if _, err := NewRecordSVCB(1, testDomainName(t, "."), p); err == nil {
			t.Error("NewRecordSVCB() with a RDATA of more than 65535 octets did not report an error")
		}
	})
}

func TestNewRecordSVCBErrors(t *testing.T) {
	tests := []struct {
		name        string
		svcPriority uint16
		params      []SvcParam
	}{
		{
			name:        "AliasMode record with SvcParams",
			svcPriority: 0,
			params:      []SvcParam{mustSvcParam(t, KeyAlpn, "h2")},
		},
		{
			name:        "record with the same key twice",
			svcPriority: 1,
			params: []SvcParam{
				mustSvcParam(t, KeyAlpn, "h2"),
				mustSvcParam(t, KeyAlpn, "h3"),
			},
		},
		{
			name:        "mandatory param naming a key the record does not have",
			svcPriority: 1,
			params:      []SvcParam{mustSvcParam(t, KeyMandatory, "port")},
		},
		{
			name:        "SvcParam with a malformed value",
			svcPriority: 1,
			params:      []SvcParam{{Key: KeyPort, Value: []byte{0x01}}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewRecordSVCB(tt.svcPriority, testDomainName(t, "svcb.example.com."), tt.params...); err == nil {
				t.Error("NewRecordSVCB() did not report an error")
			}
		})
	}
}

func TestNewRecordSVCBFromParams(t *testing.T) {
	got, err := NewRecordSVCBFromParams(1, "svcb.example.com.", map[string]string{
		"port": "8443",
		"alpn": "h2,h3",
	})
	if err != nil {
		t.Fatalf("NewRecordSVCBFromParams() error = %v", err)
	}
	if !reflect.DeepEqual(got, svcbWant(t)) {
		t.Errorf("NewRecordSVCBFromParams() got = %v, want %v", got, svcbWant(t))
	}

	if _, err := NewRecordSVCBFromParams(1, "svcb.example.com.", map[string]string{"zzz=": "x"}); err == nil {
		t.Error("NewRecordSVCBFromParams() with an invalid key name did not report an error")
	}
	if _, err := NewRecordSVCBFromParams(1, "svcb..example.com.", nil); err == nil {
		t.Error("NewRecordSVCBFromParams() with an invalid target name did not report an error")
	}
}

func TestNewRecordSVCBFromString(t *testing.T) {
	tests := []struct {
		input      string
		want       RecordSVCB
		wantString string
	}{
		{
			input:      "1 svcb.example.com. alpn=h2,h3 port=8443",
			want:       svcbWant(t),
			wantString: "1 svcb.example.com. alpn=h2,h3 port=8443",
		},
		{
			input:      "1 svcb.example.com. port=8443 alpn=h2,h3",
			want:       svcbWant(t),
			wantString: "1 svcb.example.com. alpn=h2,h3 port=8443",
		},
		{
			input: `1 svcb.example.com. alpn="h2,h3"`,
			want: RecordSVCB{
				SvcPriority: 1,
				TargetName:  testDomainName(t, "svcb.example.com."),
				SvcParams:   []SvcParam{{Key: KeyAlpn, Value: []byte{0x02, 'h', '2', 0x02, 'h', '3'}}},
			},
			wantString: "1 svcb.example.com. alpn=h2,h3",
		},
		{
			// The comma of the ALPN ID "a,b" is escaped in the value-list
			// (Appendix A.1) and that escape is escaped once more for the
			// character-string (Appendix A), which is why the input and the
			// output name it with two backslashes.
			input: `1 svcb.example.com. alpn=a\\,b`,
			want: RecordSVCB{
				SvcPriority: 1,
				TargetName:  testDomainName(t, "svcb.example.com."),
				SvcParams:   []SvcParam{{Key: KeyAlpn, Value: []byte{0x03, 'a', ',', 'b'}}},
			},
			wantString: `1 svcb.example.com. alpn=a\\,b`,
		},
		{
			input: "0 alias.example.com.",
			want: RecordSVCB{
				SvcPriority: 0,
				TargetName:  testDomainName(t, "alias.example.com."),
			},
			wantString: "0 alias.example.com.",
		},
		{
			input: "1 . no-default-alpn",
			want: RecordSVCB{
				SvcPriority: 1,
				TargetName:  testDomainName(t, "."),
				SvcParams:   []SvcParam{{Key: KeyNoDefaultAlpn}},
			},
			wantString: "1 . no-default-alpn",
		},
		{
			// The keys of the input are in any order, but the wire format is
			// the key numbers in strictly increasing order (RFC 9460
			// Section 7.4), which is also the order String() writes.
			input: "1 svcb.example.com. mandatory=port,alpn alpn=h2 port=8443",
			want: RecordSVCB{
				SvcPriority: 1,
				TargetName:  testDomainName(t, "svcb.example.com."),
				SvcParams: []SvcParam{
					{Key: KeyMandatory, Value: []byte{0x00, 0x01, 0x00, 0x03}},
					{Key: KeyAlpn, Value: []byte{0x02, 'h', '2'}},
					{Key: KeyPort, Value: []byte{0x20, 0xFB}},
				},
			},
			wantString: "1 svcb.example.com. mandatory=alpn,port alpn=h2 port=8443",
		},
		{
			input: "1 svcb.example.com. ipv4hint=192.0.2.1,192.0.2.2",
			want: RecordSVCB{
				SvcPriority: 1,
				TargetName:  testDomainName(t, "svcb.example.com."),
				SvcParams:   []SvcParam{{Key: KeyIPv4Hint, Value: []byte{192, 0, 2, 1, 192, 0, 2, 2}}},
			},
			wantString: "1 svcb.example.com. ipv4hint=192.0.2.1,192.0.2.2",
		},
		{
			input: `1 svcb.example.com. ech="\000\001\002"`,
			want: RecordSVCB{
				SvcPriority: 1,
				TargetName:  testDomainName(t, "svcb.example.com."),
				SvcParams:   []SvcParam{{Key: KeyECH, Value: []byte{0x00, 0x01, 0x02}}},
			},
			wantString: `1 svcb.example.com. ech="\000\001\002"`,
		},
		{
			input: "1 svcb.example.com. key7=ab",
			want: RecordSVCB{
				SvcPriority: 1,
				TargetName:  testDomainName(t, "svcb.example.com."),
				SvcParams:   []SvcParam{{Key: SvcParamKey(7), Value: []byte{'a', 'b'}}},
			},
			wantString: "1 svcb.example.com. key7=ab",
		},
		{
			input: "65531 svcb.example.com.",
			want: RecordSVCB{
				SvcPriority: 65531,
				TargetName:  testDomainName(t, "svcb.example.com."),
			},
			wantString: "65531 svcb.example.com.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := NewRecordSVCBFromString(tt.input)
			if err != nil {
				t.Fatalf("NewRecordSVCBFromString(%q) error = %v", tt.input, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewRecordSVCBFromString(%q) got = %v, want %v", tt.input, got, tt.want)
			}
			if s := got.String(); s != tt.wantString {
				t.Errorf("String() = %q, want %q", s, tt.wantString)
			}
		})
	}
}

func TestNewRecordSVCBFromStringErrors(t *testing.T) {
	tests := []struct {
		input string
	}{
		{input: ""},
		{input: "1"},
		{input: "svcb.example.com. alpn=h2"},
		{input: "-1 svcb.example.com."},
		{input: "65536 svcb.example.com."},
		{input: "1 svcb..example.com."},
		{input: "1 svcb.example.com. alpn="},
		{input: "1 svcb.example.com. alpn=,h2"},
		{input: "1 svcb.example.com. alpn=h2 alpn=h3"},
		{input: "1 svcb.example.com. port="},
		{input: "1 svcb.example.com. port=65536"},
		{input: "1 svcb.example.com. port=80 x"},
		{input: "1 svcb.example.com. no-default-alpn=x"},
		{input: "1 svcb.example.com. zzz=x"},
		{input: "1 svcb.example.com. keyNNNNN=x"},
		{input: "1 svcb.example.com. ipv4hint=192.0.2.1,"},
		{input: "1 svcb.example.com. ipv6hint=192.0.2.1"},
		{input: "1 svcb.example.com. mandatory=port"},
		{input: `1 svcb.example.com. alpn="h2`},
		{input: `1 svcb.example.com. alpn=h2" x`},
		{input: `1 svcb.example.com. ech="\"`},
		{input: `1 svcb.example.com. ech="\1"`},
		{input: "0 svcb.example.com. alpn=h2"},
		{input: "1 svcb.example.com. key7=" + strings.Repeat("x", 65529)},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if _, err := NewRecordSVCBFromString(tt.input); err == nil {
				t.Errorf("NewRecordSVCBFromString(%q) error = nil, want an error", tt.input)
			}
		})
	}
}

func TestRecordSVCBString(t *testing.T) {
	tests := []struct {
		name string
		r    RecordSVCB
		want string
	}{
		{
			name: "record with alpn and port",
			r:    svcbWant(t),
			want: "1 svcb.example.com. alpn=h2,h3 port=8443",
		},
		{
			name: "AliasMode record",
			r: RecordSVCB{
				SvcPriority: 0,
				TargetName:  testDomainName(t, "alias.example.com."),
			},
			want: "0 alias.example.com.",
		},
		{
			name: "record with the root target name",
			r: RecordSVCB{
				SvcPriority: 1,
				TargetName:  testDomainName(t, "."),
				SvcParams:   []SvcParam{{Key: KeyNoDefaultAlpn}},
			},
			want: "1 . no-default-alpn",
		},
		{
			name: "record with an IPv6 hint",
			r: RecordSVCB{
				SvcPriority: 1,
				TargetName:  testDomainName(t, "svcb.example.com."),
				SvcParams: []SvcParam{{Key: KeyIPv6Hint, Value: []byte{
					0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
					0, 0, 0, 0, 0, 0, 0, 1,
					0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
					0, 0, 0, 0, 0, 0, 0, 2,
				}}},
			},
			want: "1 svcb.example.com. ipv6hint=2001:db8::1,2001:db8::2",
		},
		{
			name: "record with a param whose value is not printable",
			r: RecordSVCB{
				SvcPriority: 1,
				TargetName:  testDomainName(t, "svcb.example.com."),
				SvcParams:   []SvcParam{{Key: KeyECH, Value: []byte{0x00, 0x01, 0xff, '"'}}},
			},
			want: `1 svcb.example.com. ech="\000\001\255\""`,
		},
		{
			name: "record with a param whose value holds a space",
			r: RecordSVCB{
				SvcPriority: 1,
				TargetName:  testDomainName(t, "svcb.example.com."),
				SvcParams:   []SvcParam{{Key: SvcParamKey(7), Value: []byte("a b")}},
			},
			want: `1 svcb.example.com. key7="a\032b"`,
		},
		{
			name: "record with an ALPN ID that holds a comma",
			r: RecordSVCB{
				SvcPriority: 1,
				TargetName:  testDomainName(t, "svcb.example.com."),
				SvcParams:   []SvcParam{{Key: KeyAlpn, Value: []byte{0x03, 'a', ',', 'b'}}},
			},
			want: `1 svcb.example.com. alpn=a\\,b`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.r.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRecordSVCBWireFormatRoundTrip(t *testing.T) {
	original, err := NewRecordSVCB(1, testDomainName(t, "SvcB.Example.COM."),
		mustSvcParam(t, KeyAlpn, "h2,h3"),
		mustSvcParam(t, KeyPort, "8443"),
	)
	if err != nil {
		t.Fatalf("NewRecordSVCB() error = %v", err)
	}

	// The target name is written in full and with its case unchanged, even
	// though an unrelated name that is used by it is available for compression
	// (RFC 9460 Section 2.2).  Only the SvcParams are shared with svcbRDATA.
	var wantWire WireFormat
	wantWire = append(wantWire,
		0x00, 0x01,
		0x04, 'S', 'v', 'c', 'B',
		0x07, 'E', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'C', 'O', 'M',
		0x00,
	)
	wantWire = append(wantWire, svcbRDATA[len(wantWire):]...)

	db := NewNameCompressionDB()
	db.AddDomainName(testDomainName(t, "example.com."), 12)

	var w WireFormat
	size := original.AppendWireFormat(&w, db)
	if size != uint32(len(w)) {
		t.Errorf("AppendWireFormat() size = %v, want %v", size, len(w))
	}
	if !bytes.Equal(w, wantWire) {
		t.Errorf("AppendWireFormat() = %v, want %v", w, wantWire)
	}

	got, pos, err := ParseRecordSVCB(w, 0, size)
	if err != nil {
		t.Fatalf("ParseRecordSVCB() error = %v", err)
	}
	if pos != size {
		t.Errorf("ParseRecordSVCB() pos = %v, want %v", pos, size)
	}
	if !reflect.DeepEqual(got, original) {
		t.Errorf("ParseRecordSVCB() got = %v, want %v", got, original)
	}

	// The canonical wire format is the same RDATA with the target name
	// lower-cased, which is what svcbRDATA holds.
	var cw WireFormat
	cSize := original.AppendCanonicalWireFormat(&cw)
	if cSize != uint32(len(cw)) {
		t.Errorf("AppendCanonicalWireFormat() size = %v, want %v", cSize, len(cw))
	}
	if !bytes.Equal(original.CanonicalWireFormat(), cw) {
		t.Errorf("CanonicalWireFormat() = %v, want %v", original.CanonicalWireFormat(), cw)
	}
	if !bytes.Equal(cw, svcbRDATA) {
		t.Errorf("AppendCanonicalWireFormat() = %v, want %v", cw, svcbRDATA)
	}
}

func TestParseResourceRecordSVCB(t *testing.T) {
	// A SVCB record in a message.
	var w WireFormat
	w.AppendDomainName(testDomainName(t, "svc.example.com."), nil)
	w.AppendUInt16(uint16(TYPE_SVCB))
	w.AppendUInt16(uint16(CLASS_IN))
	w.AppendUInt32(3600)
	w.AppendUInt16(uint16(len(svcbRDATA)))
	w.AppendBytes(svcbRDATA)

	rr, pos, err := ParseResourceRecord(w, 0)
	if err != nil {
		t.Fatalf("ParseResourceRecord() error = %v", err)
	}
	if pos != uint32(len(w)) {
		t.Errorf("ParseResourceRecord() pos = %v, want %v", pos, len(w))
	}
	if rr.Class != CLASS_IN {
		t.Errorf("Class = %v, want CLASS_IN", rr.Class)
	}
	if rr.Type != TYPE_SVCB {
		t.Errorf("Type = %v, want TYPE_SVCB", rr.Type)
	}
	if rr.TTL != 3600 {
		t.Errorf("TTL = %v, want 3600", rr.TTL)
	}
	rdata, ok := rr.RData.(RecordSVCB)
	if !ok {
		t.Fatalf("RData = %T, want RecordSVCB", rr.RData)
	}
	if !reflect.DeepEqual(rdata, svcbWant(t)) {
		t.Errorf("RData = %v, want %v", rdata, svcbWant(t))
	}

	// The record type name and the SVCB type code round-trip.
	if TYPE_SVCB != 64 {
		t.Errorf("TYPE_SVCB = %d, want 64", TYPE_SVCB)
	}
	if TYPE_SVCB.String() != "SVCB" {
		t.Errorf("TYPE_SVCB.String() = %q, want %q", TYPE_SVCB.String(), "SVCB")
	}
	if n, err := NewType("SVCB"); err != nil || n != TYPE_SVCB {
		t.Errorf("NewType(%q) = %v, %v, want TYPE_SVCB, nil", "SVCB", n, err)
	}
	if n, err := NewType("TYPE64"); err != nil || n != TYPE_SVCB {
		t.Errorf("NewType(%q) = %v, %v, want TYPE_SVCB, nil", "TYPE64", n, err)
	}
}
