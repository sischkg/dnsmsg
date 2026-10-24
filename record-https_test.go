package dnsmsg

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

// httpsRDATA is the RDATA the parse tests below read: SvcPriority 1, target
// name "svc.example.com.", and the alpn and ipv4hint SvcParams an HTTPS record
// commonly carries.  It is the RDATA of the example.com. HTTPS record of
// RFC 9460 Appendix C.1 with the alpn value of Section 2.1.
var httpsRDATA = WireFormat{
	0x00, 0x01, // SvcPriority: 1
	0x03, 's', 'v', 'c', // target name: svc
	0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // ...example
	0x03, 'c', 'o', 'm', // ...com
	0x00,                   // root label
	0x00, 0x01, 0x00, 0x06, // SvcParamKey=alpn, value of 6 octets
	0x02, 'h', '2', 0x02, 'h', '3', // ALPN IDs "h2" and "h3"
	0x00, 0x04, 0x00, 0x08, // SvcParamKey=ipv4hint, value of 8 octets
	192, 0, 2, 1, 192, 0, 2, 2, // hints 192.0.2.1 and 192.0.2.2
}

// httpsWant is the record httpsRDATA is the RDATA of.
func httpsWant(t *testing.T) RecordHTTPS {
	t.Helper()
	return RecordHTTPS{
		RecordSVCB: RecordSVCB{
			SvcPriority: 1,
			TargetName:  testDomainName(t, "svc.example.com."),
			SvcParams: []SvcParam{
				{Key: KeyAlpn, Value: []byte{0x02, 'h', '2', 0x02, 'h', '3'}},
				{Key: KeyIPv4Hint, Value: []byte{192, 0, 2, 1, 192, 0, 2, 2}},
			},
		},
	}
}

func TestParseRecordHTTPS(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		begin   uint32
		end     uint32
		want    RecordHTTPS
		wantPos uint32
		wantErr bool
	}{
		{
			name:    "record with alpn and ipv4hint",
			input:   httpsRDATA,
			begin:   0,
			want:    httpsWant(t),
			wantPos: 41,
		},
		{
			name:    "record at nonzero begin",
			input:   append([]byte{0xFF, 0xFF, 0xFF}, httpsRDATA...),
			begin:   3,
			want:    httpsWant(t),
			wantPos: 44,
		},
		{
			name:    "record followed by the next record",
			input:   append(append([]byte{}, httpsRDATA...), 0xAA, 0xBB),
			begin:   0,
			end:     41,
			want:    httpsWant(t),
			wantPos: 41,
		},
		{
			name: "record with the root target name and no-default-alpn",
			input: []byte{
				0x00, 0x01,
				0x00,                   // target name: the root
				0x00, 0x02, 0x00, 0x00, // SvcParamKey=no-default-alpn, empty value
				0x00, 0x03, 0x00, 0x02, 0x01, 0xBB, // port=443
			},
			begin: 0,
			want: RecordHTTPS{
				RecordSVCB: RecordSVCB{
					SvcPriority: 1,
					TargetName:  testDomainName(t, "."),
					SvcParams: []SvcParam{
						{Key: KeyNoDefaultAlpn},
						{Key: KeyPort, Value: []byte{0x01, 0xBB}},
					},
				},
			},
			wantPos: 13,
		},
		{
			name: "AliasMode record without SvcParams",
			input: []byte{
				0x00, 0x00, // SvcPriority: 0
				0x03, 'f', 'o', 'o', 0x00, // target name: foo.
			},
			begin: 0,
			want: RecordHTTPS{
				RecordSVCB: RecordSVCB{
					SvcPriority: 0,
					TargetName:  testDomainName(t, "foo."),
				},
			},
			wantPos: 7,
		},
		{
			name: "record with an ECH SvcParam",
			input: []byte{
				0x00, 0x01,
				0x01, 'x', 0x00, // target name: x.
				0x00, 0x05, 0x00, 0x03, 0x00, 0x01, 0x02, // ech with opaque bytes
			},
			begin: 0,
			want: RecordHTTPS{
				RecordSVCB: RecordSVCB{
					SvcPriority: 1,
					TargetName:  testDomainName(t, "x."),
					SvcParams:   []SvcParam{{Key: KeyECH, Value: []byte{0x00, 0x01, 0x02}}},
				},
			},
			wantPos: 12,
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
			input:   append(append([]byte{}, httpsRDATA...), 0x00, 0x01, 0x00),
			begin:   0,
			wantErr: true,
		},
		{
			name: "SvcParam value beyond the end of the RDATA",
			input: []byte{
				0x00, 0x01,
				0x01, 'x', 0x00,
				0x00, 0x04, 0x00, 0x08, 192, 0, 2, 1,
			},
			begin:   0,
			wantErr: true,
		},
		{
			name: "SvcParamKeys not in increasing order",
			input: []byte{
				0x00, 0x01,
				0x01, 'x', 0x00,
				0x00, 0x04, 0x00, 0x04, 192, 0, 2, 1, // ipv4hint
				0x00, 0x01, 0x00, 0x02, 0x02, 'h', '2', // alpn, which is a lower key
			},
			begin:   0,
			wantErr: true,
		},
		{
			name: "record has the same SvcParamKey twice",
			input: []byte{
				0x00, 0x01,
				0x01, 'x', 0x00,
				0x00, 0x04, 0x00, 0x04, 192, 0, 2, 1,
				0x00, 0x04, 0x00, 0x04, 192, 0, 2, 2,
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
			input:   httpsRDATA,
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

			got, pos, err := ParseRecordHTTPS(w, tt.begin, end)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseRecordHTTPS() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if pos != tt.wantPos {
				t.Errorf("ParseRecordHTTPS() pos = %v, want %v", pos, tt.wantPos)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseRecordHTTPS() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewRecordHTTPS(t *testing.T) {
	got, err := NewRecordHTTPS(1, testDomainName(t, "svc.example.com."),
		mustSvcParam(t, KeyIPv4Hint, "192.0.2.1,192.0.2.2"),
		mustSvcParam(t, KeyAlpn, "h2,h3"),
	)
	if err != nil {
		t.Fatalf("NewRecordHTTPS() error = %v", err)
	}
	if !reflect.DeepEqual(got, httpsWant(t)) {
		t.Errorf("NewRecordHTTPS() got = %v, want %v", got, httpsWant(t))
	}
	if got.Type() != TYPE_HTTPS {
		t.Errorf("Type() = %v, want TYPE_HTTPS", got.Type())
	}

	if _, err := NewRecordHTTPS(0, testDomainName(t, "svc.example.com."),
		mustSvcParam(t, KeyAlpn, "h2")); err == nil {
		t.Error("NewRecordHTTPS() with an AliasMode record with SvcParams did not report an error")
	}
}

func TestNewRecordHTTPSFromParams(t *testing.T) {
	got, err := NewRecordHTTPSFromParams(1, "svc.example.com.", map[string]string{
		"ipv4hint": "192.0.2.1,192.0.2.2",
		"alpn":     "h2,h3",
	})
	if err != nil {
		t.Fatalf("NewRecordHTTPSFromParams() error = %v", err)
	}
	if !reflect.DeepEqual(got, httpsWant(t)) {
		t.Errorf("NewRecordHTTPSFromParams() got = %v, want %v", got, httpsWant(t))
	}

	if _, err := NewRecordHTTPSFromParams(1, "svc.example.com.", map[string]string{
		"alpn": "h2", "port": "not-a-port",
	}); err == nil {
		t.Error("NewRecordHTTPSFromParams() with an invalid value did not report an error")
	}
}

func TestNewRecordHTTPSFromString(t *testing.T) {
	tests := []struct {
		input      string
		want       RecordHTTPS
		wantString string
	}{
		{
			input:      "1 svc.example.com. alpn=h2,h3 ipv4hint=192.0.2.1,192.0.2.2",
			want:       httpsWant(t),
			wantString: "1 svc.example.com. alpn=h2,h3 ipv4hint=192.0.2.1,192.0.2.2",
		},
		{
			// The SvcParams may be given in any order, but String() writes them
			// in increasing SvcParamKey order.
			input:      "1 svc.example.com. ipv4hint=192.0.2.1,192.0.2.2 alpn=h2,h3",
			want:       httpsWant(t),
			wantString: "1 svc.example.com. alpn=h2,h3 ipv4hint=192.0.2.1,192.0.2.2",
		},
		{
			input: "1 . alpn=h2 no-default-alpn port=8443",
			want: RecordHTTPS{
				RecordSVCB: RecordSVCB{
					SvcPriority: 1,
					TargetName:  testDomainName(t, "."),
					SvcParams: []SvcParam{
						{Key: KeyAlpn, Value: []byte{0x02, 'h', '2'}},
						{Key: KeyNoDefaultAlpn},
						{Key: KeyPort, Value: []byte{0x20, 0xFB}},
					},
				},
			},
			wantString: "1 . alpn=h2 no-default-alpn port=8443",
		},
		{
			input: "0 alias.example.com.",
			want: RecordHTTPS{
				RecordSVCB: RecordSVCB{
					SvcPriority: 0,
					TargetName:  testDomainName(t, "alias.example.com."),
				},
			},
			wantString: "0 alias.example.com.",
		},
		{
			input: `1 svc.example.com. ech="\000\001\002"`,
			want: RecordHTTPS{
				RecordSVCB: RecordSVCB{
					SvcPriority: 1,
					TargetName:  testDomainName(t, "svc.example.com."),
					SvcParams:   []SvcParam{{Key: KeyECH, Value: []byte{0x00, 0x01, 0x02}}},
				},
			},
			wantString: `1 svc.example.com. ech="\000\001\002"`,
		},
		{
			// A quoted character-string value is read, but String() writes an
			// ALPN value as a comma-separated list, which needs no quoting.
			input: `1 svc.example.com. alpn="h2,h3"`,
			want: RecordHTTPS{
				RecordSVCB: RecordSVCB{
					SvcPriority: 1,
					TargetName:  testDomainName(t, "svc.example.com."),
					SvcParams:   []SvcParam{{Key: KeyAlpn, Value: []byte{0x02, 'h', '2', 0x02, 'h', '3'}}},
				},
			},
			wantString: "1 svc.example.com. alpn=h2,h3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := NewRecordHTTPSFromString(tt.input)
			if err != nil {
				t.Fatalf("NewRecordHTTPSFromString(%q) error = %v", tt.input, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewRecordHTTPSFromString(%q) got = %v, want %v", tt.input, got, tt.want)
			}
			if got.String() != tt.wantString {
				t.Errorf("NewRecordHTTPSFromString(%q) String() = %q, want %q", tt.input, got.String(), tt.wantString)
			}
			roundTrip, err := NewRecordHTTPSFromString(tt.wantString)
			if err != nil {
				t.Errorf("NewRecordHTTPSFromString(%q) error = %v", tt.wantString, err)
			} else if !reflect.DeepEqual(roundTrip, tt.want) {
				t.Errorf("NewRecordHTTPSFromString(%q) got = %v, want %v", tt.wantString, roundTrip, tt.want)
			}
			if got.Type() != TYPE_HTTPS {
				t.Errorf("Type() = %v, want TYPE_HTTPS", got.Type())
			}
		})
	}
}

func TestNewRecordHTTPSFromStringErrors(t *testing.T) {
	tests := []struct {
		input string
	}{
		{input: ""},
		{input: "1"},
		{input: "svc.example.com. alpn=h2"},
		{input: "-1 svc.example.com."},
		{input: "65536 svc.example.com."},
		{input: "1 svc..example.com."},
		{input: "1 svc.example.com. alpn="},
		{input: "1 svc.example.com. alpn=,h2"},
		{input: "1 svc.example.com. ipv4hint=192.0.2.1,"},
		{input: "1 svc.example.com. ipv6hint=192.0.2.1"},
		{input: "1 svc.example.com. port=65536"},
		{input: "1 svc.example.com. zzz=x"},
		{input: "1 svc.example.com. alpn=h2 alpn=h3"},
		{input: "1 svc.example.com. mandatory=alpn"},
		{input: "1 svc.example.com. mandatory=mandatory"},
		{input: "0 svc.example.com. alpn=h2"},
		{input: `1 svc.example.com. alpn="h2`},
		{input: `1 svc.example.com. ech="\"`},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			_, err := NewRecordHTTPSFromString(tt.input)
			if err == nil {
				t.Fatalf("NewRecordHTTPSFromString(%q) did not report an error", tt.input)
			}
			// The presentation-format and wire-format code a HTTPS record shares
			// with a SVCB record must never report a HTTPS record as a SVCB one.
			if wantErrNamesRecord(err, "SVCB") {
				t.Errorf("NewRecordHTTPSFromString(%q) error = %q, which names the SVCB record", tt.input, err)
			}
		})
	}
}

func TestNewRecordHTTPSFromStringNamesTheHTTPSRecord(t *testing.T) {
	// The errors of the fields only a presentation-format string has name the
	// record whose string it is.
	tests := []struct {
		input string
	}{
		{input: ""},
		{input: "1"},
		{input: "svc.example.com. alpn=h2"},
		{input: "65536 svc.example.com."},
		{input: "1 svc..example.com."},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			_, err := NewRecordHTTPSFromString(tt.input)
			if err == nil {
				t.Fatalf("NewRecordHTTPSFromString(%q) did not report an error", tt.input)
			}
			if !wantErrNamesRecord(err, "HTTPS") {
				t.Errorf("NewRecordHTTPSFromString(%q) error = %q, which does not name the HTTPS record", tt.input, err)
			}
		})
	}
}

// wantErrNamesRecord reports whether the error mentions the given record type
// name, so that a HTTPS record is never reported as a SVCB record.
func wantErrNamesRecord(err error, name string) bool {
	return bytes.Contains([]byte(err.Error()), []byte(name))
}

func TestRecordHTTPSString(t *testing.T) {
	tests := []struct {
		name string
		r    RecordHTTPS
		want string
	}{
		{
			name: "record with alpn and ipv4hint",
			r:    httpsWant(t),
			want: "1 svc.example.com. alpn=h2,h3 ipv4hint=192.0.2.1,192.0.2.2",
		},
		{
			name: "AliasMode record",
			r: RecordHTTPS{
				RecordSVCB: RecordSVCB{
					SvcPriority: 0,
					TargetName:  testDomainName(t, "alias.example.com."),
				},
			},
			want: "0 alias.example.com.",
		},
		{
			name: "record with an ECH param, whose value is not printable",
			r: RecordHTTPS{
				RecordSVCB: RecordSVCB{
					SvcPriority: 1,
					TargetName:  testDomainName(t, "svc.example.com."),
					SvcParams:   []SvcParam{{Key: KeyECH, Value: []byte{0x00, 0x01, 0x02}}},
				},
			},
			want: `1 svc.example.com. ech="\000\001\002"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.r.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
			roundTrip, err := NewRecordHTTPSFromString(tt.want)
			if err != nil {
				t.Errorf("NewRecordHTTPSFromString(%q) error = %v", tt.want, err)
				return
			}
			if !reflect.DeepEqual(roundTrip, tt.r) {
				t.Errorf("NewRecordHTTPSFromString(%q) got = %v, want %v", tt.want, roundTrip, tt.r)
			}
		})
	}
}

func TestRecordHTTPSWireFormatRoundTrip(t *testing.T) {
	// The target name of the record this test writes has upper-case octets, so
	// that it shows the difference between the wire format, which keeps the
	// octets as they are, and the canonical wire format, which lower-cases
	// them.  Its SvcParams are those of httpsRDATA.
	const nameLen = (1 + 4) + (1 + 7) + (1 + 3) + 1
	original, err := NewRecordHTTPS(1, testDomainName(t, "SvcB.Example.COM."),
		mustSvcParam(t, KeyIPv4Hint, "192.0.2.1,192.0.2.2"),
		mustSvcParam(t, KeyAlpn, "h2,h3"),
	)
	if err != nil {
		t.Fatalf("NewRecordHTTPS() error = %v", err)
	}

	// The target name is written in full, with its case unchanged, and without
	// using a compression pointer that is available for it
	// (RFC 9460 Section 2.2).
	db := NewNameCompressionDB()
	db.AddDomainName(testDomainName(t, "svc.example.com."), 12)

	var w WireFormat
	size := original.AppendWireFormat(&w, db)
	if size != uint32(len(w)) {
		t.Errorf("AppendWireFormat() size = %v, want %v", size, len(w))
	}
	want := WireFormat{
		0x00, 0x01, // SvcPriority: 1
		0x04, 'S', 'v', 'c', 'B', // target name: SvcB
		0x07, 'E', 'x', 'a', 'm', 'p', 'l', 'e', // ...Example
		0x03, 'C', 'O', 'M', // ...COM
		0x00, // root label
	}
	want = append(want, httpsRDATA[2+17:]...)
	if !bytes.Equal(w, want) {
		t.Errorf("AppendWireFormat() = % x, want % x", w, want)
	}

	got, pos, err := ParseRecordHTTPS(w, 0, size)
	if err != nil {
		t.Fatalf("ParseRecordHTTPS() error = %v", err)
	}
	if pos != size {
		t.Errorf("ParseRecordHTTPS() pos = %v, want %v", pos, size)
	}
	if !reflect.DeepEqual(got, original) {
		t.Errorf("ParseRecordHTTPS() got = %v, want %v", got, original)
	}

	// The canonical wire format is the same octets with the target name
	// lower-cased.
	var cw WireFormat
	cSize := original.AppendCanonicalWireFormat(&cw)
	if cSize != uint32(len(cw)) {
		t.Errorf("AppendCanonicalWireFormat() size = %v, want %v", cSize, len(cw))
	}
	if !bytes.Equal(original.CanonicalWireFormat(), cw) {
		t.Errorf("CanonicalWireFormat() = %v, want %v", original.CanonicalWireFormat(), cw)
	}
	lower := append(WireFormat{}, want...)
	for i := 2; i < 2+nameLen; i++ {
		if 'A' <= lower[i] && lower[i] <= 'Z' {
			lower[i] += 'a' - 'A'
		}
	}
	if !bytes.Equal(cw, lower) {
		t.Errorf("AppendCanonicalWireFormat() = % x, want % x", cw, lower)
	}
}

func TestParseResourceRecordHTTPS(t *testing.T) {
	// A HTTPS record in a message.
	var w WireFormat
	w.AppendDomainName(testDomainName(t, "svc.example.com."), nil)
	w.AppendUInt16(uint16(TYPE_HTTPS))
	w.AppendUInt16(uint16(CLASS_IN))
	w.AppendUInt32(3600)
	w.AppendUInt16(uint16(len(httpsRDATA)))
	w.AppendBytes(httpsRDATA)

	rr, pos, err := ParseResourceRecord(w, 0)
	if err != nil {
		t.Fatalf("ParseResourceRecord() error = %v", err)
	}
	if pos != uint32(len(w)) {
		t.Errorf("ParseResourceRecord() pos = %v, want %v", pos, len(w))
	}
	if rr.Type != TYPE_HTTPS {
		t.Errorf("Type = %v, want TYPE_HTTPS", rr.Type)
	}
	if rr.TTL != 3600 {
		t.Errorf("TTL = %v, want 3600", rr.TTL)
	}
	rdata, ok := rr.RData.(RecordHTTPS)
	if !ok {
		t.Fatalf("RData = %T, want RecordHTTPS", rr.RData)
	}
	if !reflect.DeepEqual(rdata, httpsWant(t)) {
		t.Errorf("RData = %v, want %v", rdata, httpsWant(t))
	}

	// The record type name and the HTTPS type code round-trip.
	if TYPE_HTTPS.String() != "HTTPS" {
		t.Errorf("TYPE_HTTPS.String() = %q, want %q", TYPE_HTTPS.String(), "HTTPS")
	}
	if n, err := NewType("HTTPS"); err != nil || n != TYPE_HTTPS {
		t.Errorf("NewType(%q) = %v, %v, want TYPE_HTTPS, nil", "HTTPS", n, err)
	}
	if n, err := NewType("TYPE65"); err != nil || n != TYPE_HTTPS {
		t.Errorf("NewType(%q) = %v, %v, want TYPE_HTTPS, nil", "TYPE65", n, err)
	}
	if TYPE_HTTPS != 65 {
		t.Errorf("TYPE_HTTPS = %d, want 65", TYPE_HTTPS)
	}
	if TYPE_SVCB != 64 {
		t.Errorf("TYPE_SVCB = %d, want 64", TYPE_SVCB)
	}
}

func TestRecordHTTPSJSON(t *testing.T) {
	// A HTTPS record marshals with the shape RecordSVCB writes, and it
	// unmarshals into a RecordHTTPS rather than a RecordSVCB.
	tests := []struct {
		name string
		r    RecordHTTPS
		want string
	}{
		{
			name: "record with alpn and port",
			r:    newHTTPS(t, "1 svc.example.com. alpn=h2,h3 port=8443"),
			want: `{"SvcParams":[{"Key":"alpn","Raw":"AmgyAmgz","Value":"h2,h3"},{"Key":"port","Raw":"IPs","Value":"8443"}],"SvcPriority":1,"TargetName":"svc.example.com."}`,
		},
		{
			name: "AliasMode record without SvcParams",
			r:    newHTTPS(t, "0 alias.example.com."),
			want: `{"SvcParams":[],"SvcPriority":0,"TargetName":"alias.example.com."}`,
		},
		{
			name: "record with no-default-alpn and ech",
			r:    newHTTPS(t, `1 . alpn=h2 no-default-alpn ech="\000\001"`),
			want: `{"SvcParams":[{"Key":"alpn","Raw":"Amgy","Value":"h2"},{"Key":"no-default-alpn","Raw":"","Value":""},{"Key":"ech","Raw":"AAE","Value":"\"\\000\\001\""}],"SvcPriority":1,"TargetName":"."}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.r)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			if string(data) != tt.want {
				t.Errorf("json.Marshal() = %s, want %s", data, tt.want)
			}

			// Unmarshalling the RDATA on its own gives the record back.
			var got RecordHTTPS
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.r) {
				t.Errorf("json.Unmarshal() got = %v, want %v", got, tt.r)
			}

			// Unmarshalling the record as the RData of a resource record keeps
			// the HTTPS type.
			rr := ResourceRecord{
				Name:  testDomainName(t, "svc.example.com."),
				Class: CLASS_IN,
				Type:  TYPE_HTTPS,
				TTL:   3600,
				RData: tt.r,
			}
			rrData, err := json.Marshal(rr)
			if err != nil {
				t.Fatalf("json.Marshal(record) error = %v", err)
			}
			if !bytes.Contains(rrData, []byte(`"Type":"HTTPS"`)) {
				t.Errorf("json.Marshal(record) = %s, which does not name the HTTPS type", rrData)
			}
			var gotRR ResourceRecord
			if err := json.Unmarshal(rrData, &gotRR); err != nil {
				t.Fatalf("json.Unmarshal(record) error = %v", err)
			}
			gotRData, ok := gotRR.RData.(*RecordHTTPS)
			if !ok {
				t.Fatalf("RData = %T, want *RecordHTTPS", gotRR.RData)
			}
			if !reflect.DeepEqual(*gotRData, tt.r) {
				t.Errorf("RData = %v, want %v", gotRData, tt.r)
			}
		})
	}
}

func TestRecordHTTPSUnmarshalJSONErrors(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{
			name: "unknown SvcParamKey",
			data: `{"SvcPriority":1,"TargetName":"svc.example.com.","SvcParams":[{"Key":"zzz","Value":"x"}]}`,
		},
		{
			name: "SvcParam value that does not fit its key",
			data: `{"SvcPriority":1,"TargetName":"svc.example.com.","SvcParams":[{"Key":"port","Value":"80,443"}]}`,
		},
		{
			name: "AliasMode record with SvcParams",
			data: `{"SvcPriority":0,"TargetName":"alias.example.com.","SvcParams":[{"Key":"alpn","Value":"h2"}]}`,
		},
		{
			name: "mandatory param naming a key the record does not have",
			data: `{"SvcPriority":1,"TargetName":"svc.example.com.","SvcParams":[{"Key":"mandatory","Value":"alpn"}]}`,
		},
		{
			name: "Raw that is not base64",
			data: `{"SvcPriority":1,"TargetName":"svc.example.com.","SvcParams":[{"Key":"alpn","Raw":"!!!"}]}`,
		},
		{
			name: "SvcParams that is not a list",
			data: `{"SvcPriority":1,"TargetName":"svc.example.com.","SvcParams":"alpn=h2"}`,
		},
		{
			name: "TargetName that is not a domain name",
			data: `{"SvcPriority":1,"TargetName":"svc..example.com.","SvcParams":[]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r RecordHTTPS
			err := json.Unmarshal([]byte(tt.data), &r)
			if err == nil {
				t.Fatalf("json.Unmarshal(%s) did not report an error", tt.data)
			}
			if !wantErrNamesRecord(err, "HTTPS") {
				t.Errorf("json.Unmarshal(%s) error = %q, which does not name the HTTPS record", tt.data, err)
			}
		})
	}
}

// newHTTPS returns the HTTPS record of the given presentation-format string for
// the JSON tests below.
func newHTTPS(t *testing.T, s string) RecordHTTPS {
	t.Helper()
	r, err := NewRecordHTTPSFromString(s)
	if err != nil {
		t.Fatalf("NewRecordHTTPSFromString(%q): %v", s, err)
	}
	return r
}
