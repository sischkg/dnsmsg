package dnsmsg

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// RecordTLSA represents a TLSA record per RFC 6698.
//
// A TLSA record names the certificate, or the public key of the certificate,
// that a client is to expect when it connects to the service the record's name
// gives.  The name is a service label such as _443._tcp.example.com (RFC 7671
// Section 3.1), and the RDATA is the certificate association data, which is a
// hash of the certificate or of its public key, together with the three
// one-octet fields that say how the certificate is to be used and how the
// association data was made.  The RDLENGTH is the length of the association
// data: 35 octets for a SHA-256 hash, 67 for a SHA-512 hash, and 4 or more
// for the other matching types.
//
// The library only reads and writes the record.  It does not compute the
// association data, and it does not check that the association data is a hash
// of the length its matching type says: a sender may use a matching type the
// specification does not assign, and a receiver must still be able to read the
// record.
type RecordTLSA struct {
	CertificateUsage uint8
	Selector         uint8
	MatchingType     uint8
	Data             []byte
}

// The certificate usage field.  The short names are those of the IANA "TLSA
// Certificate Usages" registry (RFC 6698 Section 7.2); the same values are
// called PKIX-TA, PKIX-EE, DANE-TA and DANE-EE in RFC 7671.  Values 4 through
// 254 are unassigned, and 255 is reserved for private use.
const (
	TLSACertUsageCA                   uint8 = 0 // CA constraint
	TLSACertUsageServiceConstraint    uint8 = 1 // service certificate constraint
	TLSACertUsageTrustAnchorAssertion uint8 = 2 // trust anchor assertion
	TLSACertUsageDomainIssued         uint8 = 3 // domain-issued certificate
	TLSACertUsagePrivate              uint8 = 255
)

// The selector field: which part of the certificate the association data was
// made from (RFC 6698 Section 2.1.2 and Section 7.3).  Values 2 through 254
// are unassigned, and 255 is reserved for private use.
const (
	TLSASelectorFullCertificate uint8 = 0
	TLSASelectorSPKI            uint8 = 1
	TLSASelectorPrivate         uint8 = 255
)

// The matching type field: how the association data was made from what the
// selector selected (RFC 6698 Section 2.1.3 and Section 7.4).  Matching type 1
// is the SHA-256 hash and matching type 2 is the SHA-512 hash.  Values 3
// through 254 are unassigned, and 255 is reserved for private use.
const (
	TLSAMatchingNoHash  uint8 = 0
	TLSAMatchingSHA256  uint8 = 1
	TLSAMatchingSHA512  uint8 = 2
	TLSAMatchingPrivate uint8 = 255
)

const (
	// A TLSA record is the three one-octet fields followed by the certificate
	// association data, so its shortest possible RDATA is 4 octets.
	tlsaRDataSize = 4

	// The longest certificate association data that fits in an RDATA: RDLENGTH
	// is 16 bits and the three fixed fields take 3 octets.
	tlsaMaxDataSize = 1<<16 - 1 - 3

	// The presentation format shows each of the three one-octet fields as a
	// decimal integer, which is at most 3 digits (RFC 6698 Section 3).
	tlsaMaxFieldDigits = 3
)

func (r RecordTLSA) Type() ResourceType {
	return TYPE_TLSA
}

// String returns the presentation format of the record: the certificate usage,
// the selector and the matching type as decimal integers, and the certificate
// association data as a string of lower-case hexadecimal digits
// (RFC 6698 Section 3).  A string longer than 255 characters may be broken by
// whitespace when it is written in a master file, which
// NewRecordTLSAFromString reads back as the same record.
func (r RecordTLSA) String() string {
	return fmt.Sprintf("%d %d %d %s",
		r.CertificateUsage, r.Selector, r.MatchingType, hex.EncodeToString(r.Data))
}

// CanonicalWireFormat returns the RDATA of the record.  A TLSA record has no
// domain name, so its canonical wire format and its RDATA are the same bytes
// (RFC 6698).
func (r RecordTLSA) CanonicalWireFormat() []byte {
	w := new(WireFormat)
	r.AppendCanonicalWireFormat(w)
	return *w
}

// AppendWireFormat appends the RDATA of the record: the certificate usage, the
// selector and the matching type as single octets, and then the certificate
// association data.  db is not used because the record holds no domain name.
func (r RecordTLSA) AppendWireFormat(w *WireFormat, db *NameCompressionDB) uint32 {
	var size uint32 = 0
	size += w.AppendUInt8(r.CertificateUsage)
	size += w.AppendUInt8(r.Selector)
	size += w.AppendUInt8(r.MatchingType)
	size += w.AppendBytes(r.Data)
	return size
}

func (r RecordTLSA) AppendCanonicalWireFormat(w *WireFormat) uint32 {
	return r.AppendWireFormat(w, nil)
}

// NewRecordTLSA creates a RecordTLSA from the certificate usage, the selector,
// the matching type and the certificate association data.  An error is
// returned when the association data is empty, or longer than an RDATA can
// hold.
func NewRecordTLSA(certUsage, selector, matchingType uint8, data []byte) (RecordTLSA, error) {
	if len(data) == 0 {
		return RecordTLSA{}, fmt.Errorf("empty TLSA certificate association data")
	}
	if len(data) > tlsaMaxDataSize {
		return RecordTLSA{}, fmt.Errorf("TLSA certificate association data of %d octets does not fit in an RDATA", len(data))
	}
	return RecordTLSA{
		CertificateUsage: certUsage,
		Selector:         selector,
		MatchingType:     matchingType,
		Data:             data,
	}, nil
}

// NewRecordTLSAFromHex creates a RecordTLSA whose certificate association data
// is given as a string of hexadecimal digits, as the presentation format and
// JSON show it.  Upper and lower case digits are both accepted.
func NewRecordTLSAFromHex(certUsage, selector, matchingType uint8, hexData string) (RecordTLSA, error) {
	data, err := hexDecodeTLSA(hexData)
	if err != nil {
		return RecordTLSA{}, err
	}
	return NewRecordTLSA(certUsage, selector, matchingType, data)
}

// NewRecordTLSAFromString parses a TLSA record from the presentation format:
// the certificate usage, the selector and the matching type as decimal
// integers, and the certificate association data as a string of hexadecimal
// digits.  Master files break a string of hexadecimal digits at the end of a
// line (RFC 6698 Section 3), so the association data may also be given as
// several whitespace separated strings, which are joined before they are
// decoded.
func NewRecordTLSAFromString(s string) (RecordTLSA, error) {
	fields := strings.Fields(s)
	if len(fields) < 4 {
		return RecordTLSA{}, fmt.Errorf("invalid TLSA record: expected a certificate usage, a selector, a matching type and a certificate association data, got %d field(s)", len(fields))
	}

	certUsage, err := parseTLSAField("certificate usage", fields[0])
	if err != nil {
		return RecordTLSA{}, err
	}
	selector, err := parseTLSAField("selector", fields[1])
	if err != nil {
		return RecordTLSA{}, err
	}
	matchingType, err := parseTLSAField("matching type", fields[2])
	if err != nil {
		return RecordTLSA{}, err
	}

	data, err := hexDecodeTLSA(strings.Join(fields[3:], ""))
	if err != nil {
		return RecordTLSA{}, err
	}

	return NewRecordTLSA(certUsage, selector, matchingType, data)
}

// ParseRecordTLSA parses a TLSA record from wire format.  The certificate
// association data occupies the remainder of the record's RDATA, bounded by
// end, the RDLENGTH-derived offset of the record, rather than the remainder of
// the whole message: no field of a TLSA record carries a length of its own
// (RFC 6698 Section 2.1).  The octets are copied, so that changing the
// message does not change the record.
func ParseRecordTLSA(w WireFormat, begin uint32, end uint32) (r RecordTLSA, pos uint32, err error) {
	var p uint32 = begin

	if end > uint32(w.Size()) {
		err = fmt.Errorf("invalid TLSA record RDATA size")
		return
	}
	// The shortest TLSA RDATA is the three fixed fields and one octet of
	// association data.
	if end < begin+tlsaRDataSize {
		err = fmt.Errorf("not enough size for TLSA record")
		return
	}

	certUsage, err := w.GetUInt8(p)
	if err != nil {
		err = fmt.Errorf("cannot parse certificate usage: %w", err)
		return
	}
	p++

	selector, err := w.GetUInt8(p)
	if err != nil {
		err = fmt.Errorf("cannot parse selector: %w", err)
		return
	}
	p++

	matchingType, err := w.GetUInt8(p)
	if err != nil {
		err = fmt.Errorf("cannot parse matching type: %w", err)
		return
	}
	p++

	data := make([]byte, end-p)
	copy(data, w[p:end])

	r = RecordTLSA{
		CertificateUsage: certUsage,
		Selector:         selector,
		MatchingType:     matchingType,
		Data:             data,
	}
	pos = end
	return
}

// parseTLSAField reads one of the one-octet fields of a TLSA record from the
// decimal integer the presentation format gives it (RFC 6698 Section 3).  A
// field that is not 0 through 255 cannot be read.
func parseTLSAField(name, s string) (uint8, error) {
	if len(s) == 0 || len(s) > tlsaMaxFieldDigits {
		return 0, fmt.Errorf("invalid TLSA record: invalid %s %q", name, s)
	}
	n, err := strconv.ParseUint(s, 10, 8)
	if err != nil {
		return 0, fmt.Errorf("invalid TLSA record: invalid %s %q", name, s)
	}
	return uint8(n), nil
}

// hexDecodeTLSA decodes the certificate association data from a string of
// hexadecimal digits.  A record whose association data is empty cannot be
// read: the association data is the whole reason a TLSA record exists.
func hexDecodeTLSA(s string) ([]byte, error) {
	if len(s) == 0 {
		return nil, fmt.Errorf("invalid TLSA record: empty certificate association data")
	}
	data, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid TLSA record: invalid certificate association data %q", s)
	}
	if len(data) > tlsaMaxDataSize {
		return nil, fmt.Errorf("TLSA certificate association data of %d octets does not fit in an RDATA", len(data))
	}
	return data, nil
}

// MarshalJSON encodes the record as a JSON object.  The certificate
// association data is encoded as a lower-case hexadecimal string, which is
// what the presentation format uses for it.
func (r RecordTLSA) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"CertificateUsage": r.CertificateUsage,
		"Selector":         r.Selector,
		"MatchingType":     r.MatchingType,
		"Data":             hex.EncodeToString(r.Data),
	})
}

// UnmarshalJSON decodes the record from the JSON object MarshalJSON produces,
// taking the certificate association data from its hexadecimal string.  The
// three one-octet fields are also accepted as decimal strings.
func (r *RecordTLSA) UnmarshalJSON(data []byte) error {
	var fields struct {
		CertificateUsage json.RawMessage `json:"CertificateUsage"`
		Selector         json.RawMessage `json:"Selector"`
		MatchingType     json.RawMessage `json:"MatchingType"`
		Data             string          `json:"Data"`
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("cannot parse TLSA record: %w", err)
	}

	certUsage, err := decodeTLSAField("certificate usage", fields.CertificateUsage)
	if err != nil {
		return err
	}
	selector, err := decodeTLSAField("selector", fields.Selector)
	if err != nil {
		return err
	}
	matchingType, err := decodeTLSAField("matching type", fields.MatchingType)
	if err != nil {
		return err
	}
	association, err := hexDecodeTLSA(fields.Data)
	if err != nil {
		return err
	}

	r.CertificateUsage = certUsage
	r.Selector = selector
	r.MatchingType = matchingType
	r.Data = association
	return nil
}

// decodeTLSAField reads one of the one-octet fields of a TLSA record from a
// JSON number, or from a JSON string holding the decimal integer the
// presentation format uses for it.
func decodeTLSAField(name string, raw json.RawMessage) (uint8, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return 0, fmt.Errorf("invalid TLSA record: missing %s", name)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return parseTLSAField(name, s)
	}
	var n uint8
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, fmt.Errorf("invalid TLSA record: invalid %s", name)
	}
	return n, nil
}
