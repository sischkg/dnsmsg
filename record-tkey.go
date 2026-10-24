package dnsmsg

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
)

// RecordTKEY represents a TKEY record (RFC 2930 Section 2).
//
// The Key Size and Other Size fields of the wire format are not stored: they
// are the lengths of KeyData and OtherData.
//
// A TKEY record is a meta-RR: it is not stored in a zone and not cached.  Its
// CLASS is ignored and SHOULD be ANY, and its TTL is meaningless and SHOULD be
// zero so that older implementations do not cache it.  There MUST NOT be more
// than one TKEY record in a DNS query or response (RFC 2930 Section 3).
type RecordTKEY struct {
	Algorithm  DomainName
	Inception  uint32
	Expiration uint32
	Mode       uint16
	Error      uint16
	KeyData    []byte
	OtherData  []byte
}

// TKEY modes (RFC 2930 Section 2.5).  Modes 1 through 5 are the modes the
// specification names; mode 0 and mode 65535 are reserved and the modes
// between them are unassigned.
const (
	TKEYModeReserved           uint16 = 0
	TKEYModeServerAssignment   uint16 = 1
	TKEYModeDHExchange         uint16 = 2
	TKEYModeGSSAPI             uint16 = 3
	TKEYModeResolverAssignment uint16 = 4
	TKEYModeKeyDeletion        uint16 = 5
)

// TKEY error codes (RFC 2930 Section 2.6).  The Error field is an extended
// RCODE: TKEYErrorNoError through TKEYErrorRefused are the DNS RCODEs and
// TKEYErrorBadSig through TKEYErrorBadAlg are the extended RCODEs, the same
// values the TSIG error codes use.
const (
	TKEYErrorNoError uint16 = 0
	TKEYErrorFormErr uint16 = 1

	TKEYErrorServFail  uint16 = 2
	TKEYErrorNameError uint16 = 3
	TKEYErrorNotImpl   uint16 = 4
	TKEYErrorRefused   uint16 = 5

	TKEYErrorBadSig uint16 = 16
	TKEYErrorBadKey uint16 = 17

	TKEYErrorBadTime uint16 = 18
	TKEYErrorBadMode uint16 = 19
	TKEYErrorBadName uint16 = 20
	TKEYErrorBadAlg  uint16 = 21
)

// TKEYErrorString renders an error code as its name.  Codes no specification
// names are rendered as ERROR followed by the number.
func TKEYErrorString(e uint16) string {
	switch e {
	case TKEYErrorNoError:
		return "NOERROR"
	case TKEYErrorFormErr:
		return "FORMERR"
	case TKEYErrorServFail:
		return "SERVFAIL"
	case TKEYErrorNameError:
		return "NXDOMAIN"
	case TKEYErrorNotImpl:
		return "NOTIMP"
	case TKEYErrorRefused:
		return "REFUSED"
	case TKEYErrorBadSig:
		return "BADSIG"
	case TKEYErrorBadKey:
		return "BADKEY"
	case TKEYErrorBadTime:
		return "BADTIME"
	case TKEYErrorBadMode:
		return "BADMODE"
	case TKEYErrorBadName:
		return "BADNAME"
	case TKEYErrorBadAlg:
		return "BADALG"
	default:
		return fmt.Sprintf("ERROR%d", e)
	}
}

// NewTKEYError reads an error code from its name or from its number.  The
// names TKEYErrorString gives to codes no specification names, such as
// "ERROR99", are read back as the number they show.
func NewTKEYError(s string) (uint16, error) {
	switch s {
	case "NOERROR":
		return TKEYErrorNoError, nil
	case "FORMERR":
		return TKEYErrorFormErr, nil
	case "SERVFAIL":
		return TKEYErrorServFail, nil
	case "NXDOMAIN":
		return TKEYErrorNameError, nil
	case "NOTIMP":
		return TKEYErrorNotImpl, nil
	case "REFUSED":
		return TKEYErrorRefused, nil
	case "BADSIG":
		return TKEYErrorBadSig, nil
	case "BADKEY":
		return TKEYErrorBadKey, nil
	case "BADTIME":
		return TKEYErrorBadTime, nil
	case "BADMODE":
		return TKEYErrorBadMode, nil
	case "BADNAME":
		return TKEYErrorBadName, nil
	case "BADALG":
		return TKEYErrorBadAlg, nil
	}
	if len(s) > 5 && s[:5] == "ERROR" {
		if e, err := strconv.ParseUint(s[5:], 10, 16); err == nil {
			return uint16(e), nil
		}
	}
	e, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf(`invalid TKEY error "%s"`, s)
	}
	return uint16(e), nil
}

// TKEYModeString renders a mode as the name of the mode RFC 2930 defines.
// Reserved and unassigned modes are rendered as their number.
func TKEYModeString(m uint16) string {
	switch m {
	case TKEYModeServerAssignment:
		return "SERVER-ASSIGNMENT"
	case TKEYModeDHExchange:
		return "DH-EXCHANGE"
	case TKEYModeGSSAPI:
		return "GSS-API"
	case TKEYModeResolverAssignment:
		return "RESOLVER-ASSIGNMENT"
	case TKEYModeKeyDeletion:
		return "KEY-DELETION"
	default:
		return strconv.FormatUint(uint64(m), 10)
	}
}

// NewTKEYMode reads a mode from the name TKEYModeString gives it or from its
// number.
func NewTKEYMode(s string) (uint16, error) {
	switch s {
	case "SERVER-ASSIGNMENT":
		return TKEYModeServerAssignment, nil
	case "DH-EXCHANGE":
		return TKEYModeDHExchange, nil
	case "GSS-API":
		return TKEYModeGSSAPI, nil
	case "RESOLVER-ASSIGNMENT":
		return TKEYModeResolverAssignment, nil
	case "KEY-DELETION":
		return TKEYModeKeyDeletion, nil
	}
	m, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf(`invalid TKEY mode "%s"`, s)
	}
	return uint16(m), nil
}

func (r RecordTKEY) Type() ResourceType {
	return TYPE_TKEY
}

// String renders the record as the presentation format this package uses for
// TKEY records: the algorithm name, the inception and expiration times, the
// mode and error names, the key data as base64, and, when it is not empty,
// the other data as base64.  RFC 2930 gives no presentation format, because a
// TKEY record does not appear in a master file; NewRecordTKEYFromString reads
// back what String produces.
func (r RecordTKEY) String() string {
	s := fmt.Sprintf("%s %d %d %s %s %s",
		r.Algorithm.String(),
		r.Inception,
		r.Expiration,
		TKEYModeString(r.Mode),
		TKEYErrorString(r.Error),
		encodeBase64(r.KeyData),
	)
	if len(r.OtherData) > 0 {
		s += " " + encodeBase64(r.OtherData)
	}
	return s
}

func (r RecordTKEY) CanonicalWireFormat() []byte {
	w := new(WireFormat)
	r.AppendCanonicalWireFormat(w)
	return *w
}

func (r RecordTKEY) AppendWireFormat(w *WireFormat, db *NameCompressionDB) uint32 {
	var size uint32 = 0
	// The algorithm name is never compressed (RFC 3597 Section 4), so db is
	// deliberately not used here.
	size += w.AppendDomainName(r.Algorithm, nil)
	size += w.AppendUInt32(r.Inception)
	size += w.AppendUInt32(r.Expiration)
	size += w.AppendUInt16(r.Mode)
	size += w.AppendUInt16(r.Error)
	size += w.AppendUInt16(uint16(len(r.KeyData)))
	size += w.AppendBytes(r.KeyData)
	size += w.AppendUInt16(uint16(len(r.OtherData)))
	size += w.AppendBytes(r.OtherData)
	return size
}

func (r RecordTKEY) AppendCanonicalWireFormat(w *WireFormat) uint32 {
	var size uint32 = 0
	size += w.AppendCanonicalDomainName(r.Algorithm)
	size += w.AppendUInt32(r.Inception)
	size += w.AppendUInt32(r.Expiration)
	size += w.AppendUInt16(r.Mode)
	size += w.AppendUInt16(r.Error)
	size += w.AppendUInt16(uint16(len(r.KeyData)))
	size += w.AppendBytes(r.KeyData)
	size += w.AppendUInt16(uint16(len(r.OtherData)))
	size += w.AppendBytes(r.OtherData)
	return size
}

// MarshalJSON encodes the record as a JSON object.  The algorithm is encoded as
// a presentation format string, the mode and the error as their names, and the
// key data and the other data as base64 strings.
func (r RecordTKEY) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"Algorithm":  r.Algorithm,
		"Inception":  r.Inception,
		"Expiration": r.Expiration,
		"Mode":       TKEYModeString(r.Mode),
		"Error":      TKEYErrorString(r.Error),
		"KeyData":    encodeBase64(r.KeyData),
		"OtherData":  encodeBase64(r.OtherData),
	})
}

// UnmarshalJSON decodes the record from the JSON object MarshalJSON produces.
// The mode and the error are accepted as names or as numbers.
func (r *RecordTKEY) UnmarshalJSON(data []byte) error {
	var fields struct {
		Algorithm  DomainName      `json:"Algorithm"`
		Inception  uint32          `json:"Inception"`
		Expiration uint32          `json:"Expiration"`
		Mode       json.RawMessage `json:"Mode"`
		Error      json.RawMessage `json:"Error"`
		KeyData    string          `json:"KeyData"`
		OtherData  string          `json:"OtherData"`
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("cannot parse TKEY record: %w", err)
	}
	mode, err := decodeTKEYMode(fields.Mode)
	if err != nil {
		return fmt.Errorf("invalid TKEY mode: %w", err)
	}
	tkeyError, err := decodeTKEYError(fields.Error)
	if err != nil {
		return fmt.Errorf("invalid TKEY error: %w", err)
	}
	keyData, err := decodeBase64(fields.KeyData)
	if err != nil {
		return fmt.Errorf("invalid TKEY key data: %w", err)
	}
	otherData, err := decodeBase64(fields.OtherData)
	if err != nil {
		return fmt.Errorf("invalid TKEY other data: %w", err)
	}
	*r = RecordTKEY{
		Algorithm:  fields.Algorithm,
		Inception:  fields.Inception,
		Expiration: fields.Expiration,
		Mode:       mode,
		Error:      tkeyError,
		KeyData:    keyData,
		OtherData:  otherData,
	}
	return nil
}

// decodeTKEYMode reads a mode from a JSON value, which is either the name
// TKEYModeString gives it or its number.  An absent or null field is the
// reserved mode 0.
func decodeTKEYMode(data json.RawMessage) (uint16, error) {
	if len(data) == 0 || string(data) == "null" {
		return TKEYModeReserved, nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		return NewTKEYMode(s)
	}
	var m uint16
	if err := json.Unmarshal(data, &m); err != nil {
		return 0, fmt.Errorf("invalid mode %s", data)
	}
	return m, nil
}

// decodeTKEYError reads an error code from a JSON value, which is either the
// name TKEYErrorString gives it or its number.  An absent or null field is
// NOERROR.
func decodeTKEYError(data json.RawMessage) (uint16, error) {
	if len(data) == 0 || string(data) == "null" {
		return TKEYErrorNoError, nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		return NewTKEYError(s)
	}
	var e uint16
	if err := json.Unmarshal(data, &e); err != nil {
		return 0, fmt.Errorf("invalid error %s", data)
	}
	return e, nil
}

// NewRecordTKEY builds a TKEY record.  The key data and the other data must
// fit the 16 bit length fields of the wire format.
func NewRecordTKEY(algorithm DomainName, inception, expiration uint32, mode, tkeyError uint16, keyData, otherData []byte) (r RecordTKEY, err error) {
	if len(keyData) > 1<<16-1 {
		return r, fmt.Errorf("key data of %d octets does not fit 16 bits", len(keyData))
	}
	if len(otherData) > 1<<16-1 {
		return r, fmt.Errorf("other data of %d octets does not fit 16 bits", len(otherData))
	}
	r.Algorithm = algorithm
	r.Inception = inception
	r.Expiration = expiration
	r.Mode = mode
	r.Error = tkeyError
	r.KeyData = keyData
	r.OtherData = otherData
	return r, nil
}

// NewRecordTKEYFromString parses the format RecordTKEY.String produces.  The
// mode and the error are accepted as names or as numbers, and the trailing
// other data is optional.
func NewRecordTKEYFromString(s string) (r RecordTKEY, err error) {
	pattern := regexp.MustCompile(`^(\S+) (\d+) (\d+) ([A-Za-z0-9][A-Za-z0-9-]*) ([A-Za-z0-9]+) ([A-Za-z0-9+/]*)(?: ([A-Za-z0-9+/]*))?$`)
	matched := pattern.FindStringSubmatch(s)
	if matched == nil {
		return r, fmt.Errorf("invalid TKEY record: %s", s)
	}

	algorithm, err := NewDomainNameFromString(matched[1])
	if err != nil {
		return r, fmt.Errorf("invalid algorithm name: %s", err)
	}

	inception, e := strconv.ParseUint(matched[2], 10, 32)
	if e != nil {
		return r, fmt.Errorf("invalid inception: %s", e)
	}

	expiration, e := strconv.ParseUint(matched[3], 10, 32)
	if e != nil {
		return r, fmt.Errorf("invalid expiration: %s", e)
	}

	mode, e := NewTKEYMode(matched[4])
	if e != nil {
		return r, e
	}

	tkeyError, e := NewTKEYError(matched[5])
	if e != nil {
		return r, e
	}

	keyData, e := decodeBase64(matched[6])
	if e != nil {
		return r, fmt.Errorf("invalid key data: %s", e)
	}

	var otherData []byte
	if matched[7] != "" {
		otherData, e = decodeBase64(matched[7])
		if e != nil {
			return r, fmt.Errorf("invalid other data: %s", e)
		}
	}

	return NewRecordTKEY(algorithm, uint32(inception), uint32(expiration), mode, tkeyError, keyData, otherData)
}

// ParseRecordTKEY reads a TKEY record whose RDATA begins at begin and ends at
// end, which is the offset the RDLENGTH of the enclosing resource record points
// to.  The algorithm name is read with name compression expanded, although
// RFC 3597 Section 4 says a TKEY record must not use compression.
func ParseRecordTKEY(w WireFormat, begin uint32, end uint32) (r RecordTKEY, pos uint32, err error) {
	var p uint32 = begin

	if end > uint32(w.Size()) {
		err = fmt.Errorf("invalid TKEY record RDATA size")
		return
	}
	// The shortest TKEY RDATA is the root algorithm name, the inception and
	// expiration times, the mode, the error and the two empty length fields.
	if end < begin+1+4+4+2+2+2+2 {
		err = fmt.Errorf("not enough size for TKEY record")
		return
	}

	algorithm, p, err := NewDomainNameFromCompressedWireFormat(&w, begin)
	if err != nil {
		err = fmt.Errorf("cannot parse algorithm name: %w", err)
		return
	}

	inception, err := w.GetUInt32(p)
	if err != nil {
		err = fmt.Errorf("cannot parse inception: %w", err)
		return
	}
	p += 4

	expiration, err := w.GetUInt32(p)
	if err != nil {
		err = fmt.Errorf("cannot parse expiration: %w", err)
		return
	}
	p += 4

	mode, err := w.GetUInt16(p)
	if err != nil {
		err = fmt.Errorf("cannot parse mode: %w", err)
		return
	}
	p += 2

	tkeyError, err := w.GetUInt16(p)
	if err != nil {
		err = fmt.Errorf("cannot parse error: %w", err)
		return
	}
	p += 2

	if end-p < 2 {
		err = fmt.Errorf("truncated TKEY record")
		return
	}
	keySize, err := w.GetUInt16(p)
	if err != nil {
		err = fmt.Errorf("cannot parse key size: %w", err)
		return
	}
	p += 2
	if uint32(keySize) > end-p {
		err = fmt.Errorf("TKEY key data exceeds RDATA")
		return
	}
	keyData, err := w.GetBytes(p, uint32(keySize))
	if err != nil {
		err = fmt.Errorf("cannot parse key data: %w", err)
		return
	}
	p += uint32(keySize)

	if end-p < 2 {
		err = fmt.Errorf("truncated TKEY record")
		return
	}
	otherSize, err := w.GetUInt16(p)
	if err != nil {
		err = fmt.Errorf("cannot parse other data size: %w", err)
		return
	}
	p += 2
	if uint32(otherSize) > end-p {
		err = fmt.Errorf("TKEY other data exceeds RDATA")
		return
	}
	otherData, err := w.GetBytes(p, uint32(otherSize))
	if err != nil {
		err = fmt.Errorf("cannot parse other data: %w", err)
		return
	}
	p += uint32(otherSize)

	if p != end {
		err = fmt.Errorf("TKEY record does not fill its RDATA")
		return
	}

	r.Algorithm = algorithm
	r.Inception = inception
	r.Expiration = expiration
	r.Mode = mode
	r.Error = tkeyError
	r.KeyData = keyData
	r.OtherData = otherData

	pos = end
	return
}
