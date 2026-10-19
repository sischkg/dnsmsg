package dnsmsg

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

// RecordOPT represents an OPT (Pseudo) record carrying EDNS(0) extensions
// in the additional section per RFC 6891.
//
// Version is the EDNS version and Flags is the 16-bit flags field (bit
// 0x8000 is the DNSSEC OK bit, the remaining bits are Z).  Neither is part
// of the RDATA on the wire: RFC 6891 Section 6.1.3 packs the version and
// the flags, together with the extended RCODE, into the record's TTL field,
// and the record's CLASS field carries the requestor's UDP payload size
// (Section 6.1.1).  AppendResourceRecord and ParseResourceRecord translate
// between those wire fields and this struct, so an OPT record in this
// package always has Class CLASS_IN and its TTL set to the UDP payload
// size.  The RDATA of an OPT record holds only the EDNS options, which may
// be none at all.
type RecordOPT struct {
	Version uint8
	Flags   uint16
	Options []EDNSOption
}

// EDNSOption is a single EDNS(0) option (RFC 6891 Section 6.1.4).
//
// Library users can provide their own typed EDNS(0) options by defining a
// type that satisfies this interface: Code returns the option code, Data
// returns the option's wire-format payload, and String renders the option
// in presentation format without a leading space.  RecordOPT applies the
// common "code(2) + length(2) + data" framing to Code() and Data(), and
// concatenates String() implementations (space separated) when formatting.
type EDNSOption interface {
	// Code returns the EDNS option code for this option (RFC 6891).
	Code() uint16
	// Data returns the option's wire-format payload.  For options that
	// carry no payload (such as the DNSSEC option) this returns a nil or
	// empty slice.
	Data() []byte
	// String renders the option in presentation format, without a leading
	// space.  RecordOPT joins the option strings with single spaces.
	String() string
}

// EDNSOptionDNSSEC is the zero-length EDNS(0) DNSSEC option (RFC 3225).
// Its presence signals that the sender accepts DNSSEC records.
type EDNSOptionDNSSEC struct{}

func (EDNSOptionDNSSEC) Code() uint16 {
	return EDNSOptionCodeDNSSEC
}
func (EDNSOptionDNSSEC) Data() []byte {
	return nil
}
func (EDNSOptionDNSSEC) String() string {
	return "DO"
}
func (EDNSOptionDNSSEC) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"Code": EDNSOptionCodeDNSSEC,
	})
}

// UnmarshalJSON decodes the option from the JSON object MarshalJSON
// produces.  The option carries no payload, so only the object form is
// accepted.
func (o *EDNSOptionDNSSEC) UnmarshalJSON(data []byte) error {
	var fields struct{}
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("cannot parse DNSSEC EDNS option: %w", err)
	}
	return nil
}

// EDNSOptionNSID is the EDNS(0) Name Server ID option (RFC 7873) carrying
// an opaque identifier for the name server.
type EDNSOptionNSID struct {
	ID string
}

func (EDNSOptionNSID) Code() uint16 {
	return EDNSOptionCodeNSID
}
func (o EDNSOptionNSID) Data() []byte {
	return []byte(o.ID)
}
func (o EDNSOptionNSID) String() string {
	return "NSID " + hex.EncodeToString([]byte(o.ID))
}
func (o EDNSOptionNSID) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"Code": EDNSOptionCodeNSID,
		"ID":   o.ID,
	})
}

// UnmarshalJSON decodes the option from the JSON object MarshalJSON
// produces, taking the identifier as a string.
func (o *EDNSOptionNSID) UnmarshalJSON(data []byte) error {
	var fields struct {
		ID string `json:"ID"`
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("cannot parse NSID EDNS option: %w", err)
	}
	o.ID = fields.ID
	return nil
}

// EDNSOptionEDE is the EDNS(0) Extended DNS Errors option (RFC 8914).
// It carries a 16-bit INFO-CODE indexing the "Extended DNS Error
// Codes" registry (RFC 8914 Section 4) and a variable-length UTF-8
// EXTRA-TEXT providing additional context for the error.
type EDNSOptionEDE struct {
	ErrorCode uint16
	ExtraText string
}

func (EDNSOptionEDE) Code() uint16 {
	return EDNSOptionCodeEDE
}
func (o EDNSOptionEDE) Data() []byte {
	w := new(WireFormat)
	w.AppendUInt16(o.ErrorCode)
	w.AppendBytes([]byte(o.ExtraText))
	return *w
}
func (o EDNSOptionEDE) String() string {
	if o.ExtraText == "" {
		return fmt.Sprintf("EDE %d", o.ErrorCode)
	}
	return fmt.Sprintf("EDE %d %q", o.ErrorCode, o.ExtraText)
}
func (o EDNSOptionEDE) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"Code":      EDNSOptionCodeEDE,
		"ErrorCode": o.ErrorCode,
		"ExtraText": o.ExtraText,
	})
}

// UnmarshalJSON decodes the option from the JSON object MarshalJSON
// produces.
func (o *EDNSOptionEDE) UnmarshalJSON(data []byte) error {
	var fields struct {
		ErrorCode uint16 `json:"ErrorCode"`
		ExtraText string `json:"ExtraText"`
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("cannot parse EDE EDNS option: %w", err)
	}
	o.ErrorCode = fields.ErrorCode
	o.ExtraText = fields.ExtraText
	return nil
}

// EDNSOptionRaw is a generic EDNS(0) option for codes that have no
// registered parser.  It preserves the option code and payload verbatim.
type EDNSOptionRaw struct {
	OptionCode uint16
	OptionData []byte
}

func (o EDNSOptionRaw) Code() uint16 {
	return o.OptionCode
}
func (o EDNSOptionRaw) Data() []byte {
	return o.OptionData
}
func (o EDNSOptionRaw) String() string {
	return fmt.Sprintf("%d %s", o.OptionCode, hex.EncodeToString(o.OptionData))
}
func (o EDNSOptionRaw) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"Code":       o.OptionCode,
		"OptionData": hex.EncodeToString(o.OptionData),
	})
}

// UnmarshalJSON decodes the option from the JSON object MarshalJSON
// produces, taking the payload from its hexadecimal string.  The option
// code is taken from the "Code" field.
func (o *EDNSOptionRaw) UnmarshalJSON(data []byte) error {
	var fields struct {
		Code       uint16 `json:"Code"`
		OptionData string `json:"OptionData"`
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("cannot parse raw EDNS option: %w", err)
	}
	optionData, err := hex.DecodeString(fields.OptionData)
	if err != nil {
		return fmt.Errorf("invalid EDNS option data %q: %w", fields.OptionData, err)
	}
	o.OptionCode = fields.Code
	o.OptionData = optionData
	return nil
}

// EDNS0 version (RFC 6891)
const EDNS0Version uint8 = 0

// EDNS0 (0x8000) flag in the FLAGS field:
// DNSSEC is acceptable for this client (RFC 3225).
const EDNS0FlagDO uint16 = 0x8000

// EDNS(0) option codes (RFCs 3225, 7873, 4635, 8914)
const (
	EDNSOptionCodeDNSSEC       uint16 = 1
	EDNSOptionCodeNSID         uint16 = 3
	EDNSOptionCodeClientSubnet uint16 = 8
	EDNSOptionCodeEDE          uint16 = 15
)

// EDE error codes (RFC 8914 Section 4, the IANA "Extended DNS Error
// Codes" registry).
const (
	EDECodeOther                      = 0
	EDECodeUnsupportedDNSKEYAlgorithm = 1
	EDECodeUnsupportedDSDigestType    = 2
	EDECodeStaleAnswer                = 3
	EDECodeForgedAnswer               = 4
	EDECodeDNSSECIndeterminate        = 5
	EDECodeDNSSECBogus                = 6
	EDECodeSignatureExpired           = 7
	EDECodeSignatureNotYetValid       = 8
	EDECodeDNSKEYMissing              = 9
	EDECodeRRSIGsMissing              = 10
	EDECodeNoZoneKeyBitSet            = 11
	EDECodeNSECMissing                = 12
	EDECodeCachedError                = 13
	EDECodeNotReady                   = 14
	EDECodeBlocked                    = 15
	EDECodeCensored                   = 16
	EDECodeFiltered                   = 17
	EDECodeProhibited                 = 18
	EDECodeStaleNXDOMAINAnswer        = 19
	EDECodeNotAuthoritative           = 20
	EDECodeNotSupported               = 21
	EDECodeNoReachableAuthority       = 22
	EDECodeNetworkError               = 23
	EDECodeInvalidData                = 24
)

func (r RecordOPT) Type() ResourceType {
	return TYPE_OPT
}

func (r RecordOPT) String() string {
	s := fmt.Sprintf("%04x", r.Flags)
	for _, opt := range r.Options {
		s += " " + opt.String()
	}
	return s
}

func (r RecordOPT) CanonicalWireFormat() []byte {
	w := new(WireFormat)
	r.AppendCanonicalWireFormat(w)
	return *w
}

// packedTTL returns the value to write in an OPT record's TTL field, the
// extended RCODE and flags packed as described in RFC 6891 Section 6.1.3:
//
//	byte 0 (MSB): extended RCODE
//	byte 1:       EDNS version
//	byte 2-3:     flags (DO bit and Z)
//
// This package writes an extended RCODE of zero: Message.RCODE is eight
// bits wide and cannot express the full twelve-bit response code, so a
// response code such as BADVERS (16) is not representable.
func (r RecordOPT) packedTTL() uint32 {
	return uint32(r.Version)<<16 | uint32(r.Flags)
}

// AppendWireFormat writes the RDATA of an OPT record, which per RFC 6891
// Section 6.1.2 holds only the EDNS options.  The version, the flags and
// the extended RCODE belong to the record's TTL field, and the UDP payload
// size to its CLASS field; AppendResourceRecord writes both.
func (r RecordOPT) AppendWireFormat(w *WireFormat, db *NameCompressionDB) uint32 {
	var size uint32 = 0
	for _, opt := range r.Options {
		data := opt.Data()
		size += w.AppendUInt16(opt.Code())
		size += w.AppendUInt16(uint16(len(data)))
		size += w.AppendBytes(data)
	}
	return size
}

func (r RecordOPT) AppendCanonicalWireFormat(w *WireFormat) uint32 {
	return r.AppendWireFormat(w, nil)
}

// MarshalJSON encodes the record as a JSON object.  Each EDNS option is
// encoded via the concrete option type's own MarshalJSON.
func (r RecordOPT) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"Version": r.Version,
		"Flags":   r.Flags,
		"Options": r.Options,
	})
}

func (r *RecordOPT) UnmarshalJSON(data []byte) error {
	var fields struct {
		Version uint8             `json:"Version"`
		Flags   uint16            `json:"Flags"`
		Options []json.RawMessage `json:"Options"`
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("cannot parse OPT record: %w", err)
	}
	var options []EDNSOption
	if fields.Options != nil {
		options = make([]EDNSOption, 0, len(fields.Options))
		for _, raw := range fields.Options {
			opt, err := unmarshalEDNSOption(raw)
			if err != nil {
				return err
			}
			options = append(options, opt)
		}
	}
	r.Version = fields.Version
	r.Flags = fields.Flags
	r.Options = options
	return nil
}

// unmarshalEDNSOption decodes a single EDNS option into the concrete option
// type selected by its option code, mirroring the wire-format parser.
// Option codes the library does not interpret are decoded as EDNSOptionRaw.
func unmarshalEDNSOption(data json.RawMessage) (EDNSOption, error) {
	var header struct {
		Code uint16 `json:"Code"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return nil, fmt.Errorf("cannot parse EDNS option: %w", err)
	}

	var opt EDNSOption
	switch header.Code {
	case EDNSOptionCodeDNSSEC:
		opt = new(EDNSOptionDNSSEC)
	case EDNSOptionCodeNSID:
		opt = new(EDNSOptionNSID)
	case EDNSOptionCodeEDE:
		opt = new(EDNSOptionEDE)
	default:
		raw := new(EDNSOptionRaw)
		if err := json.Unmarshal(data, raw); err != nil {
			return nil, fmt.Errorf("cannot parse EDNS option %d: %w", header.Code, err)
		}
		return raw, nil
	}
	if err := json.Unmarshal(data, opt); err != nil {
		return nil, fmt.Errorf("cannot parse EDNS option %d: %w", header.Code, err)
	}
	return opt, nil
}

// NewRecordOPT creates a new RecordOPT from structured values
func NewRecordOPT(version uint8, flags uint16, options ...EDNSOption) RecordOPT {
	return RecordOPT{
		Version: version,
		Flags:   flags,
		Options: options,
	}
}

// NewEDNSOptionNSID creates an EDNS network ID (NSID) option (RFC 7873)
// carrying the given identifier.  The identifier must be 1-255 printable
// ASCII characters.
func NewEDNSOptionNSID(nsid string) (EDNSOptionNSID, error) {
	if len(nsid) < 1 || len(nsid) > 255 {
		return EDNSOptionNSID{}, fmt.Errorf("invalid NSID length %d", len(nsid))
	}
	for _, c := range nsid {
		if c < 0x21 || c > 0x7E {
			return EDNSOptionNSID{}, fmt.Errorf("invalid character in NSID %q", nsid)
		}
	}
	return EDNSOptionNSID{ID: nsid}, nil
}

// NewEDNSOptionEDE creates an EDNS extended DNS errors option
// (RFC 8914) carrying the given 16-bit error code and (optionally
// empty) UTF-8 extra text.  The error code should be one of the
// EDECode* constants but any 16-bit value is accepted, matching
// the permissive nature of the wire format.
func NewEDNSOptionEDE(errorCode uint16, extraText string) EDNSOptionEDE {
	return EDNSOptionEDE{
		ErrorCode: errorCode,
		ExtraText: extraText,
	}
}

// ednsOptionParsers maps EDNS option codes to parsers that turn raw option
// data into a typed EDNSOption.  Unknown codes fall back to an
// EDNSOptionRaw.  The map is guarded by ednsOptionParsersMu so it can be
// registered concurrently with parsing.
var (
	ednsOptionParsersMu sync.RWMutex
	ednsOptionParsers   = map[uint16]func(data []byte) EDNSOption{
		EDNSOptionCodeDNSSEC: func(data []byte) EDNSOption { return EDNSOptionDNSSEC{} },
		EDNSOptionCodeNSID:   func(data []byte) EDNSOption { return EDNSOptionNSID{ID: string(data)} },
		EDNSOptionCodeEDE: func(data []byte) EDNSOption {
			if len(data) < 2 {
				// A well-formed EDE option needs the 2-byte INFO-CODE;
				// fall back to the raw option for truncated payloads.
				return EDNSOptionRaw{OptionCode: EDNSOptionCodeEDE, OptionData: data}
			}
			return EDNSOptionEDE{
				ErrorCode: binary.BigEndian.Uint16(data[:2]),
				ExtraText: string(data[2:]),
			}
		},
	}
)

// newEDNSOption constructs an EDNSOption for the given option code and raw
// data.  It consults the registered option parsers and returns an
// EDNSOptionRaw for codes without a parser, so parsing stays lenient on
// codes the library does not know about.
func newEDNSOption(code uint16, data []byte) EDNSOption {
	ednsOptionParsersMu.RLock()
	p, ok := ednsOptionParsers[code]
	ednsOptionParsersMu.RUnlock()
	if ok {
		return p(data)
	}
	return EDNSOptionRaw{OptionCode: code, OptionData: data}
}

// RegisterEDNSOptionParser registers a parser for an EDNS(0) option code so
// that options with that code decode into a typed EDNSOption when an OPT
// record is parsed or read from presentation format.  Registering a parser
// for a code that is already known (for example EDNSOptionCodeNSID)
// replaces the previous parser.
func RegisterEDNSOptionParser(code uint16, p func(data []byte) EDNSOption) {
	ednsOptionParsersMu.Lock()
	ednsOptionParsers[code] = p
	ednsOptionParsersMu.Unlock()
}

// NewRecordOPTFromString parses an OPT record from a presentation format
// string.  The first field is the 16-bit flags value (decimal, or hex
// with a 0x prefix; 0x8000 is the DO bit).  The remaining fields are
// options, either the DNSSEC convenience "DO" or pairs of decimal option
// code and hexadecimal option data.
// Format: <flags> [DO] ... [option-code hex-data] ...
func NewRecordOPTFromString(s string) (r RecordOPT, err error) {
	var opt RecordOPT

	fields := strings.Fields(s)
	if len(fields) < 1 {
		return opt, fmt.Errorf(`invalid OPT record format "%s"`, s)
	}

	flags, err := strconv.ParseUint(fields[0], 0, 16)
	if err != nil {
		return RecordOPT{}, fmt.Errorf(`invalid flags "%s"`, fields[0])
	}
	opt.Flags = uint16(flags)

	for i := 1; i < len(fields); {
		switch strings.ToUpper(fields[i]) {
		case "DO":
			opt.Options = append(opt.Options, newEDNSOption(EDNSOptionCodeDNSSEC, nil))
			i++
		default:
			if i+1 >= len(fields) {
				return RecordOPT{}, fmt.Errorf(`option code "%s" without data`, fields[i])
			}
			code, cErr := strconv.ParseUint(fields[i], 10, 16)
			if cErr != nil {
				return RecordOPT{}, fmt.Errorf(`invalid option code "%s"`, fields[i])
			}
			data, dErr := hex.DecodeString(fields[i+1])
			if dErr != nil {
				return RecordOPT{}, fmt.Errorf(`invalid option data "%s"`, fields[i+1])
			}
			opt.Options = append(opt.Options, newEDNSOption(uint16(code), data))
			i += 2
		}
	}

	r = opt
	return
}

// ParseRecordOPT parses the RDATA of an OPT record, which per RFC 6891
// Section 6.1.2 holds only the EDNS options and may be empty.  The RDATA is
// bounded by end, the RDLENGTH-derived offset of the record, rather than the
// remainder of the whole message.  The version, the flags and the UDP payload
// size are read from the record's TTL and CLASS fields by
// ParseResourceRecord.
func ParseRecordOPT(w WireFormat, begin uint32, end uint32) (r RecordOPT, pos uint32, err error) {
	var p uint32 = begin

	if end > uint32(w.Size()) {
		err = fmt.Errorf("invalid OPT record RDATA size")
		return
	}

	for p < end {
		if end-p < 4 {
			err = fmt.Errorf("truncated EDNS option")
			return
		}
		code, cErr := w.GetUInt16(p)
		if cErr != nil {
			err = fmt.Errorf("cannot parse option code: %w", cErr)
			return
		}
		p += 2
		size, sErr := w.GetUInt16(p)
		if sErr != nil {
			err = fmt.Errorf("cannot parse option length: %w", sErr)
			return
		}
		p += 2
		if uint32(size) > end-p {
			err = fmt.Errorf("EDNS option exceeds RDATA")
			return
		}
		data, dErr := w.GetBytes(p, uint32(size))
		if dErr != nil {
			err = fmt.Errorf("cannot parse option data: %w", dErr)
			return
		}
		p += uint32(size)

		r.Options = append(r.Options, newEDNSOption(code, data))
	}

	pos = end
	return
}
