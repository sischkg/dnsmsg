package dnsmsg

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

// RecordOPT represents an OPT (Pseudo) record carrying EDNS(0) extensions
// in the additional section per RFC 6891.
//
// The RDATA consists of a version byte, a 16-bit flags field (bit 0x8000
// is the DNSSEC DO bit, the low four bits hold the EDNS version which
// must match the VERSION byte) and zero or more EDNS options.
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

func (r RecordOPT) AppendWireFormat(w *WireFormat, db *NameCompressionDB) uint32 {
	var size uint32 = 0
	size += w.AppendUInt8(r.Version)
	size += w.AppendUInt16(r.Flags)
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

// ParseRecordOPT parses an OPT record from wire format.  The RDATA is
// bounded by end, the RDLENGTH-derived offset of the record, rather than
// the remainder of the whole message.
func ParseRecordOPT(w WireFormat, begin uint32, end uint32) (r RecordOPT, pos uint32, err error) {
	var p uint32 = begin

	if end > uint32(w.Size()) {
		err = fmt.Errorf("invalid OPT record RDATA size")
		return
	}
	if end < begin+3 {
		err = fmt.Errorf("not enough size for OPT record")
		return
	}

	version, err := w.GetUInt8(p)
	if err != nil {
		err = fmt.Errorf("cannot parse version: %w", err)
		return
	}
	p += 1

	flags, err := w.GetUInt16(p)
	if err != nil {
		err = fmt.Errorf("cannot parse flags: %w", err)
		return
	}
	p += 2

	// Per RFC 6891 Section 6.1.3, the EDNS version in the flags field
	// (the low four bits) must match the VERSION byte.
	if uint8(flags&0x0f) != version {
		err = fmt.Errorf("EDNS version mismatch: flags=%d version=%d", flags, version)
		return
	}

	r.Version = version
	r.Flags = flags

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
