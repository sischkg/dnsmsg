package dnsmsg

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// RecordTSIG represents a TSIG record (RFC 8945 Section 4.1).
//
// The MAC Size and Other Len fields of the wire format are not stored: they
// are the lengths of MAC and OtherData.
//
// A TSIG record is not part of a zone: it is appended to a DNS message and
// its CLASS MUST be ANY and its TTL MUST be zero.
type RecordTSIG struct {
	Algorithm  DomainName
	TimeSigned uint64
	Fudge      uint16
	MAC        []byte
	OriginalID uint16
	Error      uint16
	OtherData  []byte
}

// TSIG error codes.  The Error field holds an extended RCODE (RFC 8945
// Section 5).  NOERROR, BADSIG, BADKEY, BADTIME and BADTRUNC are assigned by
// RFC 8945; BADMODE, BADNAME and BADALG are assigned by IANA.
const (
	TSIGErrorNoError  uint16 = 0
	TSIGErrorBadSig   uint16 = 16
	TSIGErrorBadKey   uint16 = 17
	TSIGErrorBadTime  uint16 = 18
	TSIGErrorBadMode  uint16 = 19
	TSIGErrorBadName  uint16 = 20
	TSIGErrorBadAlg   uint16 = 21
	TSIGErrorBadTrunc uint16 = 22
)

// maxTSIGTimeSigned is the largest value the 48 bit Time Signed field can hold.
const maxTSIGTimeSigned uint64 = 1<<48 - 1

// TSIGErrorString renders an error code as its name.  Codes the TSIG
// specification does not name are rendered as ERROR followed by the number.
func TSIGErrorString(e uint16) string {
	switch e {
	case TSIGErrorNoError:
		return "NOERROR"
	case TSIGErrorBadSig:
		return "BADSIG"
	case TSIGErrorBadKey:
		return "BADKEY"
	case TSIGErrorBadTime:
		return "BADTIME"
	case TSIGErrorBadMode:
		return "BADMODE"
	case TSIGErrorBadName:
		return "BADNAME"
	case TSIGErrorBadAlg:
		return "BADALG"
	case TSIGErrorBadTrunc:
		return "BADTRUNC"
	default:
		return fmt.Sprintf("ERROR%d", e)
	}
}

// NewTSIGError reads an error code from its name or from its number.  The
// names TSIGErrorString gives to codes this specification does not name, such
// as "ERROR99", are read back as the number they show.
func NewTSIGError(s string) (uint16, error) {
	switch s {
	case "NOERROR":
		return TSIGErrorNoError, nil
	case "BADSIG":
		return TSIGErrorBadSig, nil
	case "BADKEY":
		return TSIGErrorBadKey, nil
	case "BADTIME":
		return TSIGErrorBadTime, nil
	case "BADMODE":
		return TSIGErrorBadMode, nil
	case "BADNAME":
		return TSIGErrorBadName, nil
	case "BADALG":
		return TSIGErrorBadAlg, nil
	case "BADTRUNC":
		return TSIGErrorBadTrunc, nil
	}
	if v, err := strconv.ParseUint(s, 10, 16); err == nil {
		return uint16(v), nil
	}
	if rest, ok := strings.CutPrefix(s, "ERROR"); ok {
		if v, err := strconv.ParseUint(rest, 10, 16); err == nil {
			return uint16(v), nil
		}
	}
	return 0, fmt.Errorf(`unknown TSIG error "%s"`, s)
}

func (r RecordTSIG) Type() ResourceType {
	return TYPE_TSIG
}

// String renders the record as
//
//	<algorithm> <time-signed> <fudge> <mac-base64> <original-id> <error> [<other-data-hex>]
//
// TSIG has no presentation format in a zone file, so this is the format this
// library uses for it.  NewRecordTSIGFromString reads it back.
func (r RecordTSIG) String() string {
	s := fmt.Sprintf("%s %d %d %s %d %s",
		r.Algorithm.String(),
		r.TimeSigned,
		r.Fudge,
		encodeBase64(r.MAC),
		r.OriginalID,
		TSIGErrorString(r.Error),
	)
	if len(r.OtherData) > 0 {
		s += " " + hex.EncodeToString(r.OtherData)
	}
	return s
}

func (r RecordTSIG) CanonicalWireFormat() []byte {
	w := new(WireFormat)
	r.AppendCanonicalWireFormat(w)
	return *w
}

func (r RecordTSIG) AppendWireFormat(w *WireFormat, db *NameCompressionDB) uint32 {
	var size uint32 = 0
	// The algorithm name is never compressed (RFC 3597 Section 4.1), so db
	// is deliberately not used here.
	size += w.AppendDomainName(r.Algorithm, nil)
	size += w.AppendUInt48(r.TimeSigned)
	size += w.AppendUInt16(r.Fudge)
	size += w.AppendUInt16(uint16(len(r.MAC)))
	size += w.AppendBytes(r.MAC)
	size += w.AppendUInt16(r.OriginalID)
	size += w.AppendUInt16(r.Error)
	size += w.AppendUInt16(uint16(len(r.OtherData)))
	size += w.AppendBytes(r.OtherData)
	return size
}

func (r RecordTSIG) AppendCanonicalWireFormat(w *WireFormat) uint32 {
	var size uint32 = 0
	size += w.AppendCanonicalDomainName(r.Algorithm)
	size += w.AppendUInt48(r.TimeSigned)
	size += w.AppendUInt16(r.Fudge)
	size += w.AppendUInt16(uint16(len(r.MAC)))
	size += w.AppendBytes(r.MAC)
	size += w.AppendUInt16(r.OriginalID)
	size += w.AppendUInt16(r.Error)
	size += w.AppendUInt16(uint16(len(r.OtherData)))
	size += w.AppendBytes(r.OtherData)
	return size
}

// NewRecordTSIG builds a TSIG record.  The time signed must fit the 48 bit
// field of the wire format, and MAC and OtherData must fit their 16 bit
// length fields.
func NewRecordTSIG(algorithm DomainName, timeSigned uint64, fudge uint16, mac []byte, originalID, tsigError uint16, otherData []byte) (r RecordTSIG, err error) {
	if timeSigned > maxTSIGTimeSigned {
		return r, fmt.Errorf("time signed %d does not fit 48 bits", timeSigned)
	}
	if len(mac) > 1<<16-1 {
		return r, fmt.Errorf("MAC of %d octets does not fit 16 bits", len(mac))
	}
	if len(otherData) > 1<<16-1 {
		return r, fmt.Errorf("other data of %d octets does not fit 16 bits", len(otherData))
	}
	r.Algorithm = algorithm
	r.TimeSigned = timeSigned
	r.Fudge = fudge
	r.MAC = mac
	r.OriginalID = originalID
	r.Error = tsigError
	r.OtherData = otherData
	return r, nil
}

// NewRecordTSIGFromString parses the format RecordTSIG.String produces.  The
// error field is accepted as a name or as a number, and the trailing other
// data is optional.
func NewRecordTSIGFromString(s string) (r RecordTSIG, err error) {
	pattern := regexp.MustCompile(`^(\S+) (\d+) (\d+) ([A-Za-z0-9+/]*) (\d+) ([A-Za-z0-9]+)(?: ([0-9a-fA-F]*))?$`)
	matched := pattern.FindStringSubmatch(s)
	if matched == nil {
		return r, fmt.Errorf("invalid TSIG record: %s", s)
	}

	algorithm, err := NewDomainNameFromString(matched[1])
	if err != nil {
		return r, fmt.Errorf("invalid algorithm name: %s", err)
	}

	timeSigned, e := strconv.ParseUint(matched[2], 10, 64)
	if e != nil {
		return r, fmt.Errorf("invalid time signed: %s", e)
	}
	if timeSigned > maxTSIGTimeSigned {
		return r, fmt.Errorf("time signed %d does not fit 48 bits", timeSigned)
	}

	fudge, e := strconv.ParseUint(matched[3], 10, 16)
	if e != nil {
		return r, fmt.Errorf("invalid fudge: %s", e)
	}

	mac, e := decodeBase64(matched[4])
	if e != nil {
		return r, fmt.Errorf("invalid MAC: %s", e)
	}

	originalID, e := strconv.ParseUint(matched[5], 10, 16)
	if e != nil {
		return r, fmt.Errorf("invalid original id: %s", e)
	}

	tsigError, e := NewTSIGError(matched[6])
	if e != nil {
		return r, e
	}

	var otherData []byte
	if matched[7] != "" {
		otherData, e = hex.DecodeString(matched[7])
		if e != nil {
			return r, fmt.Errorf("invalid other data: %s", e)
		}
	}

	return NewRecordTSIG(algorithm, timeSigned, uint16(fudge), mac, uint16(originalID), tsigError, otherData)
}

// ParseRecordTSIG reads a TSIG record whose RDATA begins at begin and ends at
// end, which is the offset the RDLENGTH of the enclosing resource record
// points to.  The algorithm name is read with name compression expanded,
// although RFC 3597 Section 4.1 says a TSIG record must not use compression.
func ParseRecordTSIG(w WireFormat, begin uint32, end uint32) (r RecordTSIG, pos uint32, err error) {
	var p uint32 = begin

	if end > uint32(w.Size()) {
		err = fmt.Errorf("invalid TSIG record RDATA size")
		return
	}
	// The shortest TSIG RDATA is the root algorithm name, the time signed,
	// the fudge, the two empty length fields, the original id, the error and
	// the empty other data length.
	if end < begin+1+6+2+2+2+2+2 {
		err = fmt.Errorf("not enough size for TSIG record")
		return
	}

	algorithm, p, err := NewDomainNameFromCompressedWireFormat(&w, begin)
	if err != nil {
		err = fmt.Errorf("cannot parse algorithm name: %w", err)
		return
	}

	timeSigned, err := w.GetUInt48(p)
	if err != nil {
		err = fmt.Errorf("cannot parse time signed: %w", err)
		return
	}
	p += 6

	fudge, err := w.GetUInt16(p)
	if err != nil {
		err = fmt.Errorf("cannot parse fudge: %w", err)
		return
	}
	p += 2

	if end-p < 2 {
		err = fmt.Errorf("truncated TSIG record")
		return
	}
	macSize, err := w.GetUInt16(p)
	if err != nil {
		err = fmt.Errorf("cannot parse MAC size: %w", err)
		return
	}
	p += 2
	if uint32(macSize) > end-p {
		err = fmt.Errorf("TSIG MAC exceeds RDATA")
		return
	}
	mac, err := w.GetBytes(p, uint32(macSize))
	if err != nil {
		err = fmt.Errorf("cannot parse MAC: %w", err)
		return
	}
	p += uint32(macSize)

	originalID, err := w.GetUInt16(p)
	if err != nil {
		err = fmt.Errorf("cannot parse original id: %w", err)
		return
	}
	p += 2

	tsigError, err := w.GetUInt16(p)
	if err != nil {
		err = fmt.Errorf("cannot parse error: %w", err)
		return
	}
	p += 2

	if end-p < 2 {
		err = fmt.Errorf("truncated TSIG record")
		return
	}
	otherLen, err := w.GetUInt16(p)
	if err != nil {
		err = fmt.Errorf("cannot parse other data length: %w", err)
		return
	}
	p += 2
	if uint32(otherLen) > end-p {
		err = fmt.Errorf("TSIG other data exceeds RDATA")
		return
	}
	otherData, err := w.GetBytes(p, uint32(otherLen))
	if err != nil {
		err = fmt.Errorf("cannot parse other data: %w", err)
		return
	}
	p += uint32(otherLen)

	if p != end {
		err = fmt.Errorf("TSIG record does not fill its RDATA")
		return
	}

	r.Algorithm = algorithm
	r.TimeSigned = timeSigned
	r.Fudge = fudge
	r.MAC = mac
	r.OriginalID = originalID
	r.Error = tsigError
	r.OtherData = otherData

	pos = end
	return
}
