package dnsmsg

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
)

// RecordDS represents a DS (Delegation Signer) record per RFC 4034 Section 5.1
type RecordDS struct {
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     []byte
}

// DigestType constants for DS records
const (
	DigestTypeSHA1   uint8 = 1
	DigestTypeSHA256 uint8 = 2
	DigestTypeGOST94 uint8 = 3
	DigestTypeSHA384 uint8 = 4
)

func (r RecordDS) Type() ResourceType {
	return TYPE_DS
}

func (r RecordDS) String() string {
	digestStr := ""
	for _, b := range r.Digest {
		digestStr += fmt.Sprintf("%02x", b)
	}
	return fmt.Sprintf("%d %d %d %s", r.KeyTag, r.Algorithm, r.DigestType, digestStr)
}

func (r RecordDS) CanonicalWireFormat() []byte {
	w := new(WireFormat)
	r.AppendCanonicalWireFormat(w)
	return *w
}

func (r RecordDS) AppendWireFormat(w *WireFormat, db *NameCompressionDB) uint32 {
	var size uint32 = 0
	size += w.AppendUInt16(r.KeyTag)
	size += w.AppendUInt8(r.Algorithm)
	size += w.AppendUInt8(r.DigestType)
	size += w.AppendBytes(r.Digest)
	return size
}

func (r RecordDS) AppendCanonicalWireFormat(w *WireFormat) uint32 {
	return r.AppendWireFormat(w, nil)
}

// MarshalJSON encodes the record as a JSON object.  The delegation
// digest is encoded as a lower-case hexadecimal string, matching the
// presentation format.
func (r RecordDS) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"KeyTag":     r.KeyTag,
		"Algorithm":  r.Algorithm,
		"DigestType": r.DigestType,
		"Digest":     hex.EncodeToString(r.Digest),
	})
}

// NewRecordDS creates a new RecordDS from structured values
func NewRecordDS(keyTag uint16, algorithm uint8, digestType uint8, digest []byte) RecordDS {
	return RecordDS{
		KeyTag:     keyTag,
		Algorithm:  algorithm,
		DigestType: digestType,
		Digest:     digest,
	}
}

// NewRecordDSFromString parses a DS record from presentation format string
// Format: <key-tag> <algorithm> <digest-type> <hex-digest>
func NewRecordDSFromString(s string) (RecordDS, error) {
	pattern := regexp.MustCompile(`^(\d+) (\d+) (\d+) ([0-9a-fA-F:]+)$`)
	matched := pattern.FindStringSubmatch(s)
	if matched == nil {
		return RecordDS{}, fmt.Errorf(`invalid DS record format "%s"`, s)
	}

	keyTag, err := strconv.ParseUint(matched[1], 10, 16)
	if err != nil {
		return RecordDS{}, fmt.Errorf(`invalid key tag "%s"`, matched[1])
	}

	algorithm, err := strconv.ParseUint(matched[2], 10, 8)
	if err != nil {
		return RecordDS{}, fmt.Errorf(`invalid algorithm "%s"`, matched[2])
	}

	digestType, err := strconv.ParseUint(matched[3], 10, 8)
	if err != nil {
		return RecordDS{}, fmt.Errorf(`invalid digest type "%s"`, matched[3])
	}

	// Parse hex digest (with optional colons)
	hexDigest := regexp.MustCompile(`:`).ReplaceAllString(matched[4], "")
	digest, err := hexDecode(hexDigest)
	if err != nil {
		return RecordDS{}, fmt.Errorf(`invalid digest "%s"`, matched[4])
	}

	return RecordDS{
		KeyTag:     uint16(keyTag),
		Algorithm:  uint8(algorithm),
		DigestType: uint8(digestType),
		Digest:     digest,
	}, nil
}

// ParseRecordDS parses a DS record from wire format. The digest is bounded
// by end, the RDLENGTH-derived offset of the record, rather than the
// remainder of the whole message.
func ParseRecordDS(w WireFormat, begin uint32, end uint32) (r RecordDS, pos uint32, err error) {
	var p uint32 = begin

	keyTag, err := w.GetUInt16(p)
	if err != nil {
		err = fmt.Errorf("cannot parse key tag: %w", err)
		return
	}
	p += 2

	algorithm, err := w.GetUInt8(p)
	if err != nil {
		err = fmt.Errorf("cannot parse algorithm: %w", err)
		return
	}
	p += 1

	digestType, err := w.GetUInt8(p)
	if err != nil {
		err = fmt.Errorf("cannot parse digest type: %w", err)
		return
	}
	p += 1

	// The digest occupies the remainder of the record's RDATA, bounded by
	// end rather than the end of the whole message.
	if end > uint32(w.Size()) {
		err = fmt.Errorf("invalid DS record RDATA size")
		return
	}
	if end < p {
		err = fmt.Errorf("empty digest")
		return
	}
	digest := w[p:end]
	if len(digest) == 0 {
		err = fmt.Errorf("empty digest")
		return
	}

	r = RecordDS{
		KeyTag:     keyTag,
		Algorithm:  algorithm,
		DigestType: digestType,
		Digest:     digest,
	}
	pos = end
	return
}

// hexDecode decodes a hex string to bytes
func hexDecode(s string) ([]byte, error) {
	result := make([]byte, 0, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		if i+1 >= len(s) {
			return nil, fmt.Errorf("odd number of hex digits")
		}
		var b byte
		_, err := fmt.Sscanf(s[i:i+2], "%02x", &b)
		if err != nil {
			return nil, err
		}
		result = append(result, b)
	}
	return result, nil
}
