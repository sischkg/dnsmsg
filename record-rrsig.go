package dnsmsg

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
)

// RecordRRSIG represents an RRSIG (Resource Record Signature) record per RFC 4034 Section 5.1
type RecordRRSIG struct {
	TypeCovered uint16
	Algorithm   uint8
	Labels      uint8
	OrigTTL     uint32
	Expiration  uint32
	Inception   uint32
	KeyTag      uint16
	SignersName DomainName
	Signature   []byte
}

func (r RecordRRSIG) Type() ResourceType {
	return TYPE_RRSIG
}

func (r RecordRRSIG) String() string {
	return fmt.Sprintf("%s %d %d %d %d %d %d %s %s",
		ResourceType(r.TypeCovered).String(),
		r.Algorithm,
		r.Labels,
		r.OrigTTL,
		r.Expiration,
		r.Inception,
		r.KeyTag,
		r.SignersName.String(),
		encodeBase64(r.Signature),
	)
}

func (r RecordRRSIG) CanonicalWireFormat() []byte {
	w := new(WireFormat)
	r.AppendCanonicalWireFormat(w)
	return *w
}

func (r RecordRRSIG) AppendWireFormat(w *WireFormat, db *NameCompressionDB) uint32 {
	var size uint32 = 0
	size += w.AppendUInt16(r.TypeCovered)
	size += w.AppendUInt8(r.Algorithm)
	size += w.AppendUInt8(r.Labels)
	size += w.AppendUInt32(r.OrigTTL)
	size += w.AppendUInt32(r.Expiration)
	size += w.AppendUInt32(r.Inception)
	size += w.AppendUInt16(r.KeyTag)
	size += w.AppendDomainName(r.SignersName, db)
	size += w.AppendBytes(r.Signature)
	return size
}

func (r RecordRRSIG) AppendCanonicalWireFormat(w *WireFormat) uint32 {
	var size uint32 = 0
	size += w.AppendUInt16(r.TypeCovered)
	size += w.AppendUInt8(r.Algorithm)
	size += w.AppendUInt8(r.Labels)
	size += w.AppendUInt32(r.OrigTTL)
	size += w.AppendUInt32(r.Expiration)
	size += w.AppendUInt32(r.Inception)
	size += w.AppendUInt16(r.KeyTag)
	size += w.AppendCanonicalDomainName(r.SignersName)
	size += w.AppendBytes(r.Signature)
	return size
}

// MarshalJSON encodes the record as a JSON object.  The covered type is
// encoded as a resource type name, the signer's name as a presentation
// format string, and the signature as a base64 string.
func (r RecordRRSIG) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"TypeCovered": ResourceType(r.TypeCovered).String(),
		"Algorithm":   r.Algorithm,
		"Labels":      r.Labels,
		"OrigTTL":     r.OrigTTL,
		"Expiration":  r.Expiration,
		"Inception":   r.Inception,
		"KeyTag":      r.KeyTag,
		"SignersName": r.SignersName,
		"Signature":   encodeBase64(r.Signature),
	})
}

// UnmarshalJSON decodes the record from the JSON object MarshalJSON
// produces.  The covered type is accepted as a resource type name or a
// number, the signer's name as a presentation format string and the
// signature as a base64 string.
func (r *RecordRRSIG) UnmarshalJSON(data []byte) error {
	var fields struct {
		TypeCovered json.RawMessage `json:"TypeCovered"`
		Algorithm   uint8           `json:"Algorithm"`
		Labels      uint8           `json:"Labels"`
		OrigTTL     uint32          `json:"OrigTTL"`
		Expiration  uint32          `json:"Expiration"`
		Inception   uint32          `json:"Inception"`
		KeyTag      uint16          `json:"KeyTag"`
		SignersName DomainName      `json:"SignersName"`
		Signature   string          `json:"Signature"`
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("cannot parse RRSIG record: %w", err)
	}
	typeCovered, err := decodeResourceType(fields.TypeCovered)
	if err != nil {
		return fmt.Errorf("invalid RRSIG covered type: %w", err)
	}
	signature, err := decodeBase64(fields.Signature)
	if err != nil {
		return fmt.Errorf("invalid RRSIG signature: %w", err)
	}
	*r = RecordRRSIG{
		TypeCovered: uint16(typeCovered),
		Algorithm:   fields.Algorithm,
		Labels:      fields.Labels,
		OrigTTL:     fields.OrigTTL,
		Expiration:  fields.Expiration,
		Inception:   fields.Inception,
		KeyTag:      fields.KeyTag,
		SignersName: fields.SignersName,
		Signature:   signature,
	}
	return nil
}

// NewRecordRRSIG creates a new RecordRRSIG from structured values
func NewRecordRRSIG(typeCovered uint16, algorithm uint8, labels uint8, origTTL uint32,
	expiration uint32, inception uint32, keyTag uint16, signersName DomainName, signature []byte) RecordRRSIG {
	return RecordRRSIG{
		TypeCovered: typeCovered,
		Algorithm:   algorithm,
		Labels:      labels,
		OrigTTL:     origTTL,
		Expiration:  expiration,
		Inception:   inception,
		KeyTag:      keyTag,
		SignersName: signersName,
		Signature:   signature,
	}
}

// NewRecordRRSIGFromString parses an RRSIG record from presentation format string
// Format: <type-covered> <algorithm> <labels> <orig-ttl> <expiration> <inception> <key-tag> <signers-name> <base64-signature>
func NewRecordRRSIGFromString(s string) (RecordRRSIG, error) {
	// Split by spaces, but handle domain name carefully
	pattern := regexp.MustCompile(`^(\S+) (\d+) (\d+) (\d+) (\d+) (\d+) (\d+) (\S+) (\S+)$`)
	matched := pattern.FindStringSubmatch(s)
	if matched == nil {
		return RecordRRSIG{}, fmt.Errorf(`invalid RRSIG record format "%s"`, s)
	}

	typeCoveredStr := matched[1]
	var typeCovered uint16
	// Try to parse as number first
	if tc, err := strconv.ParseUint(typeCoveredStr, 10, 16); err == nil {
		typeCovered = uint16(tc)
	} else {
		// Try as string name (A, NS, SOA, etc.)
		t, err := NewType(typeCoveredStr)
		if err != nil {
			return RecordRRSIG{}, fmt.Errorf(`invalid type-covered "%s"`, typeCoveredStr)
		}
		typeCovered = uint16(t)
	}

	algorithm, err := strconv.ParseUint(matched[2], 10, 8)
	if err != nil {
		return RecordRRSIG{}, fmt.Errorf(`invalid algorithm "%s"`, matched[2])
	}

	labels, err := strconv.ParseUint(matched[3], 10, 8)
	if err != nil {
		return RecordRRSIG{}, fmt.Errorf(`invalid labels "%s"`, matched[3])
	}

	origTTL, err := strconv.ParseUint(matched[4], 10, 32)
	if err != nil {
		return RecordRRSIG{}, fmt.Errorf(`invalid orig-ttl "%s"`, matched[4])
	}

	expiration, err := strconv.ParseUint(matched[5], 10, 32)
	if err != nil {
		return RecordRRSIG{}, fmt.Errorf(`invalid expiration "%s"`, matched[5])
	}

	inception, err := strconv.ParseUint(matched[6], 10, 32)
	if err != nil {
		return RecordRRSIG{}, fmt.Errorf(`invalid inception "%s"`, matched[6])
	}

	keyTag, err := strconv.ParseUint(matched[7], 10, 16)
	if err != nil {
		return RecordRRSIG{}, fmt.Errorf(`invalid key-tag "%s"`, matched[7])
	}

	signersName, err := NewDomainNameFromString(matched[8])
	if err != nil {
		return RecordRRSIG{}, fmt.Errorf(`invalid signers-name "%s"`, matched[8])
	}

	signature, err := decodeBase64(matched[9])
	if err != nil {
		return RecordRRSIG{}, fmt.Errorf(`invalid signature "%s"`, matched[9])
	}

	return RecordRRSIG{
		TypeCovered: typeCovered,
		Algorithm:   uint8(algorithm),
		Labels:      uint8(labels),
		OrigTTL:     uint32(origTTL),
		Expiration:  uint32(expiration),
		Inception:   uint32(inception),
		KeyTag:      uint16(keyTag),
		SignersName: signersName,
		Signature:   signature,
	}, nil
}

// ParseRecordRRSIG parses an RRSIG record from wire format. The signature is
// bounded by end, the RDLENGTH-derived offset of the record, rather than the
// remainder of the whole message.
func ParseRecordRRSIG(w WireFormat, begin uint32, end uint32) (r RecordRRSIG, pos uint32, err error) {
	var p uint32 = begin

	typeCovered, err := w.GetUInt16(p)
	if err != nil {
		err = fmt.Errorf("cannot parse type-covered: %w", err)
		return
	}
	p += 2

	algorithm, err := w.GetUInt8(p)
	if err != nil {
		err = fmt.Errorf("cannot parse algorithm: %w", err)
		return
	}
	p += 1

	labels, err := w.GetUInt8(p)
	if err != nil {
		err = fmt.Errorf("cannot parse labels: %w", err)
		return
	}
	p += 1

	origTTL, err := w.GetUInt32(p)
	if err != nil {
		err = fmt.Errorf("cannot parse orig-ttl: %w", err)
		return
	}
	p += 4

	expiration, err := w.GetUInt32(p)
	if err != nil {
		err = fmt.Errorf("cannot parse expiration: %w", err)
		return
	}
	p += 4

	inception, err := w.GetUInt32(p)
	if err != nil {
		err = fmt.Errorf("cannot parse inception: %w", err)
		return
	}
	p += 4

	keyTag, err := w.GetUInt16(p)
	if err != nil {
		err = fmt.Errorf("cannot parse key-tag: %w", err)
		return
	}
	p += 2

	signersName, p, err := NewDomainNameFromCompressedWireFormat(&w, p)
	if err != nil {
		err = fmt.Errorf("cannot parse signers-name: %w", err)
		return
	}

	// The signature occupies the remainder of the record's RDATA, bounded by
	// end rather than the end of the whole message.
	if end > uint32(w.Size()) {
		err = fmt.Errorf("invalid RRSIG record RDATA size")
		return
	}
	if end < p {
		err = fmt.Errorf("empty signature")
		return
	}
	signature := w[p:end]
	if len(signature) == 0 {
		err = fmt.Errorf("empty signature")
		return
	}

	r = RecordRRSIG{
		TypeCovered: typeCovered,
		Algorithm:   algorithm,
		Labels:      labels,
		OrigTTL:     origTTL,
		Expiration:  expiration,
		Inception:   inception,
		KeyTag:      keyTag,
		SignersName: signersName,
		Signature:   signature,
	}
	pos = end
	return
}
