package dnsmsg

import (
	"fmt"
	"regexp"
	"strconv"
)

// RecordDNSKEY represents a DNSKEY record per RFC 4034 Section 5.1
type RecordDNSKEY struct {
	Flags     uint16
	Protocol  uint8
	Algorithm uint8
	PublicKey []byte
}

func (r RecordDNSKEY) Type() ResourceType {
	return TYPE_DNSKEY
}

func (r RecordDNSKEY) String() string {
	return fmt.Sprintf("%d %d %d %s", r.Flags, r.Protocol, r.Algorithm, encodeBase64(r.PublicKey))
}

func (r RecordDNSKEY) CanonicalWireFormat() []byte {
	w := new(WireFormat)
	r.AppendCanonicalWireFormat(w)
	return *w
}

func (r RecordDNSKEY) AppendWireFormat(w *WireFormat, db *NameCompressionDB) uint32 {
	var size uint32 = 0
	size += w.AppendUInt16(r.Flags)
	size += w.AppendUInt8(r.Protocol)
	size += w.AppendUInt8(r.Algorithm)
	size += w.AppendBytes(r.PublicKey)
	return size
}

func (r RecordDNSKEY) AppendCanonicalWireFormat(w *WireFormat) uint32 {
	return r.AppendWireFormat(w, nil)
}

// NewRecordDNSKEY creates a new RecordDNSKEY from structured values
func NewRecordDNSKEY(flags uint16, protocol uint8, algorithm uint8, publicKey []byte) RecordDNSKEY {
	return RecordDNSKEY{
		Flags:     flags,
		Protocol:  protocol,
		Algorithm: algorithm,
		PublicKey: publicKey,
	}
}

// NewRecordDNSKEYFromString parses a DNSKEY record from presentation format string
// Format: <flags> <protocol> <algorithm> <base64-public-key>
func NewRecordDNSKEYFromString(s string) (RecordDNSKEY, error) {
	pattern := regexp.MustCompile(`^(\d+) (\d+) (\d+) (\S+)$`)
	matched := pattern.FindStringSubmatch(s)
	if matched == nil {
		return RecordDNSKEY{}, fmt.Errorf(`invalid DNSKEY record format "%s"`, s)
	}

	flags, err := strconv.ParseUint(matched[1], 10, 16)
	if err != nil {
		return RecordDNSKEY{}, fmt.Errorf(`invalid flags "%s"`, matched[1])
	}

	protocol, err := strconv.ParseUint(matched[2], 10, 8)
	if err != nil {
		return RecordDNSKEY{}, fmt.Errorf(`invalid protocol "%s"`, matched[2])
	}

	algorithm, err := strconv.ParseUint(matched[3], 10, 8)
	if err != nil {
		return RecordDNSKEY{}, fmt.Errorf(`invalid algorithm "%s"`, matched[3])
	}

	publicKey, err := decodeBase64(matched[4])
	if err != nil {
		return RecordDNSKEY{}, fmt.Errorf(`invalid public key "%s"`, matched[4])
	}

	return RecordDNSKEY{
		Flags:     uint16(flags),
		Protocol:  uint8(protocol),
		Algorithm: uint8(algorithm),
		PublicKey: publicKey,
	}, nil
}

// ParseRecordDNSKEY parses a DNSKEY record from wire format. The public key
// is bounded by end, the RDLENGTH-derived offset of the record, rather than
// the remainder of the whole message.
func ParseRecordDNSKEY(w WireFormat, begin uint32, end uint32) (r RecordDNSKEY, pos uint32, err error) {
	var p uint32 = begin

	flags, err := w.GetUInt16(p)
	if err != nil {
		err = fmt.Errorf("cannot parse flags: %w", err)
		return
	}
	p += 2

	protocol, err := w.GetUInt8(p)
	if err != nil {
		err = fmt.Errorf("cannot parse protocol: %w", err)
		return
	}
	p += 1

	algorithm, err := w.GetUInt8(p)
	if err != nil {
		err = fmt.Errorf("cannot parse algorithm: %w", err)
		return
	}
	p += 1

	// The public key occupies the remainder of the record's RDATA, bounded by
	// end rather than the end of the whole message.
	if end > uint32(w.Size()) {
		err = fmt.Errorf("invalid DNSKEY record RDATA size")
		return
	}
	if end < p {
		err = fmt.Errorf("empty public key")
		return
	}
	publicKey := w[p:end]
	if len(publicKey) == 0 {
		err = fmt.Errorf("empty public key")
		return
	}

	r = RecordDNSKEY{
		Flags:     flags,
		Protocol:  protocol,
		Algorithm: algorithm,
		PublicKey: publicKey,
	}
	pos = end
	return
}
