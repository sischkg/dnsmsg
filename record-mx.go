package dnsmsg

import (
	"fmt"
	"strconv"
	"strings"
)

// RecordMX represents an MX (Mail Exchanger) record per RFC 1035 Section 3.3.1
type RecordMX struct {
	Preference uint16
	Exchange   Domainname
}

func (r RecordMX) Type() ResourceType {
	return TYPE_MX
}

func (r RecordMX) String() string {
	return fmt.Sprintf("%d %s", r.Preference, r.Exchange.String())
}

func (r RecordMX) CanonicalWireFormat() []byte {
	w := new(WireFormat)
	r.AppendCanonicalWireFormat(w)
	return *w
}

func (r RecordMX) AppendWireFormat(w *WireFormat, db *NameCompressionDB) uint32 {
	var size uint32 = 0
	size += w.AppendUInt16(r.Preference)
	size += w.AppendDomainname(r.Exchange, db)
	return size
}

func (r RecordMX) AppendCanonicalWireFormat(w *WireFormat) uint32 {
	var size uint32 = 0
	size += w.AppendUInt16(r.Preference)
	size += w.AppendCanonicalDomainname(r.Exchange)
	return size
}

// NewRecordMX creates a new RecordMX from structured values
func NewRecordMX(preference uint16, exchange Domainname) RecordMX {
	return RecordMX{
		Preference: preference,
		Exchange:   exchange,
	}
}

// NewRecordMXFromString parses an MX record from presentation format string
// Format: <preference> <exchange>
func NewRecordMXFromString(s string) (RecordMX, error) {
	fields := strings.Fields(s)
	if len(fields) != 2 {
		return RecordMX{}, fmt.Errorf(`invalid MX record format "%s"`, s)
	}

	pref, err := strconv.ParseUint(fields[0], 10, 16)
	if err != nil {
		return RecordMX{}, fmt.Errorf(`invalid preference "%s"`, fields[0])
	}

	exchange, err := NewDomainname(fields[1])
	if err != nil {
		return RecordMX{}, fmt.Errorf(`invalid exchange name "%s"`, fields[1])
	}

	return NewRecordMX(uint16(pref), exchange), nil
}

// ParseRecordMX parses an MX record from wire format
func ParseRecordMX(w WireFormat, begin uint32) (r RecordMX, end uint32, err error) {
	var p uint32 = begin

	pref, err := w.GetUInt16(p)
	if err != nil {
		err = fmt.Errorf("cannot parse preference: %w", err)
		return
	}
	p += 2

	exchange, p, err := NewDomainnameFromWireFormat(w, p)
	if err != nil {
		err = fmt.Errorf("cannot parse exchange: %w", err)
		return
	}

	r = RecordMX{
		Preference: pref,
		Exchange:   exchange,
	}
	end = p
	return
}
