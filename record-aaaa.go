package dnsmsg

import (
	"encoding/json"
	"fmt"
	"net/netip"
)

type RecordAAAA struct {
	address [16]byte
}

func (aaaa RecordAAAA) Type() ResourceType {
	return TYPE_AAAA
}

func (aaaa RecordAAAA) String() string {
	ip := netip.AddrFrom16(aaaa.address)
	return ip.String()
}

func (aaaa RecordAAAA) CanonicalWireFormat() []byte {
	return aaaa.address[:]
}

func (aaaa RecordAAAA) AppendWireFormat(w *WireFormat, db *NameCompressionDB) uint32 {
	return w.AppendBytes(aaaa.address[:])
}

func (aaaa RecordAAAA) AppendCanonicalWireFormat(w *WireFormat) uint32 {
	return w.AppendBytes(aaaa.address[:])
}

func NewRecordAAAAFromString(addr string) (record RecordAAAA, err error) {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return
	}
	if ip.Is4() {
		err = fmt.Errorf("%s is not IPv6 address", addr)
		return
	}
	record.address = ip.As16()
	return
}

// MarshalJSON encodes the record as a JSON object.  The address is
// encoded as its presentation-format string (RFC 4208 IPv6 text).
func (aaaa RecordAAAA) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"address": aaaa.String(),
	})
}

// UnmarshalJSON decodes the record from the JSON object MarshalJSON
// produces, taking the address from its presentation-format string.
func (aaaa *RecordAAAA) UnmarshalJSON(data []byte) error {
	var fields struct {
		Address string `json:"address"`
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("cannot parse AAAA record: %w", err)
	}
	rec, err := NewRecordAAAAFromString(fields.Address)
	if err != nil {
		return err
	}
	*aaaa = rec
	return nil
}

func NewRecordAAAA(addr [16]byte) (record RecordAAAA) {
	record.address = addr
	return
}

// ParseRecordAAAA parses an AAAA record from the wire format.
// The AAAA address is 16 bytes in network byte order (RFC 4038).
func ParseRecordAAAA(msg WireFormat, begin uint32) (aaaa RecordAAAA, end uint32, err error) {
	if begin+16 > uint32(msg.Size()) {
		err = fmt.Errorf("invalid AAAA record RDATA size")
		return
	}
	// The wire format uses network byte order which matches netip's 16-byte representation.
	ip, ok := netip.AddrFromSlice(msg[begin : begin+16])
	if !ok {
		err = fmt.Errorf("cannot parse AAAA address")
		return
	}
	if ip.Is4() {
		err = fmt.Errorf("AAAA record contains IPv4-mapped address")
		return
	}
	aaaa.address = ip.As16()
	end = begin + 16
	return
}

// AppendUInt16 is available on WireFormat, used by MX.
// Re-exported here for documentation only; MX uses the method directly.
