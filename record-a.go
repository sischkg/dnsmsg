package dnsmsg

import (
	"fmt"
	"net/netip"
)

type RecordA struct {
	address [4]byte
}

func (a RecordA) Type() ResourceType {
	return TYPE_A
}

func (a RecordA) String() string {
	return fmt.Sprintf("%d.%d.%d.%d", a.address[0], a.address[1], a.address[2], a.address[3])
}

func (a RecordA) CanonicalWireFormat() []byte {
	return a.address[0:4]
}

func (a RecordA) AppendWireFormat(w *WireFormat, db *NameCompressionDB) uint32 {
	return w.AppendBytes(a.address[0:4])
}

func (a RecordA) AppendCanonicalWireFormat(w *WireFormat) uint32 {
	return w.AppendBytes(a.address[0:4])
}

func NewRecordAFromString(addr string) (address RecordA, err error) {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return
	}
	if !a.Is4() {
		err = fmt.Errorf("%s is not IPv4 address", addr)
		return
	}
	address.address = a.As4()
	err = nil
	return
}

func NewRecordA(addr [4]byte) (address RecordA) {
	address.address = addr
	return
}

func ParseRecordA(msg WireFormat, begin uint32) (a RecordA, end uint32, err error) {
	if begin+4 > uint32(msg.Size()) {
		err = fmt.Errorf("invalid A record RDATA size")
		return
	}

	return NewRecordA([4]byte(msg[begin : begin+4])), begin + 4, nil
}
