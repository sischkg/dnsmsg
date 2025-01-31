package dnsmsg

import (
	"fmt"
)

type RecordRaw struct {
	Data  []byte
	rtype ResourceType
}

func (a RecordRaw) Type() ResourceType {
	return a.rtype
}

func (a RecordRaw) String() string {
	return "raw"
}

func (a RecordRaw) CanonicalWireFormat() []byte {
	return a.Data
}

func (a RecordRaw) AppendWireFormat(w *WireFormat, db *NameCompressionDB) uint32 {
	return w.AppendBytes(a.Data)
}

func (a RecordRaw) AppendCanonicalWireFormat(w *WireFormat) uint32 {
	return w.AppendBytes(a.Data)
}

func NewRecordRaw(data []byte) (r RecordRaw) {
	r.Data = data
	return
}

func ParseRecordRaw(msg WireFormat, begin uint32, end uint32) (RecordRaw, uint32, error) {
	if end > uint32(msg.Size()) {
		return NewRecordRaw([]byte{}), begin, fmt.Errorf("invalid A record RDATA size")
	}

	return NewRecordRaw(msg[begin:end]), end, nil
}
