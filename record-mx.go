package dnsmsg

import (
	"fmt"
	"strconv"
	"strings"
)

type RecordMX struct {
	pref   uint16
	mxname Domainname
}

func (mx RecordMX) Type() ResourceType {
	return TYPE_MX
}

func (mx RecordMX) String() string {
	return fmt.Sprintf("%d %s", mx.pref, mx.mxname.String())
}

func (mx RecordMX) CanonicalWireFormat() []byte {
	var w WireFormat
	w.AppendUInt16(mx.pref)
	w.AppendCanonicalDomainname(mx.mxname)
	return w
}

func (mx RecordMX) AppendWireFormat(w *WireFormat, db *NameCompressionDB) uint32 {
	var size uint32 = 0
	size += w.AppendUInt16(mx.pref)
	size += w.AppendDomainname(mx.mxname, db)
	return size
}

func (mx RecordMX) AppendCanonicalWireFormat(w *WireFormat) uint32 {
	var size uint32 = 0
	size += w.AppendUInt16(mx.pref)
	size += w.AppendCanonicalDomainname(mx.mxname)
	return size
}

func NewRecordMXFromString(s string) (mx RecordMX, err error) {
	parts := strings.Fields(s)
	if len(parts) != 2 {
		err = fmt.Errorf(`cannot parse MX record "%s"`, s)
		return
	}
	prefNum, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		err = fmt.Errorf("cannot parse preference of MX: %v", err)
		return
	}
	mxname, err := NewDomainname(parts[1])
	if err != nil {
		err = fmt.Errorf("cannot parse mxname of MX: %v", err)
		return
	}
	mx = NewRecordMX(uint16(prefNum), mxname)
	err = nil
	return
}

func NewRecordMX(pref uint16, mxname Domainname) (mx RecordMX) {
	mx.pref = pref
	mx.mxname = mxname
	return
}

func ParseRecordMX(w WireFormat, begin uint32) (mx RecordMX, end uint32, err error) {
	if begin+2 > uint32(w.Size()) {
		err = fmt.Errorf("invalid MX record RDATA size")
		return
	}

	mx.pref, _ = w.GetUInt16(begin)
	p := begin + 2

	name, p, err := NewDomainnameFromWireFormat(w, p)
	if err != nil {
		return
	}
	mx.mxname = name
	end = p
	return
}
