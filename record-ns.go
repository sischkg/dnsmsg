package dnsmsg

type RecordNS struct {
	nsname Domainname
}

func (ns RecordNS) Size() uint32 {
	return ns.nsname.Size()
}

func (a RecordNS) Type() uint16 {
	return 2
}

func (ns RecordNS) String() string {
	return ns.nsname.String()
}

func (ns RecordNS) CanonicalWireFormat() []byte {
	return ns.nsname.CanonicalWireFormat()
}

func (ns RecordNS) AppendWireFormat(w *WireFormat, db *NameCompressionDB) {
	w.AppendDomainname(ns.nsname, db)
}

func NewRecordNSFromString(n string) (ns RecordNS, err error) {
	name, err := NewDomainname(n)
	if err != nil {
		return
	}
	return NewRecordNS(name), nil
}

func NewRecordNS(n Domainname) (ns RecordNS) {
	ns.nsname = n
	return
}

func ParseRecordNS(rdata []byte) (ns RecordNS, err error) {
	name, err := NewCanonicalDomainnameFromBytes(rdata)
	if err != nil {
		return
	}
	return NewRecordNS(name), err
}
