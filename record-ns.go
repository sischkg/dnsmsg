package dnsmsg

type RecordNS struct {
	nsname Domainname
}

func (a RecordNS) Type() ResourceType {
	return TYPE_NS
}

func (ns RecordNS) String() string {
	return ns.nsname.String()
}

func (ns RecordNS) CanonicalWireFormat() []byte {
	return ns.nsname.CanonicalWireFormat()
}

func (ns RecordNS) AppendWireFormat(w *WireFormat, db *NameCompressionDB) uint32 {
	return w.AppendDomainname(ns.nsname, db)
}

func (ns RecordNS) AppendCanonicalWireFormat(w *WireFormat) uint32 {
	return w.AppendCanonicalDomainname(ns.nsname)
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

func ParseRecordNS(w WireFormat, begin uint32) (ns RecordNS, end uint32, err error) {
	name, end, err := NewDomainnameFromWireFormat(w, begin)
	if err != nil {
		return
	}
	return NewRecordNS(name), end, err
}
