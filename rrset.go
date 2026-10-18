package dnsmsg

import (
	"bytes"
	"fmt"
	"reflect"
	"sort"
)

// RRSet は同じオーナー名・クラス・タイプを持つリソースレコードの集合です。
// DNSSEC（RFC 4034 Section 6.2）では、同一の (Name, Class, Type) を持つ
// レコードをまとめて一つの署名対象（RRSet）として扱います。
//
// ゾーンファイル上では同じ名前・タイプのレコードが複数行並ぶことがあります
// （例: example.com. に複数の A レコード）。RRSet はそれらを一つにまとめ、
// 正規ワイヤフォーマットにシリアライズして DNSSEC 署名の対象データを
// 生成します。
type RRSet struct {
	// Name はレコードのオーナー名（ドメイン名）です。
	Name DomainName
	// Class はリソースクラスです（通常は CLASS_IN）。
	Class ResourceClass
	// Type はリソースタイプです。
	Type ResourceType
	// TTL はレコードの有効期限（秒）です。
	TTL uint32
	// RData は同じタイプのレコードデータのリストです。
	// 各要素は Type に対応する RDATA 実装（RecordA など）でなければなりません。
	RData []RDATA
}

// NewRRSet は RRSet を構築します。
func NewRRSet(name DomainName, class ResourceClass, typ ResourceType, ttl uint32, rdata ...RDATA) RRSet {
	return RRSet{
		Name:  name,
		Class: class,
		Type:  typ,
		TTL:   ttl,
		RData: append([]RDATA(nil), rdata...),
	}
}

// Len は RRSet に含まれるレコード数を返します。
func (rs RRSet) Len() int {
	return len(rs.RData)
}

// Add はレコードデータを RRSet に追加します。
func (rs *RRSet) Add(rdata RDATA) {
	rs.RData = append(rs.RData, rdata)
}

// Equal は lhs と rhs が同じ RRSet かどうかを比較します。
// 名前・クラス・タイプ・TTL および各レコードデータがすべて等しい場合に true を返します。
func (lhs RRSet) Equal(rhs RRSet) bool {
	if !lhs.Name.Equal(rhs.Name) {
		return false
	}
	if lhs.Class != rhs.Class {
		return false
	}
	if lhs.Type != rhs.Type {
		return false
	}
	if lhs.TTL != rhs.TTL {
		return false
	}
	if len(lhs.RData) != len(rhs.RData) {
		return false
	}
	for i := range lhs.RData {
		if !rdataEqual(lhs.RData[i], rhs.RData[i]) {
			return false
		}
	}
	return true
}

// String は RRSet を人間が読める形式で返します。
func (rs RRSet) String() string {
	var buf bytes.Buffer
	buf.WriteString(rs.Name.String())
	buf.WriteString(" ")
	buf.WriteString(rs.Class.String())
	buf.WriteString(" ")
	buf.WriteString(rs.Type.String())
	buf.WriteString(" ")
	buf.WriteString(fmt.Sprintf("%d", rs.TTL))
	for i, rdata := range rs.RData {
		if i > 0 {
			buf.WriteString("\n")
			buf.WriteString(rs.Name.String())
			buf.WriteString(" ")
			buf.WriteString(rs.Class.String())
			buf.WriteString(" ")
			buf.WriteString(rs.Type.String())
			buf.WriteString(" ")
			buf.WriteString(fmt.Sprintf("%d", rs.TTL))
		}
		buf.WriteString(" ")
		buf.WriteString(rdata.String())
	}
	return buf.String()
}

// rdataEqual は二つの RDATA 値が等しいかを比較します。
// ポインタレシーバと値レシーバの両方を受け付けます。
func rdataEqual(a, b RDATA) bool {
	if a == nil || b == nil {
		return a == b
	}
	if reflect.TypeOf(a) != reflect.TypeOf(b) {
		return false
	}
	// 値の等価性を反射で比較する。
	return reflect.DeepEqual(a, b)
}

// sortRData は RData を canonical order（RFC 4034 Section 6.2）でソートします。
// 同一タイプの RDATA はワイヤフォーマットのバイト列の辞書順で並びます。
func (rs RRSet) sortedRData() []RDATA {
	// 各 RDATA の canonical wire format を計算してソートキーとする。
	type keyed struct {
		rdata RDATA
		key   []byte
	}
	keys := make([]keyed, 0, len(rs.RData))
	for _, rdata := range rs.RData {
		keys = append(keys, keyed{rdata: rdata, key: rdata.CanonicalWireFormat()})
	}
	sort.SliceStable(keys, func(i, j int) bool {
		return bytes.Compare(keys[i].key, keys[j].key) < 0
	})
	sorted := make([]RDATA, 0, len(keys))
	for _, k := range keys {
		sorted = append(sorted, k.rdata)
	}
	return sorted
}

// CanonicalWireFormat は RFC 4034 Section 6.2 に従った正規ワイヤフォーマットを返します。
// 各レコードは所有者名（canonical、圧縮なし・小文字ドメイン名）、クラス、タイプ、
// TTL=0、RDATA（正規形）でシリアライズされ、RDATA のバイト列の辞書順でソートされます。
// TTL は 0 に固定されます。
func (rs RRSet) CanonicalWireFormat() []byte {
	w := new(WireFormat)
	rs.AppendCanonicalWireFormat(w)
	return *w
}

// AppendCanonicalWireFormat は正規ワイヤフォーマットを w に追記し、
// 書き込んだバイト数を返します。
func (rs RRSet) AppendCanonicalWireFormat(w *WireFormat) uint32 {
	var size uint32 = 0
	for _, rdata := range rs.sortedRData() {
		size += w.AppendCanonicalDomainName(rs.Name)
		size += w.AppendUInt16(uint16(rs.Class))
		size += w.AppendUInt16(uint16(rs.Type))
		size += w.AppendUInt32(0) // canonical form では TTL は 0
		size += rdata.AppendCanonicalWireFormat(w)
	}
	return size
}
