package dnsmsg

import (
	"bytes"
	"fmt"
	"sort"
)

// Zone は DNS ゾーンを表します。オリジン（ゾーンのルートドメイン名）、
// デフォルト TTL、およびゾーン内の RRSet の集合を持ちます。
// DNSSEC の署名対象となる RRSet をまとめて管理するために使用します。
type Zone struct {
	// Origin はゾーンのオリジン（ルートドメイン名）です。
	Origin DomainName
	// DefaultTTL はゾーン内のレコードに適用されるデフォルト TTL（秒）です。
	DefaultTTL uint32
	// RRsets はゾーンに含まれる RRSet のリストです。
	RRsets []RRSet
}

// NewZone は新しい Zone を構築します。
func NewZone(origin DomainName, defaultTTL uint32) Zone {
	return Zone{
		Origin:      origin,
		DefaultTTL:  defaultTTL,
		RRsets:      nil,
	}
}

// AddRRSet はゾーンに RRSet を追加します。
func (z *Zone) AddRRSet(rs RRSet) {
	z.RRsets = append(z.RRsets, rs)
}

// FindRRSet は指定したオーナー名とタイプの RRSet を検索します。
// 複数見つかった場合は最初のものを返します。見つからない場合は false を返します。
func (z Zone) FindRRSet(name DomainName, typ ResourceType) (RRSet, bool) {
	for _, rs := range z.RRsets {
		if rs.Name.Equal(name) && rs.Type == typ {
			return rs, true
		}
	}
	return RRSet{}, false
}

// RemoveRRSet は指定したオーナー名とタイプの RRSet をすべて削除します。
func (z *Zone) RemoveRRSet(name DomainName, typ ResourceType) {
	kept := z.RRsets[:0]
	for _, rs := range z.RRsets {
		if !(rs.Name.Equal(name) && rs.Type == typ) {
			kept = append(kept, rs)
		}
	}
	z.RRsets = kept
}

// Len はゾーンに含まれる RRSet の数を返します。
func (z Zone) Len() int {
	return len(z.RRsets)
}

// Equal は二つの Zone が等しいかを比較します。
func (lhs Zone) Equal(rhs Zone) bool {
	if !lhs.Origin.Equal(rhs.Origin) {
		return false
	}
	if lhs.DefaultTTL != rhs.DefaultTTL {
		return false
	}
	if len(lhs.RRsets) != len(rhs.RRsets) {
		return false
	}
	for i := range lhs.RRsets {
		if !lhs.RRsets[i].Equal(rhs.RRsets[i]) {
			return false
		}
	}
	return true
}

// String はゾーンをゾーンファイル風の人間が読める形式で返します。
func (z Zone) String() string {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "$ORIGIN %s\n", z.Origin)
	fmt.Fprintf(&buf, "$TTL %d\n", z.DefaultTTL)
	for _, rs := range z.RRsets {
		fmt.Fprintln(&buf, rs.String())
	}
	return buf.String()
}

// CanonicalWireFormat はゾーン全体の正規ワイヤフォーマットを返します。
// 各 RRSet は RFC 4034 Section 6.2 に従って正規化され、RRSet 自体は
// オーナー名とタイプの順でソートされます（ゾーン転送 AXFR の形式に準拠）。
func (z Zone) CanonicalWireFormat() []byte {
	w := new(WireFormat)
	z.AppendCanonicalWireFormat(w)
	return *w
}

// AppendCanonicalWireFormat はゾーン全体の正規ワイヤフォーマットを w に追記し、
// 書き込んだバイト数を返します。
func (z Zone) AppendCanonicalWireFormat(w *WireFormat) uint32 {
	var size uint32 = 0

	// RRSet をオーナー名とタイプの順でソートして出力する。
	ordered := z.sortedRRsets()
	for _, rs := range ordered {
		size += rs.AppendCanonicalWireFormat(w)
	}
	return size
}

// sortedRRsets は RRSet をオーナー名とタイプの順でソートしたコピーを返す。
func (z Zone) sortedRRsets() []RRSet {
	ordered := append([]RRSet(nil), z.RRsets...)
	sort.SliceStable(ordered, func(i, j int) bool {
		cmp := bytes.Compare(ordered[i].Name.CanonicalWireFormat(), ordered[j].Name.CanonicalWireFormat())
		if cmp != 0 {
			return cmp < 0
		}
		return ordered[i].Type < ordered[j].Type
	})
	return ordered
}

// ResourceRecordsToZone は ResourceRecord のリストから Zone を構築します。
// 同じ (Name, Class, Type) のレコードは同じ RRSet にグループ化されます。
// 各 RRSet の TTL は defaultTTL で上書きされます。
func ResourceRecordsToZone(origin DomainName, defaultTTL uint32, records []ResourceRecord) Zone {
	z := NewZone(origin, defaultTTL)

	type groupKey struct {
		name string
		class ResourceClass
		typ   ResourceType
	}

	groups := make(map[groupKey][]RDATA)
	order := make([]groupKey, 0)

	for _, rr := range records {
		key := groupKey{
			name: rr.Name.String(),
			class: rr.Class,
			typ:  rr.Type,
		}
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], rr.RData)
	}

	for _, key := range order {
		name, err := NewDomainNameFromString(key.name)
		if err != nil {
			// 不正な名前はスキップ
			continue
		}
		rs := NewRRSet(name, key.class, key.typ, defaultTTL)
		for _, rdata := range groups[key] {
			rs.Add(rdata)
		}
		z.AddRRSet(rs)
	}

	return z
}
