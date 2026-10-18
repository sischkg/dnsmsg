package dnsmsg

import (
	"bytes"
	"testing"
)

func buildTestZone(t *testing.T) Zone {
	t.Helper()
	origin := testDomainName(t, "example.com.")

	www := testDomainName(t, "www.example.com.")
	a1 := NewRecordA([4]byte{192, 0, 2, 1})
	a2 := NewRecordA([4]byte{192, 0, 2, 2})
	wwwRRset := NewRRSet(www, CLASS_IN, TYPE_A, 3600, a1, a2)

	ns := testDomainName(t, "ns.example.com.")
	nsRR := NewRecordNS(ns)
	nsRRset := NewRRSet(origin, CLASS_IN, TYPE_NS, 86400, nsRR)

	z := NewZone(origin, 3600)
	z.AddRRSet(wwwRRset)
	z.AddRRSet(nsRRset)
	return z
}

func TestZoneNew(t *testing.T) {
	origin := testDomainName(t, "example.com.")
	z := NewZone(origin, 3600)

	if !z.Origin.Equal(origin) {
		t.Errorf("Origin = %s, want %s", z.Origin, origin)
	}
	if z.DefaultTTL != 3600 {
		t.Errorf("DefaultTTL = %d, want 3600", z.DefaultTTL)
	}
	if z.Len() != 0 {
		t.Errorf("Len() = %d, want 0", z.Len())
	}
}

func TestZoneAddRRSet(t *testing.T) {
	origin := testDomainName(t, "example.com.")
	z := NewZone(origin, 3600)

	name := testDomainName(t, "www.example.com.")
	a := NewRecordA([4]byte{10, 0, 0, 1})
	rs := NewRRSet(name, CLASS_IN, TYPE_A, 3600, a)
	z.AddRRSet(rs)

	if z.Len() != 1 {
		t.Errorf("Len() = %d, want 1", z.Len())
	}
}

func TestZoneFindRRSet(t *testing.T) {
	z := buildTestZone(t)

	name := testDomainName(t, "www.example.com.")
	rs, ok := z.FindRRSet(name, TYPE_A)
	if !ok {
		t.Fatal("FindRRSet() returned false for existing RRSet")
	}
	if rs.Type != TYPE_A {
		t.Errorf("Type = %v, want %v", rs.Type, TYPE_A)
	}
	if rs.Len() != 2 {
		t.Errorf("Len() = %d, want 2", rs.Len())
	}

	// 存在しないタイプ
	if _, ok := z.FindRRSet(name, TYPE_NS); ok {
		t.Errorf("FindRRSet() returned true for non-existent type")
	}

	// 存在しない名前
	if _, ok := z.FindRRSet(testDomainName(t, "nonexistent.example.com."), TYPE_A); ok {
		t.Errorf("FindRRSet() returned true for non-existent name")
	}
}

func TestZoneRemoveRRSet(t *testing.T) {
	z := buildTestZone(t)

	if z.Len() != 2 {
		t.Errorf("Len() = %d, want 2", z.Len())
	}

	z.RemoveRRSet(testDomainName(t, "www.example.com."), TYPE_A)
	if z.Len() != 1 {
		t.Errorf("Len() = %d, want 1 after removal", z.Len())
	}

	// もう一度削除してもエラーにならない（べき等）
	z.RemoveRRSet(testDomainName(t, "www.example.com."), TYPE_A)
	if z.Len() != 1 {
		t.Errorf("Len() = %d, want 1 after second removal", z.Len())
	}
}

func TestZoneEqual(t *testing.T) {
	z1 := buildTestZone(t)
	z2 := buildTestZone(t)

	if !z1.Equal(z2) {
		t.Errorf("z1.Equal(z2) = false, want true")
	}

	// DefaultTTL が違う
	z3 := NewZone(z1.Origin, 7200)
	z3.AddRRSet(z1.RRsets[0])
	z3.AddRRSet(z1.RRsets[1])
	if z1.Equal(z3) {
		t.Errorf("z1.Equal(z3) = true, want false (DefaultTTL differs)")
	}

	// Origin が違う
	origin2 := testDomainName(t, "other.example.com.")
	z4 := NewZone(origin2, 3600)
	z4.AddRRSet(z1.RRsets[0])
	z4.AddRRSet(z1.RRsets[1])
	if z1.Equal(z4) {
		t.Errorf("z1.Equal(z4) = true, want false (Origin differs)")
	}
}

func TestZoneString(t *testing.T) {
	z := buildTestZone(t)
	s := z.String()

	if s == "" {
		t.Errorf("String() returned empty string")
	}
	if !bytes.Contains([]byte(s), []byte("$ORIGIN example.com.")) {
		t.Errorf("String() missing $ORIGIN: %q", s)
	}
	if !bytes.Contains([]byte(s), []byte("$TTL 3600")) {
		t.Errorf("String() missing $TTL: %q", s)
	}
}

func TestZoneCanonicalWireFormat(t *testing.T) {
	z := buildTestZone(t)

	wire := z.CanonicalWireFormat()
	if len(wire) == 0 {
		t.Errorf("CanonicalWireFormat() returned empty")
	}

	// ゾーン内の RRSet が canonical DNS name order (RFC 4034 Section 6.1)
	// でソートされていることを確認。
	// ラベル数が少ない example.com. が www.example.com. より先。
	if !bytes.HasPrefix(wire, []byte{0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00}) {
		t.Errorf("CanonicalWireFormat() prefix = %x, want example.com. first", wire[:13])
	}
}

func TestZoneAppendCanonicalWireFormat(t *testing.T) {
	z := buildTestZone(t)

	var w WireFormat
	size := z.AppendCanonicalWireFormat(&w)
	if size != uint32(len(w)) {
		t.Errorf("AppendCanonicalWireFormat() size = %d, want %d", size, len(w))
	}

	want := z.CanonicalWireFormat()
	if !bytes.Equal(w, want) {
		t.Errorf("AppendCanonicalWireFormat() = %x, want %x", w, want)
	}
}

func TestZoneSortedRRsets(t *testing.T) {
	t.Helper() // 内部関数だがテスト用に公開
	origin := testDomainName(t, "example.com.")
	www := testDomainName(t, "www.example.com.")
	a := NewRecordA([4]byte{10, 0, 0, 1})
	wwwRS := NewRRSet(www, CLASS_IN, TYPE_A, 3600, a)

	ns := testDomainName(t, "ns.example.com.")
	nsRR := NewRecordNS(ns)
	originRS := NewRRSet(origin, CLASS_IN, TYPE_NS, 86400, nsRR)

	z := NewZone(origin, 3600)
	// 意図的に逆順で追加
	z.AddRRSet(wwwRS)
	z.AddRRSet(originRS)

	ordered := z.sortedRRsets()
	if len(ordered) != 2 {
		t.Errorf("sortedRRsets() len = %d, want 2", len(ordered))
	}
	// canonical DNS name order (RFC 4034 Section 6.1) ではラベル数の少ない
	// example.com. が www.example.com. より先
	if !ordered[0].Name.Equal(origin) {
		t.Errorf("sortedRRsets()[0].Name = %s, want %s", ordered[0].Name, origin)
	}
	if !ordered[1].Name.Equal(www) {
		t.Errorf("sortedRRsets()[1].Name = %s, want %s", ordered[1].Name, www)
	}
}

func TestResourceRecordsToZone(t *testing.T) {
	origin := testDomainName(t, "example.com.")

	www := testDomainName(t, "www.example.com.")
	a1 := NewRecordA([4]byte{192, 0, 2, 1})
	a2 := NewRecordA([4]byte{192, 0, 2, 2})
	ns := testDomainName(t, "ns.example.com.")
	nsRR := NewRecordNS(ns)

	records := []ResourceRecord{
		{Name: www, Class: CLASS_IN, Type: TYPE_A, TTL: 3600, RData: a1},
		{Name: origin, Class: CLASS_IN, Type: TYPE_NS, TTL: 86400, RData: nsRR},
		{Name: www, Class: CLASS_IN, Type: TYPE_A, TTL: 7200, RData: a2}, // 同じ (www, IN, A) は同じ RRSet にグループ化
	}

	z := ResourceRecordsToZone(origin, 300, records)

	if z.Len() != 2 {
		t.Errorf("Len() = %d, want 2 (records grouped into 2 RRsets)", z.Len())
	}

	// www の A レコードは 2 件グループ化される
	wwwRS, ok := z.FindRRSet(www, TYPE_A)
	if !ok {
		t.Fatal("FindRRSet(www, TYPE_A) returned false")
	}
	if wwwRS.Len() != 2 {
		t.Errorf("www A RRSet Len() = %d, want 2", wwwRS.Len())
	}
	// TTL は defaultTTL (300) で上書きされる
	if wwwRS.TTL != 300 {
		t.Errorf("www A RRSet TTL = %d, want 300", wwwRS.TTL)
	}

	// origin の NS レコードは 1 件
	originNS, ok := z.FindRRSet(origin, TYPE_NS)
	if !ok {
		t.Fatal("FindRRSet(origin, TYPE_NS) returned false")
	}
	if originNS.Len() != 1 {
		t.Errorf("origin NS RRSet Len() = %d, want 1", originNS.Len())
	}
	if originNS.TTL != 300 {
		t.Errorf("origin NS RRSet TTL = %d, want 300", originNS.TTL)
	}
}

func TestZoneEmpty(t *testing.T) {
	origin := testDomainName(t, "example.com.")
	z := NewZone(origin, 3600)

	wire := z.CanonicalWireFormat()
	if len(wire) != 0 {
		t.Errorf("CanonicalWireFormat() = %x, want empty", wire)
	}

	if _, ok := z.FindRRSet(origin, TYPE_A); ok {
		t.Errorf("FindRRSet() on empty zone returned true")
	}
}
