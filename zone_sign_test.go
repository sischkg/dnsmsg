package dnsmsg

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

func buildSignableZone(t *testing.T) Zone {
	t.Helper()
	origin := testDomainName(t, "example.com.")

	www := testDomainName(t, "www.example.com.")
	a1 := NewRecordA([4]byte{192, 0, 2, 1})
	a2 := NewRecordA([4]byte{192, 0, 2, 2})
	wwwRS := NewRRSet(www, CLASS_IN, TYPE_A, 3600, a1, a2)

	ns := testDomainName(t, "ns.example.com.")
	nsRR := NewRecordNS(ns)
	originNS := NewRRSet(origin, CLASS_IN, TYPE_NS, 86400, nsRR)

	z := NewZone(origin, 3600)
	z.AddRRSet(wwwRS)
	z.AddRRSet(originNS)
	return z
}

func TestZoneSignRSA(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	z := buildSignableZone(t)
	signerName := testDomainName(t, "example.com.")

	records, err := z.Sign(privateKey, 8 /* RSASHA256 */, 12345, signerName, 1700000000, 1800000000)
	if err != nil {
		t.Fatalf("Zone.Sign() error = %v", err)
	}

	// 期待するレコード数：
	// - www A の RRSIG (1)
	// - origin NS の RRSIG (1)
	// - www の NSEC (1)
	// - www NSEC の RRSIG (1)
	// - origin の NSEC (1)
	// - origin NSEC の RRSIG (1)
	// 合計 6
	if len(records) != 6 {
		t.Errorf("len(records) = %d, want 6", len(records))
	}

	// すべてのレコードを検証
	typeCheck := map[ResourceType]int{}
	for _, rr := range records {
		typeCheck[rr.Type]++
	}
	if typeCheck[TYPE_RRSIG] != 4 {
		t.Errorf("TYPE_RRSIG count = %d, want 4", typeCheck[TYPE_RRSIG])
	}
	if typeCheck[TYPE_NSEC] != 2 {
		t.Errorf("TYPE_NSEC count = %d, want 2", typeCheck[TYPE_NSEC])
	}

	// 各 RRSIG の署名を検証
	pub := &privateKey.PublicKey
	for _, rr := range records {
		if rr.Type != TYPE_RRSIG {
			continue
		}
		rrsig, ok := rr.RData.(RecordRRSIG)
		if !ok {
			t.Fatalf("RRSIG record RData is not RecordRRSIG")
		}

		// 対応する RRSet を探して署名データを再構築
		var rs *RRSet
		for i := range z.RRsets {
			if z.RRsets[i].Name.Equal(rr.Name) && z.RRsets[i].Type == ResourceType(rrsig.TypeCovered) {
				rs = &z.RRsets[i]
				break
			}
		}
		// NSEC の RRSIG の場合は NSEC RRSet を構築
		if rs == nil {
			// NSEC レコードを探す
			for _, r2 := range records {
				if r2.Type == TYPE_NSEC && r2.Name.Equal(rr.Name) {
					nsec, _ := r2.RData.(RecordNSEC)
					nsecRS := NewRRSet(rr.Name, CLASS_IN, TYPE_NSEC, z.DefaultTTL, nsec)
					rs = &nsecRS
					break
				}
			}
		}
		if rs == nil {
			t.Fatalf("cannot find RRSet for RRSIG %s covered=%s", rr.Name, ResourceType(rrsig.TypeCovered))
		}

		hash := sha256.Sum256(rs.CanonicalWireFormat())
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], rrsig.Signature); err != nil {
			t.Errorf("rsa.VerifyPKCS1v15() for %s error = %v", rr.Name, err)
		}
	}

	// NSEC レコードのチェック
	for _, rr := range records {
		if rr.Type != TYPE_NSEC {
			continue
		}
		nsec, ok := rr.RData.(RecordNSEC)
		if !ok {
			t.Fatalf("NSEC record RData is not RecordNSEC")
		}
		if nsec.NextDomainName.IsRoot() && !rr.Name.Equal(z.Origin) {
			// ルートオリジンの場合のみ NextDomainName がルート
			t.Errorf("NSEC for %s: NextDomainName = %s, unexpected root", rr.Name, nsec.NextDomainName)
		}
		if len(nsec.Types) == 0 {
			t.Errorf("NSEC for %s has no types", rr.Name)
		}
	}

	// NSEC の RRSIG の TypeCovered は TYPE_NSEC であること
	for _, rr := range records {
		if rr.Type == TYPE_RRSIG {
			rrsig, _ := rr.RData.(RecordRRSIG)
			// NSEC の RRSIG は TypeCovered = TYPE_NSEC
			// www/origin の A/NS の RRSIG は TypeCovered = それぞれのタイプ
			if rrsig.TypeCovered == uint16(TYPE_NSEC) {
				if !rr.Name.Equal(rrsig.SignersName) {
					t.Logf("note: NSEC RRSIG signer name = %s", rrsig.SignersName)
				}
			}
		}
	}
}

func TestZoneSignECDSA(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}

	z := buildSignableZone(t)
	signerName := testDomainName(t, "example.com.")

	records, err := z.Sign(privateKey, 13 /* ECDSAP256SHA256 */, 54321, signerName, 1700000000, 1800000000)
	if err != nil {
		t.Fatalf("Zone.Sign() error = %v", err)
	}

	if len(records) != 6 {
		t.Errorf("len(records) = %d, want 6", len(records))
	}

	// すべての RRSIG の署名を検証
	pub := &privateKey.PublicKey
	for _, rr := range records {
		if rr.Type != TYPE_RRSIG {
			continue
		}
		rrsig, ok := rr.RData.(RecordRRSIG)
		if !ok {
			t.Fatalf("RRSIG record RData is not RecordRRSIG")
		}

		var rs *RRSet
		for i := range z.RRsets {
			if z.RRsets[i].Name.Equal(rr.Name) && z.RRsets[i].Type == ResourceType(rrsig.TypeCovered) {
				rs = &z.RRsets[i]
				break
			}
		}
		if rs == nil {
			for _, r2 := range records {
				if r2.Type == TYPE_NSEC && r2.Name.Equal(rr.Name) {
					nsec, _ := r2.RData.(RecordNSEC)
					nsecRS := NewRRSet(rr.Name, CLASS_IN, TYPE_NSEC, z.DefaultTTL, nsec)
					rs = &nsecRS
					break
				}
			}
		}
		if rs == nil {
			t.Fatalf("cannot find RRSet for RRSIG %s covered=%s", rr.Name, ResourceType(rrsig.TypeCovered))
		}

		hash := sha256.Sum256(rs.CanonicalWireFormat())
		var sig struct {
			R, S *big.Int
		}
		if _, err := asn1.Unmarshal(rrsig.Signature, &sig); err != nil {
			t.Fatalf("asn1.Unmarshal() error = %v", err)
		}
		if !ecdsa.Verify(pub, hash[:], sig.R, sig.S) {
			t.Errorf("ecdsa.Verify() for %s returned false", rr.Name)
		}
	}
}

func TestZoneSignErrors(t *testing.T) {
	z := buildSignableZone(t)
	signerName := testDomainName(t, "example.com.")

	t.Run("nil signer", func(t *testing.T) {
		if _, err := z.Sign(nil, 8, 12345, signerName, 0, 0); err == nil {
			t.Errorf("Zone.Sign() expected error for nil signer, got nil")
		}
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		if _, err := z.Sign(privateKey, 99, 12345, signerName, 0, 0); err == nil {
			t.Errorf("Zone.Sign() expected error for unsupported algorithm, got nil")
		}
	})

	t.Run("empty zone", func(t *testing.T) {
		emptyZone := NewZone(testDomainName(t, "example.com."), 3600)
		privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		records, err := emptyZone.Sign(privateKey, 8, 12345, signerName, 0, 0)
		if err != nil {
			t.Fatalf("Zone.Sign() empty zone error = %v", err)
		}
		if len(records) != 0 {
			t.Errorf("len(records) = %d, want 0 for empty zone", len(records))
		}
	})
}

func TestZoneSignNSECChain(t *testing.T) {
	// 3つの異なるオーナー名を持つゾーンで NSEC チェーンを検証
	origin := testDomainName(t, "example.com.")
	a := testDomainName(t, "a.example.com.")
	b := testDomainName(t, "b.example.com.")

	z := NewZone(origin, 3600)
	z.AddRRSet(NewRRSet(a, CLASS_IN, TYPE_A, 3600, NewRecordA([4]byte{10, 0, 0, 1})))
	z.AddRRSet(NewRRSet(b, CLASS_IN, TYPE_NS, 3600, NewRecordNS(testDomainName(t, "ns.example.com."))))
	z.AddRRSet(NewRRSet(origin, CLASS_IN, TYPE_SOA, 3600, NewRecordSOA(
		testDomainName(t, "ns.example.com."),
		testDomainName(t, "hostmaster.example.com."),
		1, 3600, 1800, 604800, 86400,
	)))

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	records, err := z.Sign(privateKey, 8, 12345, origin, 1700000000, 1800000000)
	if err != nil {
		t.Fatalf("Zone.Sign() error = %v", err)
	}

	// NSEC レコードを収集
	nsecs := make(map[string]RecordNSEC)
	for _, rr := range records {
		if rr.Type == TYPE_NSEC {
			nsec, _ := rr.RData.(RecordNSEC)
			nsecs[rr.Name.String()] = nsec
		}
	}

	if len(nsecs) != 3 {
		t.Errorf("expected 3 NSEC records, got %d", len(nsecs))
	}

	// canonical 順: a.example.com. (01 a...) < b.example.com. (01 b...) < example.com. (07 example...)
	// a -> b, b -> example.com., example.com. -> origin (example.com.)
	// 最後は orig (example.com.) に戻る

	if nsecA, ok := nsecs["a.example.com."]; ok {
		if !nsecA.NextDomainName.Equal(b) {
			t.Errorf("NSEC a.example.com. NextDomainName = %s, want b.example.com.", nsecA.NextDomainName)
		}
	}
	if nsecB, ok := nsecs["b.example.com."]; ok {
		if !nsecB.NextDomainName.Equal(origin) {
			t.Errorf("NSEC b.example.com. NextDomainName = %s, want example.com.", nsecB.NextDomainName)
		}
	}
	if nsecOrigin, ok := nsecs["example.com."]; ok {
		if !nsecOrigin.NextDomainName.Equal(origin) {
			t.Errorf("NSEC example.com. NextDomainName = %s, want example.com. (origin)", nsecOrigin.NextDomainName)
		}
	}

	// NSEC の Types に適切なタイプが含まれていること
	if nsecA, ok := nsecs["a.example.com."]; ok {
		foundA := false
		for _, typ := range nsecA.Types {
			if typ == TYPE_A {
				foundA = true
			}
		}
		if !foundA {
			t.Errorf("NSEC a.example.com. missing TYPE_A in types")
		}
	}
	if nsecOrigin, ok := nsecs["example.com."]; ok {
		foundSOA := false
		for _, typ := range nsecOrigin.Types {
			if typ == TYPE_SOA {
				foundSOA = true
			}
		}
		if !foundSOA {
			t.Errorf("NSEC example.com. missing TYPE_SOA in types")
		}
	}
}

func TestZoneSignRoundTripCanonical(t *testing.T) {
	// 署名後のレコードを正規ワイヤフォーマットにシリアライズして、
	// パースして戻ってくることを確認（基本的な整合性チェック）
	z := buildSignableZone(t)
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	signerName := testDomainName(t, "example.com.")

	records, err := z.Sign(privateKey, 8, 12345, signerName, 1700000000, 1800000000)
	if err != nil {
		t.Fatalf("Zone.Sign() error = %v", err)
	}

	for _, rr := range records {
		// w に書き出してパースする
		var w WireFormat
		db := NewNameCompressionDB()
		AppendResourceRecord(&w, rr, db)

		// パースして元と同じか
		parsed, _, err := ParseResourceRecord(w, 0)
		if err != nil {
			t.Fatalf("ParseResourceRecord() error = %v", err)
		}
		if parsed.Type != rr.Type {
			t.Errorf("parsed.Type = %v, want %v", parsed.Type, rr.Type)
		}
		if !parsed.Name.Equal(rr.Name) {
			t.Errorf("parsed.Name = %s, want %s", parsed.Name, rr.Name)
		}
		if parsed.TTL != rr.TTL {
			t.Errorf("parsed.TTL = %d, want %d", parsed.TTL, rr.TTL)
		}
		// RData の型が同じか
		if parsed.RData == nil {
			t.Errorf("parsed.RData is nil")
		}
		if rr.RData == nil {
			t.Errorf("rr.RData is nil")
		}
		if parsed.RData != nil && rr.RData != nil {
			if parsed.RData.Type() != rr.RData.Type() {
				t.Errorf("parsed RData type = %v, want %v", parsed.RData.Type(), rr.RData.Type())
			}
		}
	}
}

func TestZoneSignTTL(t *testing.T) {
	origin := testDomainName(t, "example.com.")
	name := testDomainName(t, "www.example.com.")
	z := NewZone(origin, 7200)
	z.AddRRSet(NewRRSet(name, CLASS_IN, TYPE_A, 3600, NewRecordA([4]byte{10, 0, 0, 1})))

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	records, err := z.Sign(privateKey, 8, 12345, origin, 1700000000, 1800000000)
	if err != nil {
		t.Fatalf("Zone.Sign() error = %v", err)
	}

	// www の A レコードの RRSIG は TTL 3600 を継承
	for _, rr := range records {
		if rr.Type == TYPE_RRSIG && rr.Name.Equal(name) {
			rrsig, _ := rr.RData.(RecordRRSIG)
			if rrsig.TypeCovered == uint16(TYPE_A) {
				if rr.TTL != 3600 {
					t.Errorf("RRSIG TTL = %d, want 3600 (inherited from RRSet)", rr.TTL)
				}
			}
		}
		if rr.Type == TYPE_NSEC {
			if rr.TTL != 7200 {
				t.Errorf("NSEC TTL = %d, want 7200 (zone default)", rr.TTL)
			}
		}
	}
}

func TestZoneSignWildcardRRSetVerification(t *testing.T) {
	apex := testDomainName(t, "example.com.")
	wildcard := testDomainName(t, "*.example.com.")
	expanded := testDomainName(t, "www.example.com.")

	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	dnskey := &RecordDNSKEY{
		Flags:     256,
		Protocol:  3,
		Algorithm: 8,
		PublicKey: dnskeyMaterialFromPublicKey(t, privateKey.Public()),
	}

	z := NewZone(apex, 3600)
	z.AddRRSet(NewRRSet(apex, CLASS_IN, TYPE_SOA, 3600, NewRecordSOA(
		testDomainName(t, "ns1.example.com."),
		testDomainName(t, "admin.example.com."),
		2026010101, 3600, 900, 1209600, 300,
	)))
	z.AddRRSet(NewRRSet(apex, CLASS_IN, TYPE_DNSKEY, 3600, dnskey))
	z.AddRRSet(NewRRSet(wildcard, CLASS_IN, TYPE_A, 3600, NewRecordA([4]byte{192, 0, 2, 1})))

	records, err := z.Sign(privateKey, 8, 12345, apex, 1700000000, 1800000000)
	if err != nil {
		t.Fatalf("Zone.Sign() error = %v", err)
	}

	// ゾーンにはワイルドカードが展開されないままの名前で格納され、
	// その名前のまま署名されている。
	rsWildcard, ok := z.FindRRSet(wildcard, TYPE_A)
	if !ok {
		t.Fatalf("FindRRSet(*.example.com., A) not found")
	}
	rrsig := findRRSIGFor(t, records, wildcard, TYPE_A)
	if rrsig.Labels != 2 {
		t.Errorf("wildcard RRSIG Labels = %d, want 2", rrsig.Labels)
	}
	if rrsig.OrigTTL != 3600 {
		t.Errorf("wildcard RRSIG OrigTTL = %d, want 3600", rrsig.OrigTTL)
	}

	// www.example.com. に対して提供される展開済み RRSet は、ワイルドカード名に
	// 対するこの RRSIG で検証できる。
	rsExpanded := NewRRSet(expanded, CLASS_IN, TYPE_A, rrsig.OrigTTL,
		NewRecordA([4]byte{192, 0, 2, 1}))
	if err := VerifyRRSetWithDNSKEY(&rsExpanded, rrsig, dnskey, time.Unix(1750000000, 0)); err != nil {
		t.Errorf("VerifyRRSetWithDNSKEY(www.example.com. <- *.example.com.) error = %v", err)
	}

	// 展開されないワイルドカード RRSet 自体も検証できる。
	if err := VerifyRRSetWithDNSKEY(&rsWildcard, rrsig, dnskey, time.Unix(1750000000, 0)); err != nil {
		t.Errorf("VerifyRRSetWithDNSKEY(*.example.com.) error = %v", err)
	}

	// ワイルドカードは同じ接末のより深い展開も覆う (RFC 1034 Section 4.3.3)。
	// www.sub.example.com. は Labels=2 から *.example.com. に復元されるため検証できる。
	deeper := NewRRSet(testDomainName(t, "www.sub.example.com."), CLASS_IN, TYPE_A, 3600,
		NewRecordA([4]byte{192, 0, 2, 1}))
	if err := VerifyRRSetWithDNSKEY(&deeper, rrsig, dnskey, time.Unix(1750000000, 0)); err != nil {
		t.Errorf("VerifyRRSetWithDNSKEY(www.sub.example.com. <- *.example.com.) error = %v", err)
	}

	// ワイルドカードの接末にない名前は検証できない。
	other := NewRRSet(testDomainName(t, "www.example.org."), CLASS_IN, TYPE_A, 3600,
		NewRecordA([4]byte{192, 0, 2, 1}))
	if err := VerifyRRSetWithDNSKEY(&other, rrsig, dnskey, time.Unix(1750000000, 0)); err == nil {
		t.Error("VerifyRRSetWithDNSKEY(www.example.org.) expected error, got nil")
	}
}

// findRRSIGFor は records の中から name にあり type を覆う RRSIG を 1 件返す。
func findRRSIGFor(t *testing.T, records []ResourceRecord, name DomainName, typ ResourceType) *RecordRRSIG {
	t.Helper()
	for _, rr := range records {
		if rr.Type != TYPE_RRSIG || !rr.Name.Equal(name) {
			continue
		}
		rrsig, ok := rr.RData.(RecordRRSIG)
		if !ok {
			continue
		}
		if ResourceType(rrsig.TypeCovered) == typ {
			out := rrsig
			return &out
		}
	}
	t.Fatalf("no RRSIG covering %s %s found in Zone.Sign() records", name, typ)
	return nil
}
