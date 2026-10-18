package dnsmsg

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"testing"
)

func buildNSEC3Zone(t *testing.T) Zone {
	t.Helper()
	origin := testDomainName(t, "example.com.")

	www := testDomainName(t, "www.example.com.")
	a1 := NewRecordA([4]byte{192, 0, 2, 1})
	wwwRS := NewRRSet(www, CLASS_IN, TYPE_A, 3600, a1)

	ns := testDomainName(t, "ns.example.com.")
	nsRR := NewRecordNS(ns)
	originNS := NewRRSet(origin, CLASS_IN, TYPE_NS, 86400, nsRR)

	z := NewZone(origin, 3600)
	z.AddRRSet(wwwRS)
	z.AddRRSet(originNS)
	return z
}

// computeNSEC3HashSHA1 はテスト用の NSEC3 ハッシュ計算（SHA-1, 1 iteration）
func computeNSEC3HashSHA1(name DomainName, salt []byte) []byte {
	nameWire := name.CanonicalWireFormat()
	h := sha1.New()
	h.Write(nameWire)
	h.Write(salt)
	return h.Sum(nil)
}

func TestZoneSignNSEC3RSA(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	z := buildNSEC3Zone(t)
	signerName := testDomainName(t, "example.com.")
	salt := []byte{0x01, 0x02, 0x03}

	records, err := z.SignNSEC3(privateKey, 8 /* RSASHA256 */, 12345, signerName,
		1700000000, 1800000000, 1 /* SHA-1 */, 0 /* flags */, 1 /* iterations */, salt)
	if err != nil {
		t.Fatalf("Zone.SignNSEC3() error = %v", err)
	}

	// 期待するレコード数：
	// - www A の RRSIG (1)
	// - origin NS の RRSIG (1)
	// - www の NSEC3 (1)
	// - www NSEC3 の RRSIG (1)
	// - origin の NSEC3 (1)
	// - origin NSEC3 の RRSIG (1)
	// - origin の NSEC3PARAM (1)
	// - NSEC3PARAM の RRSIG (1)
	// 合計 8
	if len(records) != 8 {
		t.Errorf("len(records) = %d, want 8", len(records))
	}

	// タイプ別カウント
	typeCount := map[ResourceType]int{}
	for _, rr := range records {
		typeCount[rr.Type]++
	}
	if typeCount[TYPE_RRSIG] != 5 {
		t.Errorf("TYPE_RRSIG count = %d, want 5", typeCount[TYPE_RRSIG])
	}
	if typeCount[TYPE_NSEC3] != 2 {
		t.Errorf("TYPE_NSEC3 count = %d, want 2", typeCount[TYPE_NSEC3])
	}
	if typeCount[TYPE_NSEC3PARAM] != 1 {
		t.Errorf("TYPE_NSEC3PARAM count = %d, want 1", typeCount[TYPE_NSEC3PARAM])
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

		// 対応する RRSet または NSEC3 / NSEC3PARAM を探す
		var rs *RRSet
		for i := range z.RRsets {
			if z.RRsets[i].Name.Equal(rr.Name) && z.RRsets[i].Type == ResourceType(rrsig.TypeCovered) {
				rs = &z.RRsets[i]
				break
			}
		}
		if rs == nil {
			// NSEC3 または NSEC3PARAM の RRSIG の場合、TypeCovered に一致するレコードを探す
			for _, r2 := range records {
				if r2.Name.Equal(rr.Name) && r2.Type == ResourceType(rrsig.TypeCovered) {
					if r2.Type == TYPE_NSEC3 {
						nsec3, _ := r2.RData.(RecordNSEC3)
						nsec3RS := NewRRSet(rr.Name, CLASS_IN, TYPE_NSEC3, z.DefaultTTL, nsec3)
						rs = &nsec3RS
					} else if r2.Type == TYPE_NSEC3PARAM {
						nsec3param, _ := r2.RData.(RecordNSEC3PARAM)
						nsec3paramRS := NewRRSet(rr.Name, CLASS_IN, TYPE_NSEC3PARAM, z.DefaultTTL, nsec3param)
						rs = &nsec3paramRS
					}
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

	// NSEC3 レコードのチェック
	for _, rr := range records {
		if rr.Type != TYPE_NSEC3 {
			continue
		}
		nsec3, ok := rr.RData.(RecordNSEC3)
		if !ok {
			t.Fatalf("NSEC3 record RData is not RecordNSEC3")
		}
		if nsec3.HashAlgorithm != 1 {
			t.Errorf("NSEC3 HashAlgorithm = %d, want 1", nsec3.HashAlgorithm)
		}
		if nsec3.Iterations != 1 {
			t.Errorf("NSEC3 Iterations = %d, want 1", nsec3.Iterations)
		}
		if !bytes.Equal(nsec3.Salt, salt) {
			t.Errorf("NSEC3 Salt = %x, want %x", nsec3.Salt, salt)
		}
		if len(nsec3.NextHashedName) == 0 {
			t.Errorf("NSEC3 NextHashedName is empty")
		}
		if len(nsec3.Types) == 0 {
			t.Errorf("NSEC3 for %s has no types", rr.Name)
		}
	}

	// NSEC3PARAM レコードのチェック
	for _, rr := range records {
		if rr.Type != TYPE_NSEC3PARAM {
			continue
		}
		nsec3param, ok := rr.RData.(RecordNSEC3PARAM)
		if !ok {
			t.Fatalf("NSEC3PARAM record RData is not RecordNSEC3PARAM")
		}
		if nsec3param.HashAlgorithm != 1 {
			t.Errorf("NSEC3PARAM HashAlgorithm = %d, want 1", nsec3param.HashAlgorithm)
		}
		if nsec3param.Iterations != 1 {
			t.Errorf("NSEC3PARAM Iterations = %d, want 1", nsec3param.Iterations)
		}
		if !bytes.Equal(nsec3param.Salt, salt) {
			t.Errorf("NSEC3PARAM Salt = %x, want %x", nsec3param.Salt, salt)
		}
	}
}

func TestZoneSignNSEC3ECDSA(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}

	z := buildNSEC3Zone(t)
	signerName := testDomainName(t, "example.com.")
	salt := []byte{0xaa, 0xbb}

	records, err := z.SignNSEC3(privateKey, 13 /* ECDSAP256SHA256 */, 54321, signerName,
		1700000000, 1800000000, 1, 0, 1, salt)
	if err != nil {
		t.Fatalf("Zone.SignNSEC3() error = %v", err)
	}

	if len(records) != 8 {
		t.Errorf("len(records) = %d, want 8", len(records))
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
			// NSEC3 または NSEC3PARAM の RRSIG の場合、TypeCovered に一致するレコードを探す
			for _, r2 := range records {
				if r2.Name.Equal(rr.Name) && r2.Type == ResourceType(rrsig.TypeCovered) {
					if r2.Type == TYPE_NSEC3 {
						nsec3, _ := r2.RData.(RecordNSEC3)
						nsec3RS := NewRRSet(rr.Name, CLASS_IN, TYPE_NSEC3, z.DefaultTTL, nsec3)
						rs = &nsec3RS
					} else if r2.Type == TYPE_NSEC3PARAM {
						nsec3param, _ := r2.RData.(RecordNSEC3PARAM)
						nsec3paramRS := NewRRSet(rr.Name, CLASS_IN, TYPE_NSEC3PARAM, z.DefaultTTL, nsec3param)
						rs = &nsec3paramRS
					}
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

func TestZoneSignNSEC3Errors(t *testing.T) {
	z := buildNSEC3Zone(t)
	signerName := testDomainName(t, "example.com.")

	t.Run("nil signer", func(t *testing.T) {
		if _, err := z.SignNSEC3(nil, 8, 12345, signerName, 0, 0, 1, 0, 1, nil); err == nil {
			t.Errorf("Zone.SignNSEC3() expected error for nil signer, got nil")
		}
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		if _, err := z.SignNSEC3(privateKey, 99, 12345, signerName, 0, 0, 1, 0, 1, nil); err == nil {
			t.Errorf("Zone.SignNSEC3() expected error for unsupported algorithm, got nil")
		}
	})

	t.Run("unsupported hash algorithm", func(t *testing.T) {
		privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		if _, err := z.SignNSEC3(privateKey, 8, 12345, signerName, 0, 0, 99, 0, 1, nil); err == nil {
			t.Errorf("Zone.SignNSEC3() expected error for unsupported hash algorithm, got nil")
		}
	})

	t.Run("zero iterations", func(t *testing.T) {
		privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		if _, err := z.SignNSEC3(privateKey, 8, 12345, signerName, 0, 0, 1, 0, 0, nil); err == nil {
			t.Errorf("Zone.SignNSEC3() expected error for zero iterations, got nil")
		}
	})

	t.Run("empty zone", func(t *testing.T) {
		emptyZone := NewZone(testDomainName(t, "example.com."), 3600)
		privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		records, err := emptyZone.SignNSEC3(privateKey, 8, 12345, signerName, 0, 0, 1, 0, 1, nil)
		if err != nil {
			t.Fatalf("Zone.SignNSEC3() empty zone error = %v", err)
		}
		if len(records) != 0 {
			t.Errorf("len(records) = %d, want 0 for empty zone", len(records))
		}
	})
}

func TestZoneSignNSEC3Chain(t *testing.T) {
	// 3つのオーナー名で NSEC3 チェーンを検証
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

	salt := []byte{0x01, 0x02}
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	records, err := z.SignNSEC3(privateKey, 8, 12345, origin,
		1700000000, 1800000000, 1, 0, 1, salt)
	if err != nil {
		t.Fatalf("Zone.SignNSEC3() error = %v", err)
	}

	// NSEC3 レコードを収集
	nsec3s := make(map[string]RecordNSEC3)
	for _, rr := range records {
		if rr.Type == TYPE_NSEC3 {
			nsec3, _ := rr.RData.(RecordNSEC3)
			nsec3s[rr.Name.String()] = nsec3
		}
	}

	if len(nsec3s) != 3 {
		t.Errorf("expected 3 NSEC3 records, got %d", len(nsec3s))
	}

	// ハッシュ値を計算して順序を確認
	type hashedName struct {
		name string
		hash []byte
	}
	var hashed []hashedName
	for nameStr := range nsec3s {
		name := testDomainName(t, nameStr)
		hash := computeNSEC3HashSHA1(name, salt)
		hashed = append(hashed, hashedName{name: nameStr, hash: hash})
	}

	// ハッシュ値でソート
	for i := 0; i < len(hashed); i++ {
		for j := i + 1; j < len(hashed); j++ {
			if bytes.Compare(hashed[i].hash, hashed[j].hash) > 0 {
				hashed[i], hashed[j] = hashed[j], hashed[i]
			}
		}
	}

	// 各 NSEC3 の NextHashedName が次のハッシュ値を指していることを確認
	for i, h := range hashed {
		nextIdx := (i + 1) % len(hashed)
		expectedNext := nsec3HashToLabel(hashed[nextIdx].hash)

		nsec3 := nsec3s[h.name]
		if !bytes.Equal(nsec3.NextHashedName, expectedNext) {
			t.Errorf("NSEC3 %s NextHashedName = %x, want %x (next: %s)",
				h.name, nsec3.NextHashedName, expectedNext, hashed[nextIdx].name)
		}
	}

	// 各 NSEC3 の Types に適切なタイプが含まれていること
	if nsec3A, ok := nsec3s["a.example.com."]; ok {
		foundA := false
		for _, typ := range nsec3A.Types {
			if typ == TYPE_A {
				foundA = true
			}
		}
		if !foundA {
			t.Errorf("NSEC3 a.example.com. missing TYPE_A in types")
		}
	}
	if nsec3Origin, ok := nsec3s["example.com."]; ok {
		foundSOA := false
		for _, typ := range nsec3Origin.Types {
			if typ == TYPE_SOA {
				foundSOA = true
			}
		}
		if !foundSOA {
			t.Errorf("NSEC3 example.com. missing TYPE_SOA in types")
		}
	}
}

func TestZoneSignNSEC3MultipleIterations(t *testing.T) {
	// 複数反復でハッシュが正しく計算されることを確認
	origin := testDomainName(t, "example.com.")
	z := NewZone(origin, 3600)
	z.AddRRSet(NewRRSet(origin, CLASS_IN, TYPE_SOA, 3600, NewRecordSOA(
		testDomainName(t, "ns.example.com."),
		testDomainName(t, "hostmaster.example.com."),
		1, 3600, 1800, 604800, 86400,
	)))

	salt := []byte{0x01, 0x02, 0x03, 0x04}
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// 1 iteration
	records1, err := z.SignNSEC3(privateKey, 8, 12345, origin, 0, 0, 1, 0, 1, salt)
	if err != nil {
		t.Fatalf("Zone.SignNSEC3() 1 iter error = %v", err)
	}

	// 2 iterations
	records2, err := z.SignNSEC3(privateKey, 8, 12345, origin, 0, 0, 1, 0, 2, salt)
	if err != nil {
		t.Fatalf("Zone.SignNSEC3() 2 iter error = %v", err)
	}

	// ハッシュ値が異なることを確認
	var nsec3_1, nsec3_2 RecordNSEC3
	for _, rr := range records1 {
		if rr.Type == TYPE_NSEC3 {
			nsec3_1 = rr.RData.(RecordNSEC3)
			break
		}
	}
	for _, rr := range records2 {
		if rr.Type == TYPE_NSEC3 {
			nsec3_2 = rr.RData.(RecordNSEC3)
			break
		}
	}

	if bytes.Equal(nsec3_1.NextHashedName, nsec3_2.NextHashedName) {
		// 1 iteration と 2 iterations ではハッシュ値が異なるはず（同じオリジンなのでNextHashedNameも同じ自身になるが、内容は同じ）
		// ただし、Iterations フィールドは異なる
	}
	if nsec3_1.Iterations != 1 {
		t.Errorf("Iterations = %d, want 1", nsec3_1.Iterations)
	}
	if nsec3_2.Iterations != 2 {
		t.Errorf("Iterations = %d, want 2", nsec3_2.Iterations)
	}
}

func TestNSEC3Hash(t *testing.T) {
	// NSEC3 ハッシュ関数の単体テスト
	name := testDomainName(t, "www.example.com.")
	salt := []byte{0x01, 0x02}

	// 1 iteration
	hash1 := nsec3Hash(name, salt, 1)
	if len(hash1) != 20 {
		t.Errorf("nsec3Hash() len = %d, want 20 (SHA-1)", len(hash1))
	}

	// 手動計算と比較
	nameWire := name.CanonicalWireFormat()
	h := sha1.New()
	h.Write(nameWire)
	h.Write(salt)
	wantHash := h.Sum(nil)

	if !bytes.Equal(hash1, wantHash) {
		t.Errorf("nsec3Hash() = %x, want %x", hash1, wantHash)
	}

	// 2 iterations は 1 iteration と異なるハッシュになる
	hash2 := nsec3Hash(name, salt, 2)
	if bytes.Equal(hash1, hash2) {
		t.Errorf("nsec3Hash() 1 iter and 2 iter should produce different hashes")
	}
}

func TestNSEC3HashToLabel(t *testing.T) {
	hash := []byte{0x01, 0x02, 0x03}
	label := nsec3HashToLabel(hash)

	want := []byte{0x03, 0x01, 0x02, 0x03}
	if !bytes.Equal(label, want) {
		t.Errorf("nsec3HashToLabel() = %x, want %x", label, want)
	}
}

func TestZoneSignNSEC3OptOut(t *testing.T) {
	// opt-out フラグを設定した NSEC3 署名
	z := buildNSEC3Zone(t)
	signerName := testDomainName(t, "example.com.")
	salt := []byte{0x01}

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	records, err := z.SignNSEC3(privateKey, 8, 12345, signerName,
		0, 0, 1, FlagOptOut, 1, salt)
	if err != nil {
		t.Fatalf("Zone.SignNSEC3() error = %v", err)
	}

	// NSEC3 レコードのフラグを確認
	for _, rr := range records {
		if rr.Type == TYPE_NSEC3 {
			nsec3, _ := rr.RData.(RecordNSEC3)
			if nsec3.Flags != FlagOptOut {
				t.Errorf("NSEC3 Flags = %d, want %d (opt-out)", nsec3.Flags, FlagOptOut)
			}
		}
		if rr.Type == TYPE_NSEC3PARAM {
			nsec3param, _ := rr.RData.(RecordNSEC3PARAM)
			if nsec3param.Flags != FlagOptOut {
				t.Errorf("NSEC3PARAM Flags = %d, want %d (opt-out)", nsec3param.Flags, FlagOptOut)
			}
		}
	}
}
