package dnsmsg

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
	"time"
)

// 検証テストで使う署名の有効期間（固定の Unix セコンド）。
const (
	testInception  uint32 = 1700000000
	testExpiration uint32 = 1800000000
)

// testVerifyTime は testInception〜testExpiration の内側の時刻。
var testVerifyTime = time.Unix(1750000000, 0)

// buildVerifyTestRRSet builds the A RRSet used by the verification tests.
func buildVerifyTestRRSet(t *testing.T) RRSet {
	t.Helper()
	name := testDomainName(t, "www.example.com.")
	a1 := NewRecordA([4]byte{192, 0, 2, 1})
	a2 := NewRecordA([4]byte{192, 0, 2, 2})
	return NewRRSet(name, CLASS_IN, TYPE_A, 3600, a1, a2)
}

// buildWildcardRRSet builds the A RRSet stored under the wildcard pattern
// wildcard, such as "*.example.com.".  A wildcard RRset is stored and signed in
// the zone under its unexpanded name (RFC 4034 Section 6.2).
func buildWildcardRRSet(t *testing.T, wildcard string) RRSet {
	t.Helper()
	name := testDomainName(t, wildcard)
	a1 := NewRecordA([4]byte{192, 0, 2, 1})
	a2 := NewRecordA([4]byte{192, 0, 2, 2})
	return NewRRSet(name, CLASS_IN, TYPE_A, 3600, a1, a2)
}

// verifyTestKey holds a key pair usable with SignRRSet and VerifyRRSet for
// one DNSSEC algorithm.
type verifyTestKey struct {
	algorithm uint8
	signer    crypto.Signer
	pubkey    crypto.PublicKey
}

// newVerifyTestKey generates a key pair for the given DNSSEC algorithm.
func newVerifyTestKey(t *testing.T, algorithm uint8) verifyTestKey {
	t.Helper()
	switch algorithm {
	case 5, 7, 8, 10:
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa.GenerateKey() error = %v", err)
		}
		return verifyTestKey{algorithm, key, &key.PublicKey}
	case 13:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey(P256) error = %v", err)
		}
		return verifyTestKey{algorithm, key, &key.PublicKey}
	case 14:
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey(P384) error = %v", err)
		}
		return verifyTestKey{algorithm, key, &key.PublicKey}
	case 15:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed25519.GenerateKey() error = %v", err)
		}
		return verifyTestKey{algorithm, priv, pub}
	}
	t.Fatalf("no test key for algorithm %d", algorithm)
	return verifyTestKey{}
}

// signForVerify signs the RRSet with the test key and fixed validity period.
func signForVerify(t *testing.T, rs *RRSet, key verifyTestKey) *RecordRRSIG {
	t.Helper()
	signerName := testDomainName(t, "example.com.")
	rrsig, err := SignRRSet(rs, key.signer, key.algorithm, 12345, signerName, testInception, testExpiration)
	if err != nil {
		t.Fatalf("SignRRSet() error = %v", err)
	}
	return rrsig
}

// notOnCurveP256 returns 64 bytes of key material for P-256 whose (x, y)
// point (1, 1) is not on the curve.
func notOnCurveP256() []byte {
	material := make([]byte, 64)
	material[31] = 1
	material[63] = 1
	return material
}

// dnskeyMaterialFromPublicKey encodes a Go public key as DNSKEY public key
// material (RFC 4034 Section 2.1 for RSA, RFC 6605 Section 4 for ECDSA,
// RFC 8080 Section 3 for Ed25519).
func dnskeyMaterialFromPublicKey(t *testing.T, pubkey crypto.PublicKey) []byte {
	t.Helper()
	switch pub := pubkey.(type) {
	case *rsa.PublicKey:
		if pub.E != 65537 {
			t.Fatalf("test RSA key has exponent %d, want 65537", pub.E)
		}
		// 指数の長さ 0 オクテットは 65537 を意味する（RFC 4034 Section 2.1）。
		return append([]byte{0}, pub.N.Bytes()...)
	case *ecdsa.PublicKey:
		size := (pub.Curve.Params().N.BitLen() + 7) / 8
		material := make([]byte, 2*size)
		pub.X.FillBytes(material[:size])
		pub.Y.FillBytes(material[size:])
		return material
	case ed25519.PublicKey:
		return append([]byte(nil), pub...)
	}
	t.Fatalf("cannot build DNSKEY material for %T", pubkey)
	return nil
}

func TestVerifyRRSetRoundTrip(t *testing.T) {
	for _, algorithm := range SupportedDNSSECAlgorithms() {
		t.Run(algorithmName(algorithm), func(t *testing.T) {
			key := newVerifyTestKey(t, algorithm)
			rs := buildVerifyTestRRSet(t)
			rrsig := signForVerify(t, &rs, key)

			// 署名検証期間内の時刻で検証できること。
			if err := VerifyRRSet(&rs, rrsig, key.pubkey, testVerifyTime); err != nil {
				t.Errorf("VerifyRRSet() error = %v, want nil", err)
			}

			// 境界（Inception と Expiration のちょうどその時刻）も有効。
			if err := VerifyRRSet(&rs, rrsig, key.pubkey, time.Unix(int64(testInception), 0)); err != nil {
				t.Errorf("VerifyRRSet() at inception time error = %v, want nil", err)
			}
			if err := VerifyRRSet(&rs, rrsig, key.pubkey, time.Unix(int64(testExpiration), 0)); err != nil {
				t.Errorf("VerifyRRSet() at expiration time error = %v, want nil", err)
			}

			// ゼロの time.Time は検証期間のチェックをスキップする。
			if err := VerifyRRSet(&rs, rrsig, key.pubkey, time.Time{}); err != nil {
				t.Errorf("VerifyRRSet() with zero time error = %v, want nil", err)
			}
		})
	}
}

// algorithmName labels the subtests with the DNSSEC algorithm number.
func algorithmName(algorithm uint8) string {
	return fmt.Sprintf("algorithm-%02d", algorithm)
}

func TestVerifyRRSetTTLAndOrderIndependent(t *testing.T) {
	key := newVerifyTestKey(t, 8)
	rs := buildVerifyTestRRSet(t)
	rrsig := signForVerify(t, &rs, key)

	// 正規形式では TTL は 0 に固定され、RDATA はソートされるため、
	// TTL が違い RDATA の順序が逆になっても検証は通る。
	other := NewRRSet(rs.Name, rs.Class, rs.Type, 7200,
		NewRecordA([4]byte{192, 0, 2, 2}),
		NewRecordA([4]byte{192, 0, 2, 1}))
	if err := VerifyRRSet(&other, rrsig, key.pubkey, testVerifyTime); err != nil {
		t.Errorf("VerifyRRSet() with different TTL and reversed RDATA order error = %v, want nil", err)
	}
}

func TestVerifyRRSetCaseInsensitive(t *testing.T) {
	key := newVerifyTestKey(t, 8)
	rs := buildVerifyTestRRSet(t)
	rrsig := signForVerify(t, &rs, key)

	// 所有者名の大文字・小文字が違っても（正規形式は同じ）検証は通る。
	mixed := NewRRSet(testDomainName(t, "WWW.Example.COM."), rs.Class, rs.Type, rs.TTL, rs.RData...)
	if err := VerifyRRSet(&mixed, rrsig, key.pubkey, testVerifyTime); err != nil {
		t.Errorf("VerifyRRSet() with mixed-case owner name error = %v, want nil", err)
	}

	// Signer's Name の大文字・小文字が違っても検証は通る。
	rrsig2 := *rrsig
	rrsig2.SignersName = testDomainName(t, "Example.COM.")
	if err := VerifyRRSet(&rs, &rrsig2, key.pubkey, testVerifyTime); err != nil {
		t.Errorf("VerifyRRSet() with mixed-case signer name error = %v, want nil", err)
	}
}

func TestVerifyRRSetRootSigner(t *testing.T) {
	// Signer's Name がルート名の場合はすべての名前をカバーする。
	key := newVerifyTestKey(t, 8)
	rs := buildVerifyTestRRSet(t)
	rrsig, err := SignRRSet(&rs, key.signer, 8, 12345, NewRootDomainName(), testInception, testExpiration)
	if err != nil {
		t.Fatalf("SignRRSet() error = %v", err)
	}
	if err := VerifyRRSet(&rs, rrsig, key.pubkey, testVerifyTime); err != nil {
		t.Errorf("VerifyRRSet() with root signer error = %v, want nil", err)
	}
}

func TestVerifyRRSetWildcardLabels(t *testing.T) {
	// RFC 4035 Section 5.3.4: 所有者名のラベル数が RRSIG の Labels フィールドより
	// 大きい場合、その RRSet と RRSIG はワイルドカード展開によって生成された。
	// 署名は展開前のワイルドカード名に対して検証されるため、展開された名前の
	// まま作られた署名では検証に失敗する。
	key := newVerifyTestKey(t, 8)
	rs := buildVerifyTestRRSet(t)
	rrsig := signForVerify(t, &rs, key)

	if err := VerifyRRSet(&rs, rrsig, key.pubkey, testVerifyTime); err != nil {
		t.Fatalf("VerifyRRSet() with Labels equal to the label count error = %v, want nil", err)
	}

	for _, labels := range []uint8{1, 2} {
		bad := *rrsig
		bad.Labels = labels
		if err := VerifyRRSet(&rs, &bad, key.pubkey, testVerifyTime); err == nil {
			t.Errorf("VerifyRRSet() with Labels = %d over a signature made for %s expected error, got nil",
				labels, rs.Name.String())
		}
	}
}

func TestSignRRSetWildcardLabels(t *testing.T) {
	// RFC 4034 Section 3.1.3: Labels フィールドはワイルドカードの左端のラベルを
	// 数えずに、ゾーン内のワイルドカード名から計算する。
	cases := []struct {
		name string
		want uint8
	}{
		{"*.example.com.", 2},
		{"*.sub.example.com.", 3},
		{"www.example.com.", 3},
		{"example.com.", 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			key := newVerifyTestKey(t, 8)
			rs := buildWildcardRRSet(t, c.name)
			rrsig := signForVerify(t, &rs, key)
			if rrsig.Labels != c.want {
				t.Errorf("SignRRSet() Labels = %d, want %d for %s", rrsig.Labels, c.want, c.name)
			}
		})
	}
}

func TestVerifyRRSetWildcard(t *testing.T) {
	// ワイルドカードの RRSet の署名検証。ゾーンにはワイルドカード名で格納され
	// 展開されないまま署名されている（RFC 4034 Section 6.2）ため、展開された
	// 名前の RRSet に対しては RRSIG の Labels フィールドから元のワイルドカード名
	// を復元して検証する（RFC 4035 Section 5.3.2）。
	key := newVerifyTestKey(t, 8)

	cases := []struct {
		desc     string
		wildcard string
		owner    string
		wantErr  bool
	}{
		// 展開された名前: *.example.com が www.example.com をカバーする。
		{"one label expansion", "*.example.com.", "www.example.com.", false},
		{"deeper expansion", "*.example.com.", "a.b.c.example.com.", false},
		// ゾーンに格納されたワイルドカード名そのものは展開せずに検証する。
		{"wildcard name unchanged", "*.example.com.", "*.example.com.", false},
		{"nested wildcard unchanged", "*.sub.example.com.", "*.sub.example.com.", false},
		// 別のワイルドカードパターンに対する署名は展開された名前を検証できない。
		{"nested wildcard covers expansion", "*.sub.example.com.", "www.sub.example.com.", false},
		{"unrelated wildcard", "*.other.example.com.", "www.example.com.", true},
		// 所有者名が Labels フィールドより少ないラベル数しかない場合は RRSIG を使えない。
		{"owner shorter than Labels", "*.example.com.", "example.com.", true},
		{"owner is the root", "*.example.com.", ".", true},
	}

	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			rs := buildWildcardRRSet(t, c.wildcard)
			rrsig := signForVerify(t, &rs, key)

			expanded := NewRRSet(testDomainName(t, c.owner), rs.Class, rs.Type, rs.TTL, rs.RData...)
			err := VerifyRRSet(&expanded, rrsig, key.pubkey, testVerifyTime)
			if c.wantErr {
				if err == nil {
					t.Errorf("VerifyRRSet(%s) expected error, got nil", c.owner)
				}
				return
			}
			if err != nil {
				t.Errorf("VerifyRRSet(%s) error = %v, want nil", c.owner, err)
			}
		})
	}

	t.Run("RDATA mismatch", func(t *testing.T) {
		// 展開された名前の RRDATA がゾーン内のワイルドカード RRSet と異なる場合。
		rs := buildWildcardRRSet(t, "*.example.com.")
		rrsig := signForVerify(t, &rs, key)
		expanded := NewRRSet(testDomainName(t, "www.example.com."), rs.Class, rs.Type, rs.TTL,
			NewRecordA([4]byte{192, 0, 2, 3}), NewRecordA([4]byte{192, 0, 2, 2}))
		if err := VerifyRRSet(&expanded, rrsig, key.pubkey, testVerifyTime); err == nil {
			t.Error("VerifyRRSet() with tampered RDATA expected error, got nil")
		}
	})

	t.Run("TTL mismatch", func(t *testing.T) {
		// 署名対象は RRSIG の Original TTL を使うため、RRSet の TTL が異なっても検証できる。
		rs := buildWildcardRRSet(t, "*.example.com.")
		rrsig := signForVerify(t, &rs, key)
		expanded := NewRRSet(testDomainName(t, "www.example.com."), rs.Class, rs.Type, 60, rs.RData...)
		if err := VerifyRRSet(&expanded, rrsig, key.pubkey, testVerifyTime); err != nil {
			t.Errorf("VerifyRRSet() with a different TTL error = %v, want nil", err)
		}
	})

	t.Run("wrong signer name", func(t *testing.T) {
		rs := buildWildcardRRSet(t, "*.example.com.")
		rrsig := signForVerify(t, &rs, key)
		bad := *rrsig
		bad.SignersName = testDomainName(t, "other.com.")
		expanded := NewRRSet(testDomainName(t, "www.example.com."), rs.Class, rs.Type, rs.TTL, rs.RData...)
		if err := VerifyRRSet(&expanded, &bad, key.pubkey, testVerifyTime); err == nil {
			t.Error("VerifyRRSet() with unrelated Signer's Name expected error, got nil")
		}
	})
}

func TestVerifyRRSetWildcardAlgorithms(t *testing.T) {
	// ワイルドカードの署名検証は全ての対応アルゴリズムで動作する。
	for _, algorithm := range SupportedDNSSECAlgorithms() {
		t.Run(fmt.Sprintf("algorithm %d", algorithm), func(t *testing.T) {
			key := newVerifyTestKey(t, algorithm)
			rs := buildWildcardRRSet(t, "*.example.com.")
			rrsig := signForVerify(t, &rs, key)
			if rrsig.Labels != 2 {
				t.Fatalf("SignRRSet() Labels = %d, want 2", rrsig.Labels)
			}
			expanded := NewRRSet(testDomainName(t, "www.example.com."), rs.Class, rs.Type, rs.TTL, rs.RData...)
			if err := VerifyRRSet(&expanded, rrsig, key.pubkey, testVerifyTime); err != nil {
				t.Errorf("VerifyRRSet() error = %v, want nil", err)
			}
		})
	}
}

func TestVerifyRRSetNoExpiration(t *testing.T) {
	// Expiration が 0 の RRSIG は期限切れにならない。
	key := newVerifyTestKey(t, 8)
	rs := buildVerifyTestRRSet(t)
	signerName := testDomainName(t, "example.com.")
	rrsig, err := SignRRSet(&rs, key.signer, 8, 12345, signerName, testInception, 0)
	if err != nil {
		t.Fatalf("SignRRSet() error = %v", err)
	}
	future := time.Unix(int64(testExpiration)+3600*24*365, 0)
	if err := VerifyRRSet(&rs, rrsig, key.pubkey, future); err != nil {
		t.Errorf("VerifyRRSet() with Expiration 0 far in the future error = %v, want nil", err)
	}
}

func TestVerifyRRSetFailures(t *testing.T) {
	key := newVerifyTestKey(t, 8)
	rs := buildVerifyTestRRSet(t)
	rrsig := signForVerify(t, &rs, key)

	t.Run("wrong key", func(t *testing.T) {
		other := newVerifyTestKey(t, 8)
		if err := VerifyRRSet(&rs, rrsig, other.pubkey, testVerifyTime); err == nil {
			t.Errorf("VerifyRRSet() with a different key expected error, got nil")
		}
	})

	t.Run("wrong key type", func(t *testing.T) {
		ec := newVerifyTestKey(t, 13)
		if err := VerifyRRSet(&rs, rrsig, ec.pubkey, testVerifyTime); err == nil {
			t.Errorf("VerifyRRSet() with an ECDSA key for an RSA RRSIG expected error, got nil")
		}
	})

	t.Run("tampered RDATA", func(t *testing.T) {
		tampered := NewRRSet(rs.Name, rs.Class, rs.Type, rs.TTL,
			NewRecordA([4]byte{192, 0, 2, 3}),
			NewRecordA([4]byte{192, 0, 2, 2}))
		if err := VerifyRRSet(&tampered, rrsig, key.pubkey, testVerifyTime); err == nil {
			t.Errorf("VerifyRRSet() with tampered RDATA expected error, got nil")
		}
	})

	t.Run("tampered signature", func(t *testing.T) {
		bad := *rrsig
		bad.Signature = append(append([]byte(nil), bad.Signature...), 0)
		if err := VerifyRRSet(&rs, &bad, key.pubkey, testVerifyTime); err == nil {
			t.Errorf("VerifyRRSet() with tampered signature expected error, got nil")
		}
	})

	t.Run("Type Covered mismatch", func(t *testing.T) {
		bad := *rrsig
		bad.TypeCovered = uint16(TYPE_NS)
		if err := VerifyRRSet(&rs, &bad, key.pubkey, testVerifyTime); err == nil {
			t.Errorf("VerifyRRSet() with wrong Type Covered expected error, got nil")
		}
	})

	t.Run("Labels too large", func(t *testing.T) {
		bad := *rrsig
		bad.Labels = uint8(labelCount(rs.Name) + 1)
		if err := VerifyRRSet(&rs, &bad, key.pubkey, testVerifyTime); err == nil {
			t.Errorf("VerifyRRSet() with Labels larger than the label count expected error, got nil")
		}
	})

	t.Run("signer does not cover owner", func(t *testing.T) {
		bad := *rrsig
		bad.SignersName = testDomainName(t, "other.com.")
		if err := VerifyRRSet(&rs, &bad, key.pubkey, testVerifyTime); err == nil {
			t.Errorf("VerifyRRSet() with unrelated Signer's Name expected error, got nil")
		}
	})

	t.Run("expired", func(t *testing.T) {
		expired := time.Unix(int64(testExpiration)+1, 0)
		if err := VerifyRRSet(&rs, rrsig, key.pubkey, expired); err == nil {
			t.Errorf("VerifyRRSet() after the expiration time expected error, got nil")
		}
	})

	t.Run("before inception", func(t *testing.T) {
		before := time.Unix(int64(testInception)-1, 0)
		if err := VerifyRRSet(&rs, rrsig, key.pubkey, before); err == nil {
			t.Errorf("VerifyRRSet() before the inception time expected error, got nil")
		}
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		bad := *rrsig
		bad.Algorithm = 99
		if err := VerifyRRSet(&rs, &bad, key.pubkey, testVerifyTime); err == nil {
			t.Errorf("VerifyRRSet() with unsupported algorithm expected error, got nil")
		}
	})

	t.Run("nil RRSet", func(t *testing.T) {
		if err := VerifyRRSet(nil, rrsig, key.pubkey, testVerifyTime); err == nil {
			t.Errorf("VerifyRRSet(nil) expected error, got nil")
		}
	})

	t.Run("nil RRSIG", func(t *testing.T) {
		if err := VerifyRRSet(&rs, nil, key.pubkey, testVerifyTime); err == nil {
			t.Errorf("VerifyRRSet(nil RRSIG) expected error, got nil")
		}
	})

	t.Run("nil public key", func(t *testing.T) {
		if err := VerifyRRSet(&rs, rrsig, nil, testVerifyTime); err == nil {
			t.Errorf("VerifyRRSet(nil public key) expected error, got nil")
		}
	})
}

func TestNewDNSSECPublicKey(t *testing.T) {
	// DNSKEY の公開鍵材料から復元した公開鍵で検証できること。
	for _, algorithm := range []uint8{8, 13, 14, 15} {
		key := newVerifyTestKey(t, algorithm)
		material := dnskeyMaterialFromPublicKey(t, key.pubkey)
		pubkey, err := NewDNSSECPublicKey(algorithm, material)
		if err != nil {
			t.Fatalf("algorithm %d: NewDNSSECPublicKey() error = %v", algorithm, err)
		}
		rs := buildVerifyTestRRSet(t)
		rrsig := signForVerify(t, &rs, key)
		if err := VerifyRRSet(&rs, rrsig, pubkey, testVerifyTime); err != nil {
			t.Errorf("algorithm %d: VerifyRRSet() with key from NewDNSSECPublicKey() error = %v, want nil", algorithm, err)
		}
	}

	t.Run("RSA one-octet exponent length", func(t *testing.T) {
		// 長さ 1 の指数（指数 3）+ 法。
		modulus := []byte{0x8d, 0x33, 0xa1, 0x77}
		pubkey, err := NewDNSSECPublicKey(8, append([]byte{1, 3}, modulus...))
		if err != nil {
			t.Fatalf("NewDNSSECPublicKey() error = %v", err)
		}
		rsaPub, ok := pubkey.(*rsa.PublicKey)
		if !ok {
			t.Fatalf("NewDNSSECPublicKey() returned %T, want *rsa.PublicKey", pubkey)
		}
		if rsaPub.E != 3 {
			t.Errorf("rsa.PublicKey.E = %d, want 3", rsaPub.E)
		}
	})

	t.Run("RSA three-octet exponent length", func(t *testing.T) {
		// 長さ 3 の指数（指数 65537）+ 法。
		modulus := []byte{0x8d, 0x33, 0xa1, 0x77}
		pubkey, err := NewDNSSECPublicKey(8, append([]byte{3, 0x01, 0x00, 0x01}, modulus...))
		if err != nil {
			t.Fatalf("NewDNSSECPublicKey() error = %v", err)
		}
		rsaPub, ok := pubkey.(*rsa.PublicKey)
		if !ok {
			t.Fatalf("NewDNSSECPublicKey() returned %T, want *rsa.PublicKey", pubkey)
		}
		if rsaPub.E != 65537 {
			t.Errorf("rsa.PublicKey.E = %d, want 65537", rsaPub.E)
		}
	})

	t.Run("errors", func(t *testing.T) {
		cases := []struct {
			name      string
			algorithm uint8
			material  []byte
		}{
			{"empty RSA key", 8, nil},
			{"invalid RSA exponent length", 8, []byte{2, 3, 1, 1}},
			{"truncated RSA exponent", 8, []byte{1}},
			{"missing RSA modulus", 8, []byte{0}},
			{"RSA exponent too small", 8, []byte{1, 1, 0xAA}},
			{"ECDSA P256 wrong length", 13, make([]byte, 64)},
			{"ECDSA P384 wrong length", 14, make([]byte, 64)},
			{"ECDSA point not on curve", 13, notOnCurveP256()},
			{"Ed25519 wrong length", 15, make([]byte, 31)},
			{"unsupported algorithm", 99, make([]byte, 32)},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				if _, err := NewDNSSECPublicKey(c.algorithm, c.material); err == nil {
					t.Errorf("NewDNSSECPublicKey() expected error, got nil")
				}
			})
		}
	})
}

func TestVerifyRRSetWithDNSKEY(t *testing.T) {
	for _, algorithm := range []uint8{8, 13, 15} {
		key := newVerifyTestKey(t, algorithm)
		rs := buildVerifyTestRRSet(t)
		rrsig := signForVerify(t, &rs, key)

		dnskey := NewRecordDNSKEY(256, 3, algorithm, dnskeyMaterialFromPublicKey(t, key.pubkey))
		if err := VerifyRRSetWithDNSKEY(&rs, rrsig, &dnskey, testVerifyTime); err != nil {
			t.Errorf("algorithm %d: VerifyRRSetWithDNSKEY() error = %v, want nil", algorithm, err)
		}

		// DNSKEY のアルゴリズムが RRSIG と違う場合はエラー。
		wrong := NewRecordDNSKEY(256, 3, 10, dnskey.PublicKey)
		if err := VerifyRRSetWithDNSKEY(&rs, rrsig, &wrong, testVerifyTime); err == nil {
			t.Errorf("algorithm %d: VerifyRRSetWithDNSKEY() with mismatched algorithm expected error, got nil", algorithm)
		}
	}

	t.Run("nil DNSKEY", func(t *testing.T) {
		key := newVerifyTestKey(t, 8)
		rs := buildVerifyTestRRSet(t)
		rrsig := signForVerify(t, &rs, key)
		if err := VerifyRRSetWithDNSKEY(&rs, rrsig, nil, testVerifyTime); err == nil {
			t.Errorf("VerifyRRSetWithDNSKEY(nil) expected error, got nil")
		}
	})
}
