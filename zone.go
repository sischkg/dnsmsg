package dnsmsg

import (
	"bytes"
	"crypto"
	"crypto/sha1"
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
// オーナー名の順序は RFC 4034 Section 6.1 の canonical DNS name order
// （右端のラベルから比較する順序）である。NSEC チェーンはこの順序で
// 作られる (RFC 4034 Section 3.1.2)。
func (z Zone) sortedRRsets() []RRSet {
	ordered := append([]RRSet(nil), z.RRsets...)
	sort.SliceStable(ordered, func(i, j int) bool {
		cmp := ordered[i].Name.CompareCanonicalOrder(ordered[j].Name)
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

// ownerNamesWithTypes はゾーン内の各ユニークなオーナー名と、その名前に
// 存在する RR タイプの集合を返す。結果はオーナー名の canonical DNS name
// order (RFC 4034 Section 6.1) 順でソートされる。
func (z Zone) ownerNamesWithTypes() ([]DomainName, map[string][]ResourceType) {
	nameSet := make(map[string]struct{})
	typesMap := make(map[string][]ResourceType)

	for _, rs := range z.RRsets {
		nameKey := rs.Name.String()
		if _, ok := nameSet[nameKey]; !ok {
			nameSet[nameKey] = struct{}{}
		}
		typesMap[nameKey] = append(typesMap[nameKey], rs.Type)
	}

	names := make([]DomainName, 0, len(nameSet))
	for nameKey := range nameSet {
		name, err := NewDomainNameFromString(nameKey)
		if err != nil {
			continue
		}
		names = append(names, name)
	}

	// canonical DNS name order (RFC 4034 Section 6.1) でソート
	sort.SliceStable(names, func(i, j int) bool {
		return names[i].CompareCanonicalOrder(names[j]) < 0
	})

	// 重複タイプを排除してソート済みにする
	for nameKey, types := range typesMap {
		seen := make(map[ResourceType]struct{})
		unique := make([]ResourceType, 0, len(types))
		for _, typ := range types {
			if _, ok := seen[typ]; !ok {
				seen[typ] = struct{}{}
				unique = append(unique, typ)
			}
		}
		sort.Slice(unique, func(i, j int) bool { return unique[i] < unique[j] })
		typesMap[nameKey] = unique
	}

	return names, typesMap
}

// nextOwnerName はソート済みのオーナー名リストにおいて、name の次に
// 来るオーナー名を返す。最後の要素の場合は orig を返す（ゾーンの
// 終端はオリジンに戻る）。
func (z Zone) nextOwnerName(names []DomainName, name DomainName, orig DomainName) DomainName {
	for i, n := range names {
		if n.Equal(name) {
			if i+1 < len(names) {
				return names[i+1]
			}
			return orig
		}
	}
	return orig
}

// Sign はゾーン内の各 RRSet に RRSIG を生成し、各オーナー名に NSEC
// レコードとその RRSIG を生成して、すべての署名レコードを返す
// (RFC 4034)。戻り値の []ResourceRecord には以下が含まれる：
//
//   - 各 RRSet に対する RRSIG レコード
//   - 各オーナー名に対する NSEC レコード
//   - 各 NSEC レコードに対する RRSIG レコード
//
// signer は crypto.Signer を実装する秘密鍵（*rsa.PrivateKey や
// *ecdsa.PrivateKey など）。algorithm は DNSSEC アルゴリズム番号、
// keyTag は署名鍵の DNSKEY キータグ、signerName は署名鍵のオーナー名、
// inception / expiration は署名の有効期間。
//
// ゾーンに RRSet が含まれていない場合は空のスライスを返す。
func (z Zone) Sign(signer crypto.Signer, algorithm uint8, keyTag uint16, signerName DomainName, inception, expiration uint32) ([]ResourceRecord, error) {
	if signer == nil {
		return nil, fmt.Errorf("signer is nil")
	}

	_, ok := dnssecAlgorithmHash(algorithm)
	if !ok {
		return nil, fmt.Errorf("unsupported DNSSEC algorithm %d for zone signing", algorithm)
	}

	var records []ResourceRecord

	// 1) 各 RRSet に対して RRSIG を生成
	for _, rs := range z.RRsets {
		rrsig, err := SignRRSet(&rs, signer, algorithm, keyTag, signerName, inception, expiration)
		if err != nil {
			return nil, fmt.Errorf("cannot sign RRSet %s %s: %w", rs.Name, rs.Type, err)
		}

		rrsigRR := ResourceRecord{
			Name:  rs.Name,
			Class: rs.Class,
			Type:  TYPE_RRSIG,
			TTL:   rs.TTL,
			RData: *rrsig,
		}
		records = append(records, rrsigRR)
	}

	// 2) 各オーナー名に対して NSEC レコードを生成
	names, typesMap := z.ownerNamesWithTypes()
	if len(names) == 0 {
		return records, nil
	}

	for _, name := range names {
		nameKey := name.String()
		types := typesMap[nameKey]
		nextName := z.nextOwnerName(names, name, z.Origin)

		nsec := NewRecordNSEC(nextName, types)

		nsecRR := ResourceRecord{
			Name:  name,
			Class: z.DefaultTTLClass(),
			Type:  TYPE_NSEC,
			TTL:   z.DefaultTTL,
			RData: nsec,
		}
		records = append(records, nsecRR)

		// 3) NSEC レコードに対する RRSIG を生成
		nsecRS := NewRRSet(name, z.DefaultTTLClass(), TYPE_NSEC, z.DefaultTTL, nsec)
		nsecRRSIG, err := SignRRSet(&nsecRS, signer, algorithm, keyTag, signerName, inception, expiration)
		if err != nil {
			return nil, fmt.Errorf("cannot sign NSEC for %s: %w", name, err)
		}

		nsecRRSIGRR := ResourceRecord{
			Name:  name,
			Class: z.DefaultTTLClass(),
			Type:  TYPE_RRSIG,
			TTL:   z.DefaultTTL,
			RData: *nsecRRSIG,
		}
		records = append(records, nsecRRSIGRR)
	}

	return records, nil
}

// DefaultTTLClass はゾーンのデフォルトクラスを返す。現在のところ
// 常に CLASS_IN を返す。
func (z Zone) DefaultTTLClass() ResourceClass {
	return CLASS_IN
}

// nsec3Hash は RFC 5155 Section 5 に従ってドメイン名の NSEC3 ハッシュを
// 計算する。
//
//   H(0) = SHA-1(canonical_name || salt)
//   H(i) = SHA-1(H(i-1) || salt) for i = 1 to iterations-1
//
// canonical_name は小文字・圧縮なしのワイヤフォーマット（DomainName.
// CanonicalWireFormat）を使用する。
func nsec3Hash(name DomainName, salt []byte, iterations uint16) []byte {
	nameWire := name.CanonicalWireFormat()

	// H(0) = SHA-1(name || salt)
	h := sha1.New()
	h.Write(nameWire)
	h.Write(salt)
	digest := h.Sum(nil)

	// H(i) = SHA-1(H(i-1) || salt) for remaining iterations
	for i := uint16(1); i < iterations; i++ {
		h = sha1.New()
		h.Write(digest)
		h.Write(salt)
		digest = h.Sum(nil)
	}

	return digest
}

// nsec3HashToLabel は NSEC3 ハッシュ値を長さプレフィックス付きラベル
// のワイヤフォーマットに変換する（先頭にハッシュ長の1オクテットを付ける）。
func nsec3HashToLabel(hash []byte) []byte {
	label := make([]byte, 0, 1+len(hash))
	label = append(label, uint8(len(hash)))
	label = append(label, hash...)
	return label
}

// SignNSEC3 はゾーンを NSEC3 (RFC 5155) で署名する。
// 各 RRSet に RRSIG を生成し、各オーナー名に NSEC3 レコードとその RRSIG を
// 生成し、さらに NSEC3PARAM レコードとその RRSIG を生成して、
// すべての署名レコードを返す。
//
// 戻り値の []ResourceRecord には以下が含まれる：
//
//   - 各 RRSet に対する RRSIG レコード
//   - 各オーナー名（ハッシュ済み）に対する NSEC3 レコード
//   - 各 NSEC3 レコードに対する RRSIG レコード
//   - ゾーンアペックスに対する NSEC3PARAM レコード
//   - NSEC3PARAM レコードに対する RRSIG レコード
//
// signer は crypto.Signer を実装する秘密鍵。algorithm は DNSSEC アルゴリズム
// 番号。keyTag は署名鍵の DNSKEY キータグ。signerName は署名鍵のオーナー名。
// inception / expiration は署名の有効期間。hashAlgorithm は NSEC3 ハッシュ
// アルゴリズム（1 = SHA-1）。flags は NSEC3 フラグ（0x01 = opt-out）。iterations
// はハッシュ反復回数。salt はソルト値。
//
// ゾーンに RRSet が含まれていない場合は空のスライスを返す。
func (z Zone) SignNSEC3(signer crypto.Signer, algorithm uint8, keyTag uint16, signerName DomainName,
	inception, expiration uint32, hashAlgorithm uint8, flags uint8, iterations uint16, salt []byte) ([]ResourceRecord, error) {

	if signer == nil {
		return nil, fmt.Errorf("signer is nil")
	}

	_, ok := dnssecAlgorithmHash(algorithm)
	if !ok {
		return nil, fmt.Errorf("unsupported DNSSEC algorithm %d for NSEC3 zone signing", algorithm)
	}

	if hashAlgorithm != HashAlgorithmSHA1 {
		return nil, fmt.Errorf("unsupported NSEC3 hash algorithm %d", hashAlgorithm)
	}

	if iterations == 0 {
		return nil, fmt.Errorf("NSEC3 iterations must be non-zero")
	}

	var records []ResourceRecord

	// 1) 各 RRSet に対して RRSIG を生成
	for _, rs := range z.RRsets {
		rrsig, err := SignRRSet(&rs, signer, algorithm, keyTag, signerName, inception, expiration)
		if err != nil {
			return nil, fmt.Errorf("cannot sign RRSet %s %s: %w", rs.Name, rs.Type, err)
		}

		rrsigRR := ResourceRecord{
			Name:  rs.Name,
			Class: rs.Class,
			Type:  TYPE_RRSIG,
			TTL:   rs.TTL,
			RData: *rrsig,
		}
		records = append(records, rrsigRR)
	}

	// 2) オーナー名とタイプを収集し、NSEC3 ハッシュでソート
	names, typesMap := z.ownerNamesWithTypes()
	if len(names) == 0 {
		return records, nil
	}

	// 各オーナー名を NSEC3 ハッシュし、ハッシュ値でソート
	type hashedEntry struct {
		name     DomainName
		nameKey  string
		hash     []byte
		types    []ResourceType
	}
	hashed := make([]hashedEntry, 0, len(names))
	for _, name := range names {
		nameKey := name.String()
		hash := nsec3Hash(name, salt, iterations)
		hashed = append(hashed, hashedEntry{
			name:    name,
			nameKey: nameKey,
			hash:    hash,
			types:   typesMap[nameKey],
		})
	}

	sort.SliceStable(hashed, func(i, j int) bool {
		return bytes.Compare(hashed[i].hash, hashed[j].hash) < 0
	})

	// 3) 各オーナー名に対して NSEC3 レコードを生成
	for i, entry := range hashed {
		// 次のハッシュ済みオーナー名（最後は最初のものに戻る）
		var nextHash []byte
		if i+1 < len(hashed) {
			nextHash = hashed[i+1].hash
		} else {
			nextHash = hashed[0].hash
		}

		nsec3 := NewRecordNSEC3(
			hashAlgorithm,
			flags,
			iterations,
			salt,
			nsec3HashToLabel(nextHash),
			entry.types,
		)

		nsec3RR := ResourceRecord{
			Name:  entry.name,
			Class: z.DefaultTTLClass(),
			Type:  TYPE_NSEC3,
			TTL:   z.DefaultTTL,
			RData: nsec3,
		}
		records = append(records, nsec3RR)

		// NSEC3 レコードに対する RRSIG を生成
		nsec3RS := NewRRSet(entry.name, z.DefaultTTLClass(), TYPE_NSEC3, z.DefaultTTL, nsec3)
		nsec3RRSIG, err := SignRRSet(&nsec3RS, signer, algorithm, keyTag, signerName, inception, expiration)
		if err != nil {
			return nil, fmt.Errorf("cannot sign NSEC3 for %s: %w", entry.name, err)
		}

		nsec3RRSIGRR := ResourceRecord{
			Name:  entry.name,
			Class: z.DefaultTTLClass(),
			Type:  TYPE_RRSIG,
			TTL:   z.DefaultTTL,
			RData: *nsec3RRSIG,
		}
		records = append(records, nsec3RRSIGRR)
	}

	// 4) ゾーンアペックスに対する NSEC3PARAM レコードを生成
	apexTypes, ok := typesMap[z.Origin.String()]
	if !ok {
		// アペックスにレコードがなくても NSEC3PARAM は生成する（空のタイプリスト）
		apexTypes = nil
	}
	nsec3param := NewRecordNSEC3PARAM(hashAlgorithm, flags, iterations, salt, apexTypes)

	nsec3paramRR := ResourceRecord{
		Name:  z.Origin,
		Class: z.DefaultTTLClass(),
		Type:  TYPE_NSEC3PARAM,
		TTL:   z.DefaultTTL,
		RData: nsec3param,
	}
	records = append(records, nsec3paramRR)

	// NSEC3PARAM レコードに対する RRSIG を生成
	nsec3paramRS := NewRRSet(z.Origin, z.DefaultTTLClass(), TYPE_NSEC3PARAM, z.DefaultTTL, nsec3param)
	nsec3paramRRSIG, err := SignRRSet(&nsec3paramRS, signer, algorithm, keyTag, signerName, inception, expiration)
	if err != nil {
		return nil, fmt.Errorf("cannot sign NSEC3PARAM: %w", err)
	}

	nsec3paramRRSIGRR := ResourceRecord{
		Name:  z.Origin,
		Class: z.DefaultTTLClass(),
		Type:  TYPE_RRSIG,
		TTL:   z.DefaultTTL,
		RData: *nsec3paramRRSIG,
	}
	records = append(records, nsec3paramRRSIGRR)

	return records, nil
}
