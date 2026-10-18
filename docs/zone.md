# Zone（DNS ゾーン）と RRSet の管理

Zone は DNS ゾーンを表す型です。オリジン（ゾーンのルートドメイン名）、デフォルト TTL、およびゾーン内の RRSet の集合を持ちます。DNSSEC の署名対象となる RRSet をまとめて管理するために使用します。

## Zone 構造体

| フィールド | 型 | 内容 |
|----------|----|------|
| `Origin` | `DomainName` | ゾーンのオリジン（ルートドメイン名） |
| `DefaultTTL` | `uint32` | ゾーン内のレコードに適用されるデフォルト TTL（秒） |
| `RRsets` | `[]RRSet` | ゾーンに含まれる RRSet のリスト |

## 主要な API

| API | 説明 |
|-----|------|
| `NewZone(origin DomainName, defaultTTL uint32) Zone` | 新しい Zone を構築 |
| `(*Zone).AddRRSet(rs RRSet)` | RRSet をゾーンに追加 |
| `(*Zone).FindRRSet(name DomainName, typ ResourceType) (RRSet, bool)` | 指定したオーナー名とタイプの RRSet を検索 |
| `(*Zone).RemoveRRSet(name DomainName, typ ResourceType)` | 指定したオーナー名とタイプの RRSet をすべて削除 |
| `(*Zone).Len() int` | 含まれる RRSet の数 |
| `(*Zone).Equal(rhs Zone) bool` | 二つの Zone が等しいか比較 |
| `(*Zone).String() string` | ゾーンファイル風の人間が読める形式で返す |
| `(*Zone).CanonicalWireFormat() []byte` | ゾーン全体の正規ワイヤフォーマットを返す |
| `(*Zone).AppendCanonicalWireFormat(w *WireFormat) uint32` | 正規ワイヤフォーマットを追記 |

### ResourceRecordsToZone（ヘルパー）

```go
func ResourceRecordsToZone(origin DomainName, defaultTTL uint32, records []ResourceRecord) Zone
```

`[]ResourceRecord` のリストから Zone を構築します。同じ (Name, Class, Type) のレコードは同じ RRSet にグループ化され、各 RRSet の TTL は `defaultTTL` で上書きされます。

## 正規ワイヤフォーマット

`CanonicalWireFormat` は各 RRSet を RFC 4034 Section 6.2 に従って正規化し、RRSet 自体をオーナー名とタイプの順でソートして出力します。オーナー名の順序は RFC 4034 Section 6.1 の canonical DNS name order（右端のラベルから比較する順序）で、`DomainName.CompareCanonicalOrder()` がその順序を実装しています。ラベル数が少ない名前ほど先になるため、ゾーンの Origin が常に最初の RRSet になります。これはゾーン転送（AXFR）の形式に準拠しています。

各 RRSet 内では、TTL は 0 に固定され、RDATA は canonical order でソートされます（`RRSet.CanonicalWireFormat()` を参照）。

## 使用例

### 1) Zone を構築して RRSet を追加する

```go
package main

import (
	"fmt"
	"log"

	"github.com/sischkg/dnsmsg"
)

func main() {
	origin, err := dnsmsg.NewDomainNameFromString("example.com.")
	if err != nil {
		log.Fatal(err)
	}

	// ゾーンを構築（デフォルト TTL 3600 秒）
	z := dnsmsg.NewZone(origin, 3600)

	// www.example.com. の A レコード 2 件
	www, _ := dnsmsg.NewDomainNameFromString("www.example.com.")
	wwwRS := dnsmsg.NewRRSet(
		www,
		dnsmsg.CLASS_IN,
		dnsmsg.TYPE_A,
		3600,
		dnsmsg.NewRecordA([4]byte{192, 0, 2, 1}),
		dnsmsg.NewRecordA([4]byte{192, 0, 2, 2}),
	)
	z.AddRRSet(wwwRS)

	// example.com. の NS レコード
	ns, _ := dnsmsg.NewDomainNameFromString("ns.example.com.")
	originRS := dnsmsg.NewRRSet(
		origin,
		dnsmsg.CLASS_IN,
		dnsmsg.TYPE_NS,
		86400,
		dnsmsg.NewRecordNS(ns),
	)
	z.AddRRSet(originRS)

	fmt.Println(z.String())
	// 出力例:
	// $ORIGIN example.com.
	// $TTL 3600
	// www.example.com. IN A 3600 192.0.2.1
	// www.example.com. IN A 3600 192.0.2.2
	// example.com. IN NS 86400 ns.example.com.
}
```

### 2) ResourceRecord のリストから Zone を構築する

```go
records := []dnsmsg.ResourceRecord{
    {Name: www, Class: dnsmsg.CLASS_IN, Type: dnsmsg.TYPE_A, TTL: 3600, RData: a1},
    {Name: origin, Class: dnsmsg.CLASS_IN, Type: dnsmsg.TYPE_NS, TTL: 86400, RData: nsRR},
    {Name: www, Class: dnsmsg.CLASS_IN, Type: dnsmsg.TYPE_A, TTL: 7200, RData: a2}, // 同じ (www, IN, A) は同じ RRSet にグループ化
}

z := dnsmsg.ResourceRecordsToZone(origin, 300, records)
// www の A レコードは 2 件同じ RRSet にグループ化され、TTL は 300 で上書きされる
```

### 3) RRSet を検索・削除する

```go
// 検索
rs, ok := z.FindRRSet(www, dnsmsg.TYPE_A)
if ok {
    fmt.Printf("found %d records\n", rs.Len())
}

// 削除
z.RemoveRRSet(www, dnsmsg.TYPE_A)
```

### 4) 正規ワイヤフォーマットを取得して DNSSEC 署名に渡す

```go
wire := z.CanonicalWireFormat()

// 各 RRSet に対して SignRRSet で署名
// rrsig, err := dnsmsg.SignRRSet(&rs, signer, 8, keyTag, signerName, inception, expiration)
```

## ゾーンの NSEC 署名（Zone.Sign）

`Zone.Sign()` はゾーン内の各 RRSet に RRSIG を生成し、各オーナー名に NSEC レコードとその RRSIG を生成して、すべての署名レコードを `[]ResourceRecord` で返します（RFC 4034）。

### Zone.Sign のシグネチャ

```go
func (z Zone) Sign(signer crypto.Signer, algorithm uint8, keyTag uint16, signerName DomainName, inception, expiration uint32) ([]ResourceRecord, error)
```

| 引数 | 型 | 内容 |
|------|----|------|
| `signer` | `crypto.Signer` | 秘密鍵（*rsa.PrivateKey や *ecdsa.PrivateKey など） |
| `algorithm` | `uint8` | DNSSEC アルゴリズム番号（`SupportedDNSSECAlgorithms()` 参照） |
| `keyTag` | `uint16` | 署名鍵の DNSKEY キータグ |
| `signerName` | `DomainName` | 署名鍵のオーナー名（DNSKEY レコードのオーナー） |
| `inception` | `uint32` | 署名開始時刻（Unix秒、0なら現在時刻） |
| `expiration` | `uint32` | 署名有効期限（Unix秒、0なら無期限） |

### 戻り値

`[]ResourceRecord` には以下が含まれる：

1. 各 RRSet に対する RRSIG レコード（Type, Name, TTL は元の RRSet を継承）
2. 各オーナー名に対する NSEC レコード（TTL はゾーンの DefaultTTL）
3. 各 NSEC レコードに対する RRSIG レコード

NSEC レコードの Next Domain Name は、canonical DNS name order（RFC 4034 Section 6.1）での次のオーナー名を指し、最後のオーナー名の場合はゾーンの Origin に戻る（ゾーンの輪郭を閉じる）。Origin はラベル数が最も少ない名前として canonical 順の先頭になるため、Origin の NSEC はゾーン内の最初のオーナー名を指し、ゾーン内で最後のオーナー名となる NSEC が Origin に戻る (RFC 4034 Section 4.1.1)。

### 使用例

```go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"

	"github.com/sischkg/dnsmsg"
)

func main() {
	origin, _ := dnsmsg.NewDomainNameFromString("example.com.")

	// ゾーンを構築
	z := dnsmsg.NewZone(origin, 3600)

	www, _ := dnsmsg.NewDomainNameFromString("www.example.com.")
	z.AddRRSet(dnsmsg.NewRRSet(
		www, dnsmsg.CLASS_IN, dnsmsg.TYPE_A, 3600,
		dnsmsg.NewRecordA([4]byte{192, 0, 2, 1}),
	))

	ns, _ := dnsmsg.NewDomainNameFromString("ns.example.com.")
	z.AddRRSet(dnsmsg.NewRRSet(
		origin, dnsmsg.CLASS_IN, dnsmsg.TYPE_NS, 86400,
		dnsmsg.NewRecordNS(ns),
	))

	// 秘密鍵で署名（実際は dnssec-keygen の .private ファイルから読み込む）
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	signerName, _ := dnsmsg.NewDomainNameFromString("example.com.")

	signedRecords, err := z.Sign(
		privateKey,        // crypto.Signer
		8,                 // RSASHA256
		12345,             // キータグ
		signerName,        // 署名鍵のオーナー名
		1700000000,        // inception
		1800000000,        // expiration
	)
	if err != nil {
		log.Fatal(err)
	}

	for _, rr := range signedRecords {
		fmt.Println(rr) // RRSIG / NSEC / NSEC の RRSIG が出力される
	}
}
```

### エラーハンドリング

| ケース | エラー |
|------|--------|
| `signer` が nil | `signer is nil` |
| 非対応アルゴリズム | `unsupported DNSSEC algorithm N for zone signing` |
| 署名失敗 | `cannot sign RRSet ...: <原因>` または `cannot sign NSEC for ...: <原因>` |

## ゾーンの NSEC3 署名（Zone.SignNSEC3）

`Zone.SignNSEC3()` はゾーンを NSEC3 (RFC 5155) で署名する。各 RRSet に RRSIG を生成し、各オーナー名（ハッシュ済み）に NSEC3 レコードとその RRSIG を生成し、さらに NSEC3PARAM レコードとその RRSIG を生成して、すべての署名レコードを `[]ResourceRecord` で返す。

### Zone.SignNSEC3 のシグネチャ

```go
func (z Zone) SignNSEC3(signer crypto.Signer, algorithm uint8, keyTag uint16, signerName DomainName,
    inception, expiration uint32, hashAlgorithm uint8, flags uint8, iterations uint16, salt []byte) ([]ResourceRecord, error)
```

| 引数 | 型 | 内容 |
|------|----|------|
| `signer` | `crypto.Signer` | 秘密鍵（*rsa.PrivateKey や *ecdsa.PrivateKey など） |
| `algorithm` | `uint8` | DNSSEC アルゴリズム番号（`SupportedDNSSECAlgorithms()` 参照） |
| `keyTag` | `uint16` | 署名鍵の DNSKEY キータグ |
| `signerName` | `DomainName` | 署名鍵のオーナー名（DNSKEY レコードのオーナー） |
| `inception` | `uint32` | 署名開始時刻（Unix秒、0なら現在時刻） |
| `expiration` | `uint32` | 署名有効期限（Unix秒、0なら無期限） |
| `hashAlgorithm` | `uint8` | NSEC3 ハッシュアルゴリズム（`HashAlgorithmSHA1` = 1） |
| `flags` | `uint8` | NSEC3 フラグ（`FlagOptOut` = 0x01、オプトアウト） |
| `iterations` | `uint16` | ハッシュ反復回数（0不可） |
| `salt` | `[]byte` | ソルト値（空スライス可） |

### 戻り値

`[]ResourceRecord` には以下が含まれる：

1. 各 RRSet に対する RRSIG レコード（Type, Name, TTL は元の RRSet を継承）
2. 各オーナー名に対する NSEC3 レコード（TTL はゾーンの DefaultTTL）
3. 各 NSEC3 レコードに対する RRSIG レコード
4. ゾーンアペックスに対する NSEC3PARAM レコード（TTL はゾーンの DefaultTTL）
5. NSEC3PARAM レコードに対する RRSIG レコード

NSEC3 レコードの Next Hashed Owner Name は、SHA-1 ハッシュ後の値を canonical 順でソートした際の次のオーナー名を指し、最後のオーナー名の場合は最初のオーナー名に戻る（輪郭を閉じる）。

### 使用例

```go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"

	"github.com/sischkg/dnsmsg"
)

func main() {
	origin, _ := dnsmsg.NewDomainNameFromString("example.com.")

	// ゾーンを構築
	z := dnsmsg.NewZone(origin, 3600)

	www, _ := dnsmsg.NewDomainNameFromString("www.example.com.")
	z.AddRRSet(dnsmsg.NewRRSet(
		www, dnsmsg.CLASS_IN, dnsmsg.TYPE_A, 3600,
		dnsmsg.NewRecordA([4]byte{192, 0, 2, 1}),
	))

	ns, _ := dnsmsg.NewDomainNameFromString("ns.example.com.")
	z.AddRRSet(dnsmsg.NewRRSet(
		origin, dnsmsg.CLASS_IN, dnsmsg.TYPE_NS, 86400,
		dnsmsg.NewRecordNS(ns),
	))

	// 秘密鍵で NSEC3 署名
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	signerName, _ := dnsmsg.NewDomainNameFromString("example.com.")
	salt := []byte{0x01, 0x02}

	signedRecords, err := z.SignNSEC3(
		privateKey,        // crypto.Signer
		8,                 // RSASHA256
		12345,             // キータグ
		signerName,        // 署名鍵のオーナー名
		1700000000,        // inception
		1800000000,        // expiration
		1,                 // SHA-1
		0,                 // フラグ（オプトアウトなし）
		1,                 // 反復回数
		salt,              // ソルト
	)
	if err != nil {
		log.Fatal(err)
	}

	for _, rr := range signedRecords {
		fmt.Println(rr) // RRSIG / NSEC3 / NSEC3 の RRSIG / NSEC3PARAM / NSEC3PARAM の RRSIG
	}
}
```

### エラーハンドリング

| ケース | エラー |
|------|--------|
| `signer` が nil | `signer is nil` |
| 非対応 DNSSEC アルゴリズム | `unsupported DNSSEC algorithm N for NSEC3 zone signing` |
| 非対応 NSEC3 ハッシュアルゴリズム | `unsupported NSEC3 hash algorithm N` |
| iterations が 0 | `NSEC3 iterations must be non-zero` |
| 署名失敗 | `cannot sign RRSet ...: <原因>` または `cannot sign NSEC3 for ...: <原因>` または `cannot sign NSEC3PARAM: <原因>` |

### NSEC3 ハッシュ

NSEC3 ハッシュは RFC 5155 Section 5 に従い、SHA-1 を使用して計算される：

```
H(0) = SHA-1(canonical_name || salt)
H(i) = SHA-1(H(i-1) || salt) for i = 1 to iterations-1
```

`canonical_name` は小文字・圧縮なしのワイヤフォーマット（`DomainName.CanonicalWireFormat()`）を使用する。

## エラーハンドリング（Zone 全般）

- `FindRRSet` は見つからない場合は `false` を返す（エラーではない）
- `ResourceRecordsToZone` は不正なドメイン名を持つレコードはスキップする
- `RemoveRRSet` は存在しない (Name, Type) の組み合わせを指定してもエラーにならない（べき等）

## 関連リンク

- [index.md](index.md) — パッケージ概要
- [rrset.md](rrset.md) — RRSet と DNSSEC 署名（正規ワイヤフォーマット、SignRRSet、SupportedDNSSECAlgorithms）
- [dnssec.md](dnssec.md) — DNSSEC 鍵ファイル（BIND dnssec-keygen 生成）の読み込み
- [RFC 4034](https://datatracker.ietf.org/doc/html/rfc4034) — DNS Security (DNSSEC) Resource Records
- [RFC 4034 Section 5.2](https://datatracker.ietf.org/doc/html/rfc4034#section-5.2) — NSEC Record
- [RFC 4034 Section 6.2](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2) — Canonical RR Set Form
- [RFC 5155](https://datatracker.ietf.org/doc/html/rfc5155) — DNS Security (DNSSEC) Hashed Authenticated Denial of Existence (NSEC3)
- [RFC 5155 Section 5](https://datatracker.ietf.org/doc/html/rfc5155#section-5) — NSEC3 Hash Algorithm

