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

`CanonicalWireFormat` は各 RRSet を RFC 4034 Section 6.2 に従って正規化し、RRSet 自体をオーナー名とタイプの順（バイト列辞書順）でソートして出力します。これはゾーン転送（AXFR）の形式に準拠しています。

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

## エラーハンドリング

- `FindRRSet` は見つからない場合は `false` を返す（エラーではない）
- `ResourceRecordsToZone` は不正なドメイン名を持つレコードはスキップする
- `RemoveRRSet` は存在しない (Name, Type) の組み合わせを指定してもエラーにならない（べき等）

## 関連リンク

- [index.md](index.md) — パッケージ概要
- [rrset.md](rrset.md) — RRSet と DNSSEC 署名（正規ワイヤフォーマット、SignRRSet、SupportedDNSSECAlgorithms）
- [dnssec.md](dnssec.md) — DNSSEC 鍵ファイル（BIND dnssec-keygen 生成）の読み込み
- [RFC 4034 Section 6.2](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2) — Canonical RR Set Form
