# DNSSEC の鍵ファイル・署名鍵・キータグ（dnssec-keygen 鍵ファイル対応）

`dnsmsg` パッケージでは、BIND に付属する `dnssec-keygen` で生成した DNSSEC 鍵ファイル（`.key` / `.private`）を読み込み、`DNSSECKey` 構造体として取得できます。読み込んだ鍵は `RecordDNSKEY` に変換してゾーンファイルに公開でき、`NewDNSSECSigner` で `crypto.Signer` に変換して `SignRRSet` の署名鍵にできます。`KeyTag` 系の API は RFC 4034 Appendix B の DNSKEY キータグを計算します。鍵の内容をファイルそのものではなくバイト列や `io.Reader` として受け取っている場合は、`ParseDNSSECKey` / `ReadDNSSECKey` 系の API で同じパース規則をファイルに触れずに適用できます。ファイルを開かずに鍵ファイルの**名前**（`K<name>+<alg>+<tag>`）だけから所属ドメイン名・アルゴリズム・キータグを取り出すのは `NewDNSSECKeyFileNameFromString` の仕事です。`ReadPrivateKeyFile` が空で返す `DNSSECKey.Name` を同じファイル名から補うのは `InferDNSSECKeyNameFromFileName` の仕事です。

## `DNSSECKey` 構造体

| フィールド | 型 | 内容 |
|----------|----|------|
| `Name` | `DomainName` | 鍵の所属ドメイン名（DNSKEY レコードのオーナー名） |
| `Flags` | `uint16` | DNSKEY フラグ（256 = ゾーンキー ZSK、257 = セキュアエントリポイント KSK） |
| `Protocol` | `uint8` | セキュリティプロトコル（DNSSEC では常に 3） |
| `Algorithm` | `uint8` | DNSSEC アルゴリズム番号（RFC 4034 Section 5.1.1） |
| `PublicKey` | `[]byte` | 公開鍵データ（`.key` ファイル読み込み時に設定。`.private` では nil） |
| `PrivateKey` | `[]byte` | 主要な秘密鍵データ（`.private` ファイル読み込み時に設定。アルゴリズム依存） |
| `PrivateParams` | `map[string][]byte` | 名前付き秘密パラメータ（Modulus, PrivateExponent, PrivateKey 等。`.private` のみ） |

## 主要な API

| API | 説明 |
|-----|------|
| `ReadKeyFile(filename string) (*DNSSECKey, error)` | `.key` ファイルを読み込み、最初の DNSKEY レコード行をパースして `DNSSECKey` を返す |
| `ReadPrivateKeyFile(filename string) (*DNSSECKey, error)` | `.private` ファイル（Private-key-format v1.3）を読み込み、アルゴリズム番号と秘密パラメータを抽出する |
| `ParseDNSSECKey(data []byte) (*DNSSECKey, error)` | `.key` ファイルの内容そのものをバイト列からパースする（ファイルは読まない。`ReadKeyFile` からファイル読み込みを除いたもの） |
| `ParseDNSSECKeyWithSource(data []byte, source string) (*DNSSECKey, error)` | 同じパースを行い、エラーメッセージでの入力の呼び名に `source` を使う |
| `ParseDNSSECPrivateKey(data []byte) (*DNSSECKey, error)` | `.private` ファイルの内容そのものをバイト列からパースする（ファイルは読まない） |
| `ParseDNSSECPrivateKeyWithSource(data []byte, source string) (*DNSSECKey, error)` | 同じパースを行い、エラーメッセージでの入力の呼び名に `source` を使う |
| `ParseDNSSECKeyLine(line string) (*DNSSECKey, error)` | DNSKEY レコード 1 行（`.key` の DNSKEY 行の書式）をパースする |
| `ReadDNSSECKey(r io.Reader) (*DNSSECKey, error)` | `r` を最後まで読んで `.key` 内容としてパースする（ファイルは読まない） |
| `ReadDNSSECPrivateKey(r io.Reader) (*DNSSECKey, error)` | `r` を最後まで読んで `.private` 内容としてパースする（ファイルは読まない） |
| `ReadDNSSECKeyPair(baseName string) (*DNSSECKey, error)` | 同一の接頭辞を持つ `.key` と `.private` を読み、1 つの `DNSSECKey` に統合する |
| `ReadDNSSECKeyFiles(keyFile, privateFile string) (*DNSSECKey, error)` | 2 つのファイル名を直接指定して同じ統合を行う |
| `MergeDNSSECKey(public, private *DNSSECKey) (*DNSSECKey, error)` | 公開鍵の半分と秘密鍵の半分を 1 つの `DNSSECKey` に統合する（ファイルは読まない。`ReadDNSSECKeyFiles` はこの統合の上にファイル名の情報を載せたもの） |
| `(*DNSSECKey).ToDNSKEY() RecordDNSKEY` | 鍵を `RecordDNSKEY` に変換（公開鍵のみ。秘密鍵は DNSKEY レコードに含まれない） |
| `NewDNSSECPublicKey(algorithm uint8, material []byte) (crypto.PublicKey, error)` | DNSKEY の公開鍵マテリアルから `crypto.PublicKey` を構築（`VerifyRRSet` の `pubkey` に渡せます） |
| `NewDNSSECSigner(key *DNSSECKey) (crypto.Signer, error)` | 鍵ファイルから復元した秘密鍵を `crypto.Signer` に変換（`SignRRSet` の署名鍵として使えます） |
| `DNSSECKeyTag(rdata []byte) uint16` | DNSKEY RDATA（wire フォーマット）から RFC 4034 Appendix B のキータグを計算 |
| `(r RecordDNSKEY).KeyTag() uint16` | `RecordDNSKEY` のキータグ（`CanonicalWireFormat()` に対して `DNSSECKeyTag` を適用） |
| `(*DNSSECKey).KeyTag() (uint16, error)` | 鍵の公開鍵材料からキータグを計算。公開鍵がない場合はエラー |
| `NewDNSSECKeyFileNameFromString(path string) (DNSSECKeyFileName, error)` | `dnssec-keygen` の鍵**ファイル名**から所属ドメイン名・アルゴリズム・キータグを解析する（ファイルは開かない） |
| `NewDNSSECKeyBaseName(name DomainName, algorithm uint8, keyTag uint16) string` | 3 つの値から `dnssec-keygen` が鍵ファイルに付ける基底名 `K<name>+<alg>+<tag>` を生成する |
| `InferDNSSECKeyNameFromFileName(path string) (DomainName, error)` | `dnssec-keygen` の鍵ファイル名から所属ドメイン名だけを取り出す（ファイルは開かない。`.private` 単体の鍵の `Name` を補う）。名前を受け付ける規則は `NewDNSSECKeyFileNameFromString` と同じ |

## キーファイル形式

### `.key` ファイル（公開鍵）

`dnssec-keygen` が生成する `.key` ファイルは、ゾーンファイル形式の DNSKEY レコードを含みます。

```
example.com. IN DNSKEY 256 3 5 AQO=
```

書式：`<name> IN DNSKEY <flags> <protocol> <algorithm> <base64-public-key>`

- `name` — 鍵の所属ドメイン名（末尾に `.` を付けた完全修飾ドメイン名）
- `flags` — 256（ZSK）または 257（KSK）
- `protocol` — 3
- `algorithm` — DNSSEC アルゴリズム番号（5 = RSASHA1、8 = RSASHA256、13 = ECDSAP256SHA256 等）
- `base64-public-key` — 公開鍵を base64（パディングなし、RFC 4634）でエンコードした文字列

コメント行（`;` または `#` で始まる行）と空行、および `$ORIGIN` / `$TTL` などのディレクティブ行はスキップされます。ファイル内の最初の DNSKEY レコード行が返されます。

### `.private` ファイル（秘密鍵）

`dnssec-keygen` が生成する `.private` ファイルは、Private-key-format v1.3 形式です。

```
Private-key-format: v1.3
Algorithm: 5 (RSASHA1)
Modulus: AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8
PublicExponent: AQAB
PrivateExponent: q83v
Prime1: AAAA
Prime2: BBBB
Exponent1: CCCC
Exponent2: DDDD
Coefficient: EEEE
Created: 20230101000000
Publish: 20230101000000
Activate: 20230101000000
```

- `Algorithm: <n> (<name>)` — アルゴリズム番号（必須。これが読み込まれます）
- その他の行（`Modulus`, `PrivateExponent` 等）は base64 でエンコードされたパラメータとして `PrivateParams` マップに格納されます
- `PrivateExponent`（または `PrivateKey`）は `PrivateKey` フィールドにもコピーされます
- `Created` / `Publish` / `Activate` などの時刻行は情報目的のみで無視されます
- 所有者名はこの形式にはありません。`.private` だけを読む `ReadPrivateKeyFile` /
  `ParseDNSSECPrivateKey` 系は `DNSSECKey.Name` を空（ラベル 0 個）で返します。これは仕様で、
  ルートゾーン名（`.`、1 ラベル）と区別するためにあえて空のままにしています。`dnssec-keygen` は
  鍵の所有者名をファイル名に書くので、ファイルから読んだ鍵にそれを設定するのは
  `InferDNSSECKeyNameFromFileName` の仕事です（「鍵ファイル名の解析」参照）。1 組まとめて読む
  `ReadDNSSECKeyPair` は `.key` の所有者名を使うので、そこでは不要です

## 鍵ペアの読み込み（`ReadDNSSECKeyPair` / `ReadDNSSECKeyFiles`）

署名には `.private` の秘密鍵マテリアルと `.key` の公開鍵マテリアルの両方が必要です。
`ReadDNSSECKeyPair` は `dnssec-keygen` が 1 組の鍵に対して生成する 2 つのファイルを読み、
それらを 1 つの `*DNSSECKey` に統合します。

```go
// どの表記でも同じ 1 組を指定する
key, err := dnsmsg.ReadDNSSECKeyPair("Kexample.com.+013+39506")
key, err := dnsmsg.ReadDNSSECKeyPair("Kexample.com.+013+39506.key")
key, err := dnsmsg.ReadDNSSECKeyPair("Kexample.com.+013+39506.private")

// ファイル名を直接指定することもできる
key, err := dnsmsg.ReadDNSSECKeyFiles(
	"/etc/bind/Kexample.com.+013+39506.key",
	"/etc/bind/Kexample.com.+013+39506.private",
)
```

2 つのファイルはどちらも欠けていればエラーになります。どちらか一方だけを読む既存の
`ReadKeyFile` / `ReadPrivateKeyFile` はそのまま使えます。

### 統合されるフィールド

| 供給するファイル | `DNSSECKey` のフィールド |
|------------------|---------------------------|
| `.key` | `Name`（所有者名）、`Flags`、`Protocol`、`Algorithm`、`PublicKey` |
| `.private` | `Algorithm`、`PrivateKey`、`PrivateParams` |

ファイルが 1 組の鍵から来ていれば両方の `Algorithm` は同じ値です。一致しない場合は
エラーになり、どちらのファイルがどちらのアルゴリズムを主張しているかが報告されます
（「エラーハンドリング」を参照）。

統合された鍵はこのまま使えます。

- `key.ToDNSKEY()` は `.key` の DNSKEY レコードと同じ RDATA を返す
- `key.KeyTag()` は公開鍵マテリアルがあるためエラーにならない
- `NewDNSSECSigner(key)` は秘密鍵マテリアルから `crypto.Signer` を組み、導出した公開鍵を
  `.key` の公開鍵マテリアルと照合する
- したがって `SignRRSet` に渡す `keyTag` は `key.ToDNSKEY().KeyTag()` と一致する

### `baseName` の解決

`baseName` は 2 つのファイルが共有する接頭辞です。

- 拡張子が無い場合はそのまま 2 つのファイル名を組み立てます
  （`Kexample.com.+008+12345` → `Kexample.com.+008+12345.key` と
  `Kexample.com.+008+12345.private`）
- `.key` または `.private` で終わる場合は、その拡張子を取り除いてから組み立てます
  （`.private` を渡した場合も同じ 1 組が読めます）
- 取り除かれるのは完全に小文字で書かれた `.key` と `.private` だけです。`.KEY` のように
  大文字を交えた拡張子はエラーになります
- 空の文字列、および `.key` だけ・`.private` だけのような空の基底名はエラーになります

ファイルは `ReadKeyFile` / `ReadPrivateKeyFile` と同じくローカルファイルシステムから
読みます（作業ディレクトリからの相対パスまたは絶対パス）。

### 読み込み時の検証

統合した鍵は `NewDNSSECSigner` に渡せる状態かを確認します。ただし検証するのは
`.private` が秘密鍵マテリアルを持ち、かつアルゴリズムが `SupportedDNSSECAlgorithms()`
に含まれる場合だけです。

- `.private` が `Algorithm` 行しか持たないなど、秘密鍵マテリアルが無い 1 組は検証できる
  ものが無いのでそのまま返す（`ToDNSKEY()` と `KeyTag()` はそのまま使えるが、
  `NewDNSSECSigner` は従来どおり `has no private key material` でエラーになる）
- `NewDNSSECSigner` が扱わないアルゴリズム（1、2、3、6、12、16 など）の鍵もそのまま読める
  （`ToDNSKEY()` と `KeyTag()` を使う目的に署名の失敗を混ぜないため）
- 検証は署名を作りません。秘密鍵マテリアルから導出した公開鍵が `.key` の公開鍵と
  一致するかを見るだけで、乱数は使いません

### `.private` の `Name:` 行

`Private-key-format` の名前空間に所有者名を載せる標準の行はありませんが、`.private` に
`Name:` 行を書く書式もあります。鍵ペアを読む経路ではその行を、値に関係なくすべて
除去し、`.key` の所有者名を正として使います。

これは鍵ペアを読む経路だけの扱いで、`ReadPrivateKeyFile` は単独では従来どおり
`cannot decode private key parameter "Name" in <path>` でエラーになります。
所有者名と秘密鍵マテリアルの両方が必要なら、その 1 組を `ReadKeyFile` と
`ReadPrivateKeyFile` で別々に読むのではなく `ReadDNSSECKeyPair` で読んでください。
`.key` を持たない `.private` について、`ReadPrivateKeyFile` はそのままで `Name` を空に返し、
所属ドメイン名は `InferDNSSECKeyNameFromFileName`（「鍵ファイル名の解析」参照）が鍵ファイル名から
補完します。

上記の「読み込み時の検証」で説明している秘密鍵と公開鍵の照合は、
`MergeDNSSECKey` が行うものと同じです。ただし `MergeDNSSECKey` は秘密鍵マテリアルを
要求するので、秘密鍵マテリアルが無い 1 組を受け取るのは鍵ペアを読む経路だけです。

## 公開鍵と秘密鍵の統合（`MergeDNSSECKey`）

```go
func MergeDNSSECKey(public, private *DNSSECKey) (*DNSSECKey, error)
```

`ReadKeyFile` が返す鍵（公開鍵の半分）と `ReadPrivateKeyFile` が返す鍵（秘密鍵の半分）を、
両方を持つ 1 つの鍵に統合します。統合した鍵はそのまま次の呼び出しに使えます。

- `key.ToDNSKEY()` は `public` の DNSKEY レコードと同じ RDATA を返す
- `key.KeyTag()` は公開鍵マテリアルがあるためエラーにならない
- `NewDNSSECSigner(key)` は秘密鍵マテリアルから `crypto.Signer` を組み、導出した公開鍵を
  `public` の公開鍵マテリアルと照合する
- したがって `SignRRSet` の `keyTag` 引数には `key.KeyTag()` の値を渡せばよく、それは
  `key.ToDNSKEY().KeyTag()` と一致する

この関数はファイルを読みません。すでに 2 つの半分を持っている場合に使ってください。

- `ReadKeyFile` と `ReadPrivateKeyFile` を別々に呼んだ（拡張子の解決や `.private` の
  `Name:` 行の扱いを自分で決めたい場合を含む）
- 鍵をメモリ内で組み立てた（テストの鍵、他の場所から復元した鍵）
- 1 組の鍵を自分が生成した

`ReadDNSSECKeyFiles` はこの統合と `Algorithm` の照合をそのまま行ったうえで、返すエラーに
2 つのファイル名を添える関数です。ファイルを読むところから一括して行いたい場合は
`ReadDNSSECKeyFiles` を使ってください。同じ 1 組に対して両者が返す鍵は同じです。

### 統合が要求する 2 つの半分

2 つの半分が 1 つの鍵を説明していることが条件です。

| 条件 | 満たさない意味 |
|------|----------------|
| どちらの引数も `nil` でない | 半分そのものが無い |
| `public` が公開鍵マテリアル（`PublicKey`）を持つ | `.private` だけ読んだ鍵はそれを持たない。統合後の鍵は説明すべき DNSKEY を持てない |
| `private` が秘密鍵マテリアル（`PrivateKey` または `PrivateParams`）を持つ | `.key` だけ読んだ鍵はそれを持たない。統合後の鍵は署名できなくなる |
| 両方の `Algorithm` が 0 ではなく、同じ値である | 0 はアルゴリズムをどこからも読んでいないことを意味し、値が違うなら 2 つの半分は 1 つの鍵を説明していない |

`Algorithm` が 0 の `DNSSECKey` はアルゴリズムをどこからも読んでいない鍵です。0 は 2 つの値が
食い違った結果ではなく欠落なので、不一致ではなく欠落として報告します。

### どちらの半分がどのフィールドを出す

| 供給する半分 | `DNSSECKey` のフィールド |
|--------------|---------------------------|
| `public` | `Name`（所有者名）、`Flags`、`Protocol`、`Algorithm`、`PublicKey` |
| `private` | `PrivateKey`、`PrivateParams` |

`Algorithm` は 2 つの半分が共通して持つ情報なので、照合したうえで `public` の値を使います。
それ以外のフィールドはどちらか一方の半分だけが供給します。引数が持っていたそれ以外の情報は
統合後の鍵には入りません。

- `private` が持つ `Name`、`Flags`、`Protocol`、`PublicKey` は使わない
- `public` が持つ秘密鍵マテリアルは使わない（秘密鍵は `private` 側から来る）

### 統合は引数を変更しない

返す鍵は `Name` のラベル、`PublicKey`、`PrivateKey`、`PrivateParams` の各値を複製して持ちます。

- 引数は変更されない
- 統合後の鍵を変更しても引数は変わらない
- 同じ 1 組から 2 回統合した場合、返る 2 つの鍵は状態を共有しない

`PublicKey`、`PrivateKey`、`PrivateParams` の各値が `nil` の場合は `nil` のまま引き継ぎます。
`nil` は「その種類のマテリアルが無い」という `DNSSECKey` の表し方なので、空のスライスに
置き換えません。`nil` ではないが長さ 0 のスライスは長さ 0 のまま複製します。
`PrivateParams` が空（`nil` または要素数 0）の場合はマップ自体を作りません。

### 統合時に行う検証

統合した鍵のアルゴリズムが `SupportedDNSSECAlgorithms()` に含まれる場合は、統合のときに
`NewDNSSECSigner` に渡せるかを確認します。秘密鍵マテリアルから導出した公開鍵が `public` の
公開鍵マテリアルと一致しない 1 組は、ここで報告されます（署名の時点まで引っ張りません）。

- アルゴリズムが `SupportedDNSSECAlgorithms()` に含まれない（1、2、3、6、12、16 など）場合は、
  検証のために作るべき署名鍵が存在しないので、そのまま統合して返します。`KeyTag()` と
  `ToDNSKEY()` はそのまま正しく使え、`NewDNSSECSigner` は署名しようとしたときに従来どおりの
  エラーを報告します
- 検証は署名を作りません。乱数は使いません
- 秘密鍵マテリアルの要求が条件にあるため、ここで検証が飛ばされることはありません（鍵ペアを
  読む経路にある「秘密鍵マテリアルが無ければ検証もしない」分岐は、この経路にはありません）

### 2 つのファイルを別々に読んで統合する

```go
base := "Kexample.com.+013+39506"

public, err := dnsmsg.ReadKeyFile(base + ".key")
if err != nil {
	log.Fatal(err)
}
private, err := dnsmsg.ReadPrivateKeyFile(base + ".private")
if err != nil {
	log.Fatal(err)
}

key, err := dnsmsg.MergeDNSSECKey(public, private)
if err != nil {
	log.Fatal(err)
}

signer, err := dnsmsg.NewDNSSECSigner(key)
if err != nil {
	log.Fatal(err)
}

tag, err := key.KeyTag()
if err != nil {
	log.Fatal(err)
}
```

`ReadDNSSECKeyPair` はこれと同じことに、2 つのファイル名の解決と `.private` の `Name:` 行の
除去を足した関数です。

## 鍵の内容を直接パースする（`ParseDNSSECKey` / `ReadDNSSECKey`）

```go
func ParseDNSSECKey(data []byte) (*DNSSECKey, error)
func ParseDNSSECKeyWithSource(data []byte, source string) (*DNSSECKey, error)
func ParseDNSSECPrivateKey(data []byte) (*DNSSECKey, error)
func ParseDNSSECPrivateKeyWithSource(data []byte, source string) (*DNSSECKey, error)
func ParseDNSSECKeyLine(line string) (*DNSSECKey, error)
func ReadDNSSECKey(r io.Reader) (*DNSSECKey, error)
func ReadDNSSECPrivateKey(r io.Reader) (*DNSSECKey, error)
```

`ReadKeyFile` と `ReadPrivateKeyFile` は「ファイルを読む」と「内容を読む」の 2 つの手順の
組み合わせです。この節の API はそのうち読む手順だけで、ファイルに触れずに
`ReadKeyFile` / `ReadPrivateKeyFile` と同じ書式規則・同じフィールド設定・同じエラー判定を
適用します。鍵の内容をすでに別の方法で得ている呼び出し側は、ファイルを経由せずに
こちらを呼べます。

- プログラムに埋め込んだ鍵（`go:embed` した `.key` / `.private` 相当の内容）
- 設定ストア、データベース、API などから取り出した鍵の内容
- テストのためにメモリ内で組み立てた鍵の内容

これらの関数はファイルを開きません。ファイルそのものからの読み込みは
従来どおり `ReadKeyFile` / `ReadPrivateKeyFile` の仕事です。

| 関数 | 受け取るもの |
|------|-------------|
| `ParseDNSSECKey` / `ParseDNSSECKeyWithSource` | `.key` ファイルの内容そのもの（DNSKEY レコード行を含むバイト列） |
| `ParseDNSSECPrivateKey` / `ParseDNSSECPrivateKeyWithSource` | `.private` ファイルの内容そのもの（Private-key-format v1.3） |
| `ParseDNSSECKeyLine` | DNSKEY レコード 1 行（`.key` の DNSKEY 行と同じ書式） |
| `ReadDNSSECKey` / `ReadDNSSECPrivateKey` | `io.Reader`。最後まで 1 回読んでから、その内容を `.key` / `.private` 内容としてパースします |

同じ内容からは、ファイルを読む API と同じ `DNSSECKey` が返ります。

### パース規則はファイル読み込みと同じ

- 空行・`;` や `#` のコメント行・`$ORIGIN` などのゾーンファイルディレクティブを無視し、
  内容の中の**最初の DNSKEY レコード**だけを使う、公開鍵の base64 が空白で複数の
  チャンクに分かれていれば連結して復号する、といった扱いは「キーファイル形式」に
  書いたとおりで、ファイルを読む API とすべて同一です。
- 空の内容、DNSKEY レコードを含まない内容、`Algorithm` 行のない `.private` 内容も
  エラーです。エラーなしに `nil` の鍵が返ることはありません。
- `.key` 相当の内容は `Name`・`Flags`・`Protocol`・`Algorithm`・`PublicKey` に、
  `.private` 相当の内容は `PrivateKey`・`PrivateParams` に、ファイルを読む API と
  同じフィールド設定で入ります。
- `.private` の `Name:` 行はこの経路では拒否されます（「`.private` の `Name:` 行」参照）。
  1 組の鍵として読む場合は `ReadDNSSECKeyPair` / `ReadDNSSECKeyFiles` を使ってください。
- `ParseDNSSECKeyLine` は渡された 1 行だけをパースします。前後の空白は無視されますが、
  複数行の内容やコメントの扱いはありません。複数の DNSKEY レコードを含む内容を
  扱う場合は、行に分割して `ParseDNSSECKeyLine` を行ごとに使ってください。

### エラーメッセージでの入力の呼び名

ファイルを読む API のエラーは、入力をファイル名で指します
（`no DNSKEY record found in <filename>` など）。この API はファイル名を受け取らないため、
入力を既定の呼び名で指します。

| API | エラーでの入力の呼び名 |
|-----|----------------------|
| `ParseDNSSECKey` / `ReadDNSSECKey` | `DNSSEC key data` |
| `ParseDNSSECPrivateKey` / `ReadDNSSECPrivateKey` | `DNSSEC private key data` |
| `ParseDNSSECKeyWithSource` / `ParseDNSSECPrivateKeyWithSource` | 呼び出し側が渡した `source`（空文字列なら上の既定名） |

`source` はそのデータがどこから来たかを説明する任意の文章です
（`Kexample.com.+008+26415 embedded in config` など）。データが元あった場所の名前を
そのまま渡せば、エラーはファイルを読む API と同じ場所を同じ理由で指します
（文言の違いは「エラーハンドリング」に書きました）。

### Reader から読む

`ReadDNSSECKey` と `ReadDNSSECPrivateKey` は `r` を最後まで 1 回読んでから、その内容を
上記と同じパースにかけます。読み取りそのものが失敗したときは
`cannot read DNSSEC key data: <読み取りのエラー>`、
`cannot read DNSSEC private key data: <読み取りのエラー>` として返ります。
これらもファイルを開きません。

### バイト列から読んで統合する

2 組の内容がファイルではなく文字列として手元にある場合の流れです。

```go
publicData := []byte(`example.com. IN DNSKEY 257 3 8 <base64-public-key>`)
privateData := []byte(`Private-key-format: v1.3
Algorithm: 8 (RSA)
Modulus: <base64>
PrivateExponent: <base64>`)

public, err := dnsmsg.ParseDNSSECKeyWithSource(publicData, "embedded Kexample.com.+008+26415")
if err != nil {
	log.Fatal(err)
}
private, err := dnsmsg.ParseDNSSECPrivateKeyWithSource(privateData, "embedded Kexample.com.+008+26415 private")
if err != nil {
	log.Fatal(err)
}

key, err := dnsmsg.MergeDNSSECKey(public, private)
if err != nil {
	log.Fatal(err)
}

signer, err := dnsmsg.NewDNSSECSigner(key)
if err != nil {
	log.Fatal(err)
}
```

`MergeDNSSECKey` は 2 つの半分がどこから来たかを問いません。この組み方で得った鍵も、
ファイルから読んだ鍵と同じ使えます（「公開鍵と秘密鍵の統合（`MergeDNSSECKey`）」の
「使用例」と同じ続き方です）。

`ReadKeyFile` と `ReadPrivateKeyFile` は、このパースにファイル読み込みを足した関数です。
パース規則と返る鍵は同一で、エラーの違いは入力の呼び名だけです。

## 公開鍵の構築（`NewDNSSECPublicKey`）

```go
func NewDNSSECPublicKey(algorithm uint8, material []byte) (crypto.PublicKey, error)
```

DNSKEY レコードの公開鍵マテリアル（`PublicKey` フィールド、すなわち DNSKEY RDATA の末尾）から
`crypto.PublicKey` を構築します。`VerifyRRSet` の `pubkey` 引数に渡せます。

| アルゴリズム | 返される型 | 公開鍵マテリアルの形式 |
|--------------|-----------|----------------------|
| 5・7・8・10 | `*rsa.PublicKey` | 公開指数の長さ（1 オクテット。0 は指数 65537 を意味する）→ 指数 → 法（すべて big-endian、RFC 4034 Section 2.1） |
| 13・14 | `*ecdsa.PublicKey` | X 座標 → Y 座標（各 32 または 48 オクテット、0 の詰めなし。RFC 6605 Section 4） |
| 15 | `ed25519.PublicKey` | 32 オクテット（RFC 8080 Section 6） |

`RecordDNSKEY` をもっている場合は `VerifyRRSetWithDNSKEY` が内部でこの変換を行うため、
明示的に呼び出す必要はありません。`.private` ファイルだけでは公開鍵マテリアルを持たないため、
`.key` ファイルも読んでください（[rrset.md](rrset.md) の使用例 4）。

## 署名鍵の構築（`NewDNSSECSigner`）

`SignRRSet` は `crypto.Signer` を受け取ります。`NewDNSSECSigner` は `.private` ファイルから読み込んだ `DNSSECKey` の秘密パラメータから `crypto.Signer` を組み立てるので、鍵ファイルから直接署名鍵を作れます。

```go
key, err := dnsmsg.ReadPrivateKeyFile("Kexample.com.+013+39506.private")
if err != nil {
	log.Fatal(err)
}

signer, err := dnsmsg.NewDNSSECSigner(key)
if err != nil {
	log.Fatal(err)
}
// signer は crypto.Signer。SignRRSet にそのまま渡せる。
```

1 組の鍵をまとめて読む場合は `ReadDNSSECKeyPair` が `.private` と `.key` を統合した
`*DNSSECKey` を返すので、その鍵から `crypto.Signer` を組みます。

```go
key, err := dnsmsg.ReadDNSSECKeyPair("Kexample.com.+013+39506")
if err != nil {
	log.Fatal(err)
}

signer, err := dnsmsg.NewDNSSECSigner(key)
if err != nil {
	log.Fatal(err)
}
```

受け付けるアルゴリズムと、それぞれの秘密鍵に必要なパラメータ（RFC 4034 Appendix D、RFC 6605、RFC 8080）:

| アルゴリズム | 必要な秘密パラメータ | 返される型 |
|-------------|--------------------|-----------|
| 5, 7, 8, 10 (RSA) | `Modulus` / `PublicExponent` / `PrivateExponent`（`Prime1` と `Prime2` は任意） | `*rsa.PrivateKey` |
| 13, 14 (ECDSA P-256 / P-384) | `PrivateKey`（秘密スカラー。32 / 48 オクテット） | `*ecdsa.PrivateKey` |
| 15 (Ed25519) | `PrivateKey`（32 オクテットの seed） | `ed25519.PrivateKey` |

- 受け付けるアルゴリズムは `SupportedDNSSECAlgorithms()`（`5, 7, 8, 10, 13, 14, 15`）と同じです。それ以外は `unsupported DNSSEC algorithm N for signing` を返します。
- 秘密パラメータは `ReadPrivateKeyFile` が base64 からデコード済みのオクテット列として `PrivateParams` に入れています。`NewDNSSECSigner` は再度のデコード（16 進数や base64 の再解釈）を行いません。
- パラメータ名は大文字・小文字を区別しません（`Privatekey` のような綴りも受け付けます）。名前で見つからない場合は `DNSSECKey.PrivateKey`（`ReadPrivateKeyFile` が秘密指数・秘密スカラーを写すフィールド）が使われます。RSA の素数 2 つは 1 つのオクテット列にまとめられないため、名前付きパラメータからのみ読まれます。
- 秘密スカラーと seed の長さは固定です（ECDSA は曲線の位数のオクテット数、Ed25519 は 32 オクテット）。長さが違う鍵は、鍵を組み立てる前に検出されます（`ed25519.NewKeyFromSeed` は短い入力で panic するため、先に検査します）。
- `DNSKEY` の公開鍵（`PublicKey`）が設定されている場合は、秘密鍵から導出した公開鍵と比較し、一致しなければエラーにします。`.private` ファイル単体で読んだ鍵は公開鍵を持たないため、この比較は行われません。`ReadDNSSECKeyPair` で読んだ鍵ペアでは両方のマテリアルが揃うため、この比較が必ず行われます。
- RSA の `Prime1` / `Prime2` は任意です。両方揃っている場合は `Validate` と `Precompute`（CRT 値の事前計算。多くの RRSet に署名する場合に速くなります）を通します。両方ない場合は `Modulus` / `PublicExponent` / `PrivateExponent` だけを検査し、`rsa.PrivateKey` は一般経路で署名します。`Exponent1` / `Exponent2` / `Coefficient` は読みません。これらの値は素数と秘密指数から導出できるので、ファイルに書かれていても署名には使いません。
- 乱数は使いません。同じ秘密パラメータからは常に同じ鍵が得られます。

## DNSKEY のキータグ（`KeyTag`）

DNSKEY のキータグ（RFC 4034 Appendix B）は、その DNSKEY レコードの **RDATA だけ**（flags / protocol / algorithm / public key。名前・クラス・タイプ・TTL は含まない）をオクテット列として受け取り、16 ビット big-endian の語として足し合わせた下 16 ビットです。末尾で 1 オクテット余る場合は、そのオクテットを最後の語の上位バイトとして扱います。最終的なあふれ（キャリー）はもう一度加算します。

```go
key, err := dnsmsg.ReadKeyFile("Kexample.com.+013+39506.key")
if err != nil {
	log.Fatal(err)
}

dnskey := key.ToDNSKEY()
fmt.Println(dnskey.KeyTag())        // DNSKEY レコード自身のキータグ
fmt.Println(key.KeyTag())           // 同じ値（.key を読んだ鍵なので公開鍵がある）
fmt.Println(dnsmsg.DNSSECKeyTag(dnskey.CanonicalWireFormat())) // 生の RDATA から計算
```

| API | 説明 |
|-----|------|
| `DNSSECKeyTag(rdata []byte) uint16` | DNSKEY RDATA のオクテット列から計算。RDATA ではないオクテット（名前や TTL）を渡さないでください |
| `(r RecordDNSKEY).KeyTag() uint16` | `CanonicalWireFormat()` の RDATA に対して計算するため、常にそのレコードの正しいキータグを返します |
| `(*DNSSECKey).KeyTag() (uint16, error)` | `ToDNSKEY()` 経由で計算。公開鍵材料を持たない `.private` 単体の鍵はエラー |

- `SignRRSet` は `keyTag` を引数として受け取るため、値は呼び出し側が決めます。`(*DNSSECKey).KeyTag()` で計算した値をそのまま渡せば、生成される RRSIG の `KeyTag` フィールドが署名鍵の実際のキータグと一致します。
- 検証側が使う `VerifyRRSetWithDNSKEY` は渡された `RecordDNSKEY` をそのまま使い、アルゴリズムが RRSIG と違う場合だけエラーにします（`DNSKEY algorithm N does not match RRSIG algorithm M`）。複数の DNSKEY があるゾーンでどの鍵で検証するかを選ぶのは呼び出し側の仕事です。その判断には `RecordDNSKEY.KeyTag()` と `RecordRRSIG.KeyTag` を比較するのが定石です（RFC 4034 Section 3.1.1）。
- `(*DNSSECKey).KeyTag()` が公開鍵のない鍵でエラーにするのは、flags・protocol・algorithm の 4 オクテットだけの合計は見た目はキータグですが実際のキータグではないためです。`.private` 単体の鍵でキータグが必要な場合は、同じ名前の `.key` ファイルの公開鍵を `PublicKey` に設定してから計算してください。その 1 組をまとめて読むには `ReadDNSSECKeyPair` を使います。公開鍵がなくて問題になるのはキータグだけです。`.private` 単体の鍵に所属ドメイン名だけを設定するのは `InferDNSSECKeyNameFromFileName` の仕事で、その場合に `KeyTag()` は引き続きエラーになります（「鍵ファイル名の解析」参照）。

## 鍵ファイル名の解析（`NewDNSSECKeyFileNameFromString` / `NewDNSSECKeyBaseName`）

`dnssec-keygen` の鍵**ファイル名** `K<所有者名>+<アルゴリズム>+<キータグ>[.key|.private]` は、その鍵を識別する 3 つの値そのものに書き込まれています。`NewDNSSECKeyFileNameFromString` はファイルを開かずに名前だけを解析し、その 3 つの値を取り出します。ファイルの**内容**を読む `ReadKeyFile` / `ReadDNSSECKeyPair` とは別の仕事で、どのファイルを読むか・どの鍵かに対応するかを判断するのに使えます。

```go
func NewDNSSECKeyFileNameFromString(path string) (DNSSECKeyFileName, error)
func NewDNSSECKeyBaseName(name DomainName, algorithm uint8, keyTag uint16) string
```

### `DNSSECKeyFileName` 構造体

| フィールド | 型 | 内容 |
|-----------|----|------|
| `BaseName` | `string` | `.key` / `.private` 拡張子を除いた基底名。解析した名前のつづりのままです。`.key` または `.private` を足すとその鍵の 2 つのファイル名になり、`ReadDNSSECKeyPair` にそのまま渡せます |
| `Name` | `DomainName` | 鍵の所有者名（ファイル名の 1 番目のフィールド）。ゾーン鍵のゾーン名です |
| `Algorithm` | `uint8` | 鍵の DNSSEC アルゴリズム番号（2 番目のフィールド）。`DNSSECAlgorithm*` 定数と比較してください |
| `KeyTag` | `uint16` | 鍵のキータグ（3 番目のフィールド）。`RecordDNSKEY.KeyTag()` の計算結果や `RecordRRSIG.KeyTag` と比較できます |

### 受け付ける名前

- フルパスでもファイル名だけでもかまいません（ディレクトリ部分は除かれます）
- `.key` / `.private` 拡張子はあってもなくてもかまいません（除いたものが `BaseName` になります）
- `K` の直後が「所有者名（プレゼンテーション形式）`+` アルゴリズム（10 進数）`+` キータグ（10 進数）」のちょうど 3 フィールド
- 所有者名は `NewDomainNameFromString` と同じプレゼンテーション形式です。ルートゾーン用に生成された名前（`K.+013+43580`）も解析できます
- アルゴリズムは 255 以下、キータグは 65535 以下。先頭の 0 ありはあってもなくてもかまいません（`Kexample.com.+8+1` も valid）
- 拡張子は `.key` / `.private` が小文字でつづられている場合だけ除かれます。`.Key` のようなつづりはエラーです。どちらでもない拡張子（`.tar.gz` など）は除かれず、その中身がキータグ フィールドの解析時にエラーとして報告されます

### 基底名の生成（`NewDNSSECKeyBaseName`）

`NewDNSSECKeyBaseName` は 3 つの値から `dnssec-keygen` が鍵ファイルに付ける基底名を生成します。アルゴリズムを 3 桁、キータグを 5 桁の 0 埋めで書くのも `dnssec-keygen` と同じです。生成した基底名を `NewDNSSECKeyFileNameFromString` に戻すと同じ 3 つの値が得られます。

2 つを組み合わせる典型は、読み込んだ鍵の内容がファイル名と一致しているかの確認です。

```go
// 名前 1 つから、鍵ペアの読み取りに渡す基底名と期待するキータグを得る
kn, err := dnsmsg.NewDNSSECKeyFileNameFromString("keys/Kexample.com.+013+39506.key")
if err != nil {
	log.Fatal(err)
}
fmt.Println(kn.BaseName)  // "Kexample.com.+013+39506"
fmt.Println(kn.Name)      // "example.com."
fmt.Println(kn.Algorithm) // 13
fmt.Println(kn.KeyTag)    // 39506

// その名前が指す鍵ペアを読む
key, err := dnsmsg.ReadDNSSECKeyPair(kn.BaseName)
if err != nil {
	log.Fatal(err)
}

// 鍵の内容から計算したキータグがファイル名のキータグと一致するか
computed, err := key.KeyTag()
if err != nil {
	log.Fatal(err)
}
if computed != kn.KeyTag {
	log.Fatalf("key %s: file name says key tag %d, the key computes %d", kn.BaseName, kn.KeyTag, computed)
}
```

`NewDNSSECKeyFileNameFromString` の返すエラーは「エラーハンドリング」の対応表に掲載しています。

### 所属ドメイン名だけを得る（`InferDNSSECKeyNameFromFileName`）

```go
func InferDNSSECKeyNameFromFileName(path string) (DomainName, error)
```

`ReadPrivateKeyFile` は `.private` の中に所有者名を持たないので `Name` を空で返します（「`.private` ファイル」参照）。`dnssec-keygen` は鍵の所有者名をファイル名に書くので、その文字列から所属ドメイン名だけを取り出して鍵に設定するのがこのヘルパーの仕事です。

- 名前を受け付ける規則は `NewDNSSECKeyFileNameFromString` とまったく同じです（「受け付ける名前」参照）。`path` のファイルは開きません
- 返す値は `DomainName` 1 つだけです。アルゴリズムとキータグも必要なら `NewDNSSECKeyFileNameFromString` を使ってください
- `dnssec-keygen` が生成していない名前は推測せずエラーにします。設定済みの `key.Name` を上書きするかどうかを決めるのも呼び出し側です
- 1 組まとめて読むときは `ReadDNSSECKeyPair` が `.key` の所有者名を使うので、このヘルパーは必要ありません

```go
const privateFile = "keys/Kexample.com.+013+39506.private"

key, err := dnsmsg.ReadPrivateKeyFile(privateFile)
if err != nil {
	log.Fatal(err)
}

// .private には所有者名が無い。同じ鍵のファイル名から補う
key.Name, err = dnsmsg.InferDNSSECKeyNameFromFileName(privateFile)
if err != nil {
	log.Fatal(err)
}

fmt.Println(key.Name)                 // "example.com."
fmt.Println(key.Algorithm)            // 13
fmt.Println(len(key.PrivateKey) > 0)  // true
```

この `key` は秘密鍵マテリアルを持ちますが公開鍵を持たないままなので、`key.KeyTag()` はエラーのままです。公開鍵も必要なら同じ 1 組の `.key` を読む `ReadDNSSECKeyPair` を使ってください。

`InferDNSSECKeyNameFromFileName` の返すエラーは `NewDNSSECKeyFileNameFromString` のエラーに前置き `cannot infer DNSSEC key name from <path>: ` を付けたもので、内側の判定とそのつづりは変わりません（「エラーハンドリング」参照）。

## 使用例

### 1) `.key` ファイルから公開鍵を読み込み、`RecordDNSKEY` に変換する

```go
package main

import (
	"fmt"
	"log"

	"github.com/sischkg/dnsmsg"
)

func main() {
	// BIND dnssec-keygen で生成した .key ファイルを読み込む
	key, err := dnsmsg.ReadKeyFile("Kexample.com.+005+12345.key")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Name: %s\n", key.Name)        // 例: example.com.
	fmt.Printf("Flags: %d\n", key.Flags)       // 256 (ZSK) / 257 (KSK)
	fmt.Printf("Protocol: %d\n", key.Protocol) // 3
	fmt.Printf("Algorithm: %d\n", key.Algorithm)
	fmt.Printf("PublicKey: %x\n", key.PublicKey)

	// RecordDNSKEY に変換してゾーンファイルに公開できる
	dnskey := key.ToDNSKEY()
	fmt.Println(dnskey.String()) // 例: "256 3 5 YWJj"
}
```

### 2) `.private` ファイルから秘密鍵を読み込む

```go
package main

import (
	"fmt"
	"log"

	"github.com/sischkg/dnsmsg"
)

func main() {
	// dnssec-keygen で生成した .private ファイルを読み込む
	key, err := dnsmsg.ReadPrivateKeyFile("Kexample.com.+005+12345.private")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Algorithm: %d\n", key.Algorithm)
	fmt.Printf("PrivateKey: %x\n", key.PrivateKey)

	// 個別のパラメータにもアクセス可能
	if modulus, ok := key.PrivateParams["Modulus"]; ok {
		fmt.Printf("Modulus: %x\n", modulus)
	}
	if privExp, ok := key.PrivateParams["PrivateExponent"]; ok {
		fmt.Printf("PrivateExponent: %x\n", privExp)
	}

	// 公開鍵は .private ファイルには含まれないため nil
	if key.PublicKey == nil {
		fmt.Println("PublicKey: (not present in .private file)")
	}
}
```

### 3) `.key` ファイルで読み込んだ鍵を使ってレコードを構築する

```go
// .key ファイルを読み込み
key, err := dnsmsg.ReadKeyFile("Kexample.com.+008+54321.key")
if err != nil {
    log.Fatal(err)
}

// DNSKEY レコードとして追加
rr := dnsmsg.ResourceRecord{
    Name:  key.Name,
    Class: dnsmsg.CLASS_IN,
    Type:  dnsmsg.TYPE_DNSKEY,
    TTL:   3600,
    RData: key.ToDNSKEY(),
}

// ワイヤフォーマットにシリアライズ
var w dnsmsg.WireFormat
db := dnsmsg.NewNameCompressionDB()
rr.AppendWireFormat(&w, db)
```

### 4) 鍵ペアを読んで署名し、DNSKEY で検証する

```go
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/sischkg/dnsmsg"
)

func main() {
	// dnssec-keygen が同じ接頭辞で生成した .private と .key を 1 つの鍵として読む
	key, err := dnsmsg.ReadDNSSECKeyPair("Kexample.com.+013+39506")
	if err != nil {
		log.Fatal(err)
	}

	// 公開鍵マテリアルも揃った鍵なので、NewDNSSECSigner は秘密鍵から導出した公開鍵を
	// その公開鍵マテリアルと突き合わせる
	signer, err := dnsmsg.NewDNSSECSigner(key)
	if err != nil {
		log.Fatal(err)
	}

	// SignRRSet はキータグを引数として受け取る。DNSKEY から計算した値を渡す
	tag, err := key.KeyTag()
	if err != nil {
		log.Fatal(err)
	}

	name := key.Name
	rs := dnsmsg.NewRRSet(
		name,
		dnsmsg.CLASS_IN,
		dnsmsg.TYPE_A,
		3600,
		dnsmsg.NewRecordA([4]byte{192, 0, 2, 1}),
	)

	now := time.Now()
	rrsig, err := dnsmsg.SignRRSet(
		&rs,
		signer,
		key.Algorithm,
		tag,
		name,
		uint32(now.Unix())-3600,
		uint32(now.Unix())+86400,
	)
	if err != nil {
		log.Fatal(err)
	}

	// 同じ鍵の DNSKEY で検証する。キータグが RRSIG と一致していることも確認できる
	dnskey := key.ToDNSKEY()
	if dnskey.KeyTag() != tag {
		log.Fatalf("key tag mismatch: %d != %d", dnskey.KeyTag(), tag)
	}
	if err := dnsmsg.VerifyRRSetWithDNSKEY(&rs, rrsig, &dnskey, now); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("verified %s with key tag %d\n", name, tag)
}
```

既存の `ReadKeyFile` / `ReadPrivateKeyFile` で 2 つのファイルを別々に読む場合は、
`MergeDNSSECKey` で 2 つの半分を 1 つの鍵に統合してください（「公開鍵と秘密鍵の統合」参照）。

```go
base := "Kexample.com.+013+39506"

private, err := dnsmsg.ReadPrivateKeyFile(base + ".private")
if err != nil {
	log.Fatal(err)
}
public, err := dnsmsg.ReadKeyFile(base + ".key")
if err != nil {
	log.Fatal(err)
}
key, err := dnsmsg.MergeDNSSECKey(public, private)
if err != nil {
	log.Fatal(err)
}
```

`key` は上記の `signer` と `tag` を得るための鍵です。`private.PublicKey = public.PublicKey`
と `private.Name = public.Name` の 2 つの代入だけで同じ形の鍵を作ることもできますが、その場合は
2 つのファイルの `Algorithm` が同じかどうかを確認せず、鍵が署名に使えるかどうかの確認も
`NewDNSSECSigner` を呼ぶ時点まで引っ張ります。
`ReadDNSSECKeyPair` は同じ統合と `Algorithm` の照合を 2 つのファイル名の解決といっしょに行う
関数なので、ファイルから読むだけならそちらを使ってください。

## エラーハンドリング

| ケース | エラー内容 |
|------|-----------|
| ファイルが存在しない | `os.ReadFile` のエラーをラップして返す |
| DNSKEY レコードが見つからない | `no DNSKEY record found in <filename>` |
| 行のフィールド数が不足 | `invalid DNSKEY key line ...: expected at least 7 fields` |
| クラスが `IN` 以外 | `invalid DNSKEY key line ...: expected class IN` |
| タイプが `DNSKEY` 以外 | `invalid DNSKEY key line ...: expected type DNSKEY` |
| ドメイン名が不正 | `invalid DNSKEY name ...: <reason>` |
| フラグ/プロトコル/アルゴリズムが数値でない | `invalid <field> ...: <reason>` |
| 公開鍵の base64 が不正 | `invalid DNSKEY public key ...: illegal base64 data...` |
| `.private` に `Algorithm` 行がない | `no algorithm found in private key file <filename>` |
| `.private` のパラメータの base64 が不正 | `cannot decode private key parameter ...: illegal base64 data...` |
| `NewDNSSECSigner` に `nil` を渡す | `DNSSEC key is nil` |
| 公開鍵のみ（`.key` だけ）の鍵を署名に使う | `DNSSEC key <name> has no private key material: read the .private file` |
| 未対応アルゴリズムで署名しようとする | `unsupported DNSSEC algorithm <n> for signing` |
| 必要な秘密パラメータがない | `DNSSEC key <name> has no RSA private key parameter "<name>"`、`... has no ECDSA private key parameter "PrivateKey"`、`... has no Ed25519 private key parameter "PrivateKey"` |
| 秘密鍵のパラメータ長や値が不正 | `invalid RSA private key in DNSSEC key <name>: ...`、`invalid ECDSA private key in DNSSEC key <name>: the private scalar must be <n> octets, got <n>`、`invalid Ed25519 private key in DNSSEC key <name>: the seed must be 32 octets, got <n>` |
| 公開指数が DNSKEY と一致しない | `invalid RSA public exponent in DNSSEC key <name>: it must be at least 2 and less than 2^31` |
| 秘密鍵から導出した公開鍵が DNSKEY の公開鍵と違う | `DNSSEC key <name>: its private key does not match its DNSKEY public key` |
| `KeyTag` を公開鍵マテリアルなしで呼ぶ | `cannot compute the key tag of DNSSEC key <name>: no public key material` |

`ReadDNSSECKeyPair` / `ReadDNSSECKeyFiles` が返すエラー:

| ケース | エラー内容 |
|------|-----------|
| どちらかのファイルが読めない | 上記の `ReadKeyFile` / `ReadPrivateKeyFile` と同じエラー（解決されたファイル名を含む） |
| 2 つのファイルの `Algorithm` が違う | `DNSSEC key pair <key file> and <private file>: the algorithms do not match, the public key uses algorithm <n> (<name>) and the private key uses algorithm <n> (<name>)` |
| 統合後の鍵が署名に使えない | `DNSSEC key pair <key file> and <private file>: <NewDNSSECSigner のエラー>`（「読み込み時の検証」参照） |
| 基底名が空 | `cannot read DNSSEC key pair: the base name is empty`、または拡張子だけのとき `cannot read DNSSEC key pair ".key": the base name is empty` |
| 拡張子が小文字でつづられていない | `cannot read DNSSEC key pair <name>: the key file suffix is "<suffix>", which is not spelled in lower case` |

`NewDNSSECKeyFileNameFromString` が返すエラー（前置き `cannot parse DNSSEC key file name <path>: `。`<path>` は呼び出し側が渡した名前そのままです）:

| ケース | エラー内容 |
|------|-----------|
| 入力が空 | `cannot parse DNSSEC key file name: the name is empty`（入力が空のときは名前を添えない） |
| 入力か、除かれた後の名前が空 | `cannot parse DNSSEC key file name <path>: the name is empty`（`.key` だけの入力など） |
| 拡張子が小文字でつづられていない | `cannot parse DNSSEC key file name <path>: the key file suffix is "<suffix>", which is not spelled in lower case` |
| `K` で始まらない | `cannot parse DNSSEC key file name <path>: the name does not begin with "K"` |
| `+` で区切られたフィールド数が 3 でない | `cannot parse DNSSEC key file name <path>: after the "K" prefix the name has <n> fields separated by "+", want 3: the owner name, the algorithm and the key tag` |
| 所有者名が不正 | `cannot parse DNSSEC key file name <path>: owner name "<field>": <NewDomainNameFromString のエラー>` |
| アルゴリズムが数値でないか 255 を超える | `cannot parse DNSSEC key file name <path>: algorithm "<field>": <strconv.ParseUint のエラー>` |
| キータグが数値でないか 65535 を超える | `cannot parse DNSSEC key file name <path>: key tag "<field>": <strconv.ParseUint のエラー>` |

`MergeDNSSECKey` が返すエラー:

| ケース | エラー内容 |
|------|-----------|
| 公開鍵の引数が `nil` | `cannot merge DNSSEC key: the public key is nil` |
| 秘密鍵の引数が `nil` | `cannot merge DNSSEC key: the private key is nil` |
| 公開鍵側に公開鍵マテリアルがない | `cannot merge DNSSEC key: the public key carries no DNSKEY public key material, which is what a key read from a .private file has, so the merged key would have no DNSKEY to describe` |
| 秘密鍵側に秘密鍵マテリアルがない | `cannot merge DNSSEC key: the private key carries no private key material, which is what a key read from a .key file has, so the merged key would have nothing to sign with` |
| 公開鍵の `Algorithm` が 0 | `cannot merge DNSSEC key: the public key names no algorithm, so the merged key would have none` |
| 秘密鍵の `Algorithm` が 0 | `cannot merge DNSSEC key: the private key names no algorithm, so the merged key would have none` |
| 2 つの `Algorithm` が違う | `cannot merge DNSSEC key: the algorithms do not match, the public key uses algorithm <n> (<name>) and the private key uses algorithm <n> (<name>)` |
| 統合できた鍵が署名に使えない | 前置きなしの `NewDNSSECSigner` のエラーそのまま（上記の表を参照） |

前置き `cannot merge DNSSEC key: ` が付くのは 2 つの半分が統合を受けられない場合だけです。
統合はできたがその鍵で署名できない場合（秘密鍵が公開鍵と対応しない、アルゴリズムが未対応など）の
エラーは `NewDNSSECSigner` のそのままの文言で返ります。鍵ペアを読む経路は同じエラーに
2 つのファイル名を添えます（`DNSSEC key pair <key file> and <private file>: ...`）。

`ParseDNSSECKey` / `ParseDNSSECPrivateKey` / `ReadDNSSECKey` / `ReadDNSSECPrivateKey` が返すエラー:

| ケース | エラー内容 |
|------|-----------|
| 内容に DNSKEY レコードがない（空の入力を含む） | `no DNSKEY record found in <入力の呼び名>` |
| DNSKEY 行が不正 | `cannot parse <入力の呼び名>: <上記の表と同じ行パースのエラー>` |
| `.private` 内容に `Algorithm` 行がない（空の入力を含む） | `no algorithm found in <入力の呼び名>` |
| `.private` の `Algorithm` の値が不正 | `cannot parse <入力の呼び名>: empty algorithm value ...`、`cannot parse <入力の呼び名>: invalid algorithm number ...` |
| `.private` のパラメータの base64 が不正（`Name:` 行を含む `.private` もここ） | `cannot decode private key parameter "<name>" in <入力の呼び名>: illegal base64 data...` |
| `io.Reader` からの読み取りが失敗 | `cannot read DNSSEC key data: <読み取りのエラー>`、`cannot read DNSSEC private key data: <読み取りのエラー>` |

`<入力の呼び名>` は「鍵の内容を直接パースする」の「エラーメッセージでの入力の呼び名」で説明した
既定の名前（`DNSSEC key data` / `DNSSEC private key data`）、または `ParseDNSSECKeyWithSource` /
`ParseDNSSECPrivateKeyWithSource` に渡した名前です。`ParseDNSSECKeyLine` のエラーは上の表の各行の
行パースそのものの文言（`invalid DNSKEY key line ...` など）で、`cannot parse ...` の前置きは付きません。
入力が 1 行直接渡されているためです。

これらのエラーは `ReadKeyFile` / `ReadPrivateKeyFile` のエラーと同じ組み立てで、同じ失敗理由を報告します:

- パース対象をそのまま名乗るエラー（`no DNSKEY record found in <name>`、
  `cannot decode private key parameter "<name>" in <name>`）は、バイト列 API に
  `ParseDNSSECKeyWithSource(data, <path>)` / `ParseDNSSECPrivateKeyWithSource(data, <path>)`
  と元のファイル名を渡すと、ファイル API の対応するエラーと完全に同一の文字列になります。
- `cannot parse ...` と `no algorithm found in ...` が引入するエラーは、入力を導入する文言だけが
  違います。ファイル API は `key file <path>` / `private key file <path>` と呼び、
  バイト列 API は渡された名前をそのまま使います。包まれている中身（上記の表のパースエラー）は
  同一です。

## 補足

- `ReadKeyFile` / `ReadPrivateKeyFile` / `ParseDNSSECKey` / `ParseDNSSECPrivateKey` は入力の **最初の一致レコード** しか返しません。複数の鍵を含むファイルがある場合は、ファイルを分割して 1 行ずつ `ParseDNSSECKeyLine` でパースするか、独自に複数行をパースしてください。
- base64 の **出力**（`RecordDNSKEY.String()` など）はパディングなし（RawStdEncoding）でエンコードされます。**入力**（`.key` / `.private` の読み取り）はパディングの有無を問わず受け付けます（まずパディングありで復号を試み、失敗した場合にパディングなしで復号します）。
- 秘密鍵（`PrivateKey` / `PrivateParams`）は平文で扱われるため、ファイルのアクセス権限（例: `0600`）など取り扱いに注意してください。
- `.private` の鍵から `crypto.Signer` を作って RRSet に署名し、DNSKEY で検証する一連の手順は [rrset.md](rrset.md) の「DNSSEC 署名と検証」にあります。ゾーン全体に署名する場合は [zone.md](zone.md) の `Zone.Sign` を参照してください。

## 関連リンク

- [index.md](index.md) — パッケージ概要
- [rrset.md](rrset.md) — DNSSEC 署名と検証（`SignRRSet` / `VerifyRRSet`）
- [zone.md](zone.md) — `Zone.Sign` によるゾーン全体の署名と NSEC
- [RFC 4034](https://datatracker.ietf.org/doc/html/rfc4034) — DNS Security (DNSSEC) Resource Records
- [RFC 4034 Appendix B](https://datatracker.ietf.org/doc/html/rfc4034#appendix-B) — DNSKEY のキータグの計算例
- [RFC 5910](https://datatracker.ietf.org/doc/html/rfc5910) — Use of DNSSEC Algorithms and Security Algorithm
- [RFC 6605](https://datatracker.ietf.org/doc/html/rfc6605) — ECDSA DNSSEC Operations（楕円曲鍵のパラメータ表記）
- [RFC 8080](https://datatracker.ietf.org/doc/html/rfc8080) — Edwards-Curve Digital Security Algorithm (Ed25519) DNSSEC
- [BIND dnssec-keygen](https://www.isc.org/bind/) — BIND に付属する DNSSEC 鍵生成ツール
