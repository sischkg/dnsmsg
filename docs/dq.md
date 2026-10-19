# dq — クエリを送信して送受信メッセージを表示するコマンド

`cmd/dq` は `dnsmsg` パッケージの上で動くコマンドラインツールです。
コマンドラインから DNS クエリを組み立てて指定したサーバへ送信し、
**送信したクエリメッセージ**と**受信した応答メッセージ**を JSON で出力します。

出力は実際に送受信したメッセージそのものです。応答が切り詰められていても
（TC=1）別のトランスポートで問い直すことはしません。

## 構築

```sh
go build -o dq ./cmd/dq
```

## 使い方

```
usage: dq [options] <domain-name>

  -s <server>   問い合わせ先サーバのアドレスまたはホスト名
                (既定: /etc/resolv.conf の最初の nameserver)
  -p <port>     問い合わせ先のポート番号 (既定: 53)
  -c <class>    QCLASS (既定: IN)
  -t <type>     QTYPE (既定: A)
  -r            RD=1 (再帰的問い合わせ) を設定する
  --tcp         トランスポートに TCP を使う
  --udp         トランスポートに UDP を使う (既定)
  -o <format>   出力形式 (現在 json のみ)
  --edns        EDNS0 を問い合わせに含める (既定)
  --no-edns     EDNS0 を問い合わせに含めない
  --nsid        問い合わせに長さ 0 の NSID オプションを含める
  --timeout <n> 接続・送信・応答待ちの上限を秒で指定する (既定: 5)
                0 は無制限
```

- ドメイン名は位置引数を 1 つだけ指定します（`-h` を除いて位置引数が 0 個または
  2 個以上のときは使い方を出て終了コード 2 になります）。
- オプションはドメイン名の前後のどちらに置いても同じ意味になります。
  `dq example.com -r` は `dq -r example.com` と同じです。
- `--` より後ろはすべて位置引数として扱われます。`-` で始まるドメイン名を
  渡すときに使います（`dq -- -example.com`）。
- `-h` は使い方を表示して終了コード 0 で終わります。

## オプション

| オプション | 意味 | 既定 |
|------------|------|------|
| `-s <server>` | 問い合わせ先サーバ。IPv4 / IPv6 アドレスまたはホスト名 | `/etc/resolv.conf` の最初の `nameserver` |
| `-p <port>` | 問い合わせ先のポート番号。0 と 65535 より大はエラー | `53` |
| `-c <class>` | QCLASS | `IN` |
| `-t <type>` | QTYPE | `A` |
| `-r` | ヘッダの RD ビットを 1 にする（再帰的問い合わせ） | RD=0 |
| `--tcp` | トランスポートに TCP を使う | — |
| `--udp` | トランスポートに UDP を使う | 既定のトランスポート |
| `-o <format>` | 出力形式。現在 `json` のみ | `json` |
| `--edns` | 問い合わせに OPT レコード（EDNS0）を含める | 含む |
| `--no-edns` | 問い合わせに OPT レコードを含めない | — |
| `--nsid` | 問い合わせの OPT に長さ 0 の NSID オプションを含める | 含めない |
| `--timeout <n>` | 接続・送信・応答待ちの上限を秒で指定する。0 は無制限、小数も可（`--timeout 0.5`） | `5` 秒（`dnsmsg.DefaultQueryTimeout`） |

`--tcp` と `--udp`、`--edns` と `--no-edns` を同時に指定するとエラーになります。
`--nsid` は OPT を使わない `--no-edns` と同時に指定できません。
`--edns=false` と書いても EDNS0 は使われません。
`--timeout` に負の数を与えるとエラーになります。

### 指定できる QCLASS・QTYPE

`-c` と `-t` は `dnsmsg` が名前を知っている値と、10 進の数値を受け付けます。

- クラス: `IN` / `CH` / `HS` / `ANY` または数値（`-c 3` は CH）
- タイプ: `A` / `NS` / `SOA` / `MX` / `AAAA` / `OPT` / `DS` / `RRSIG` /
  `DNSKEY` / `TSIG` / `NSEC` / `NSEC3` / `NSEC3PARAM`、`TYPE<n>` または数値
  （`-t 255` は TYPE255）

分からない値はエラーになります。

```console
$ ./dq -s 172.16.253.81 -c XX -r example.com
dq: QCLASS "XX" が分かりません
```

## 出力形式

`-o json`（既定）では 2 スペースでインデントした 1 つの JSON オブジェクトを
stdout に出します。中身は `dnsmsg.Message` の JSON 表現（`MarshalJSON`）そのままで、
`Message` の JSON の鍵（`ID` / `QR` / `OPCODE` / `QuestionSection` …）がそのまま使われます。

```json
{
  "query":    { … 送信したクエリメッセージ … },
  "response": { … 受信した応答メッセージ … }
}
```

- 応答を受信できなかったときは `"response": null` になります（この場合終了コード 1）。
- ドメイン名は末尾のドット付きで表示されます（`"example.com."`、root は `"."`）。
- OPT レコードは in-memory の形で表示されます。つまり `"Class": "IN"`、
  `"TTL"` は拡張 UDP ペイロードサイズ、`RData` は `Version` / `Flags` / `Options` です。
  wire format での CLASS・TTL の使い方との対応は [edns.md](edns.md) を参照してください。
- 問い合わせ先サーバを決めたこと、エラーの内容は stderr に出ます。
  stdout は JSON だけなので `jq` などにそのままパイプできます。

### 例: 基本的な問い合わせ

```console
$ ./dq -r -s 172.16.253.81 example.com
{
  "query": {
    "AA": 0,
    "AD": 0,
    "ANCOUNT": 0,
    "ARCOUNT": 1,
    "AdditionalSection": [
      {
        "Class": "IN",
        "Name": ".",
        "RData": {
          "Flags": 0,
          "Options": null,
          "Version": 0
        },
        "TTL": 1232,
        "Type": "OPT"
      }
    ],
    "AnswerSection": null,
    "AuthoritySection": null,
    "CD": 0,
    "ID": 125,
    "NSCOUNT": 0,
    "OPCODE": 0,
    "QDCOUNT": 1,
    "QR": 0,
    "QuestionSection": [
      {
        "Class": "IN",
        "QName": "example.com.",
        "Type": "A"
      }
    ],
    "RA": 0,
    "RCODE": 0,
    "RD": 1,
    "TC": 0,
    "Z": 0
  },
  "response": {
    "AA": 0,
    "AD": 0,
    "ANCOUNT": 2,
    "ARCOUNT": 1,
    "AdditionalSection": [
      {
        "Class": "IN",
        "Name": ".",
        "RData": {
          "Flags": 0,
          "Options": null,
          "Version": 0
        },
        "TTL": 1232,
        "Type": "OPT"
      }
    ],
    "AnswerSection": [
      {
        "Class": "IN",
        "Name": "example.com.",
        "RData": {
          "address": "172.66.147.243"
        },
        "TTL": 171,
        "Type": "A"
      },
      {
        "Class": "IN",
        "Name": "example.com.",
        "RData": {
          "address": "104.20.23.154"
        },
        "TTL": 171,
        "Type": "A"
      }
    ],
    "AuthoritySection": null,
    "CD": 0,
    "ID": 125,
    "NSCOUNT": 0,
    "OPCODE": 0,
    "QDCOUNT": 1,
    "QR": 1,
    "QuestionSection": [
      {
        "Class": "IN",
        "QName": "example.com.",
        "Type": "A"
      }
    ],
    "RA": 1,
    "RCODE": 0,
    "RD": 1,
    "TC": 0,
    "Z": 0
  }
}
```

`Message.MarshalJSON` は JSON オブジェクトを作るので、フィールドはアルファベット順に
並びます（ヘッダのビット順ではありません）。`ID` は問い合わせごとに乱数で決まるので
実際の値は毎回違います。TTL やアドレスなどの応答の内容はサーバによります。

### 例: NSID を要求する

```console
$ ./dq -r --nsid example.com | jq '.query.AdditionalSection[0].RData.Options'
[
  {
    "Code": 3,
    "ID": ""
  }
]
```

クエリ側に載せる NSID は長さ 0 のオプションです（RFC 7873 Section 3 の
「応答にあなたの NSID を載せてください」という要求）。サーバが NSID を返さないと
応答側の `Options` は `null` になります。

### 例: TCP で問い合わせる

```console
$ ./dq --tcp -r example.com | jq '.response.ANCOUNT'
2
```

TCP では RFC 1035 Section 4.2 の 2 オクテットの長さプレフィックスでフレーミングされ、
応答は複数セグメントに分かれて届いても最後まで読まれます。

### 例: EDNS0 を使わない

```console
$ ./dq --no-edns -r example.com | jq '{query_arcount: .query.ARCOUNT, response_arcount: .response.ARCOUNT}'
{
  "query_arcount": 0,
  "response_arcount": 0
}
```

### 例: 応答を受信できなかったとき

送信に失敗しても、受信できなかったときにも送信しようとしたクエリは出力されます。

```console
$ ./dq -s 127.0.0.1 -p 9 -r example.com
dq: cannot receive message from 127.0.0.1:9(read udp 127.0.0.1:60178->127.0.0.1:9: read: connection refused)
{
  "query": { … 送信したクエリ … },
  "response": null
}
$ echo $?
1
```

## 動作の詳細

### 問い合わせ先サーバ

`-s` を省略すると `/etc/resolv.conf` の最初の `nameserver` の行を使い、
どのサーバに問い合わせたかを stderr に出します。

```console
$ ./dq -r example.com
dq: -s が指定されていないので 172.16.253.81 に問い合わせます
```

resolv.conf が読めない、または `nameserver` が無いときは `127.0.0.1` を使い、
その旨を stderr に出します。

サーバはホスト名でもよく、接続時に解決されます（`-s dns.google` など）。

### タイムアウト

`--timeout <n>` は接続・送信・応答待ちの上限を秒で指定します。
既定は `dnsmsg.DefaultQueryTimeout`（5 秒）です。

- 秒は小数でもよく（`--timeout 0.5`）、上限はありません。
- `0` は無制限です。応答を返すまで待ち続けます。
- 上限は接続（`net.DialTimeout`）と、その接続の送受信の両方に適用されます
  （`SendQueryWithTimeout` が `SetDeadline` で締切を設定します）。
  接続にかかった時間も待ち時間に含まれます。
- 負の数はエラーになります。

タイムアウトで失敗したときも送信したクエリは出力され、`"response": null` になります。

```console
$ ./dq -s 192.0.2.1 --timeout 1 -r example.com
dq: cannot receive message from 192.0.2.1:53(read udp 172.17.0.2:50061->192.0.2.1:53: i/o timeout)
$ ./dq --timeout -1 example.com
dq: --timeout -1 は 0 秒以上で指定してください
```

`--timeout` を省略したときの待ち時間は `dnsmsg.DefaultQueryTimeout` そのものなので、
応答を返さないサーバへの問い合わせは 5 秒で失敗します。

```console
$ ./dq -s 192.0.2.1 -r example.com
dq: cannot receive message from 192.0.2.1:53(read udp 172.17.0.2:34972->192.0.2.1:53: i/o timeout)
```

### EDNS0 と NSID

既定で OPT レコードを付けます（dig と同じ挙動です）。
ペイロードサイズは `dnsmsg.EDNS0DefaultPayloadSize`（1232）、FLAGS は 0 です。
DNSSEC を要求する DO ビットを付けるオプションはありません。

`--nsid` は OPT に NSID オプションを 1 つ追加します。
OPT を付けない `--no-edns` とは同時に使えません。

### 切り詰められた応答

応答の TC ビットが 1 でも、そのまま出力します。TCP で問い直すことはしません。
必要なら `--tcp` を明示してください。

### 終了コード

| 終了コード | 意味 |
|------------|------|
| 0 | 成功。`-h` で表示を終えるときも 0 |
| 1 | QCLASS / QTYPE が分からない、送信・受信・JSON 出力に失敗した |
| 2 | 使い方のエラー（位置引数が 1 つではない、オプションの組み合わせが不正、ポート番号が範囲外、タイムアウトの値が不正、未対応の出力形式） |

### 使い方のエラーの例

```console
$ ./dq -o yaml example.com
dq: 出力形式 "yaml" には対応していません (json のみ)
$ ./dq --tcp --udp example.com
dq: --tcp と --udp は同時に指定できません
$ ./dq --nsid --no-edns example.com
dq: --nsid は --no-edns と同時に指定できません
$ ./dq -p 0 example.com
dq: ポート番号 0 が範囲外です
```

## 内部で使っている API

| 段階 | 使っている API |
|------|----------------|
| クエリの構築 | `Message.SetQuery`（Question セクション）、`Message.SetEDNS0`（OPT と EDNS option） |
| メッセージ ID | `crypto/rand` による 16 bit の乱数 |
| 送信・受信 | `SendQueryWithTimeout`（`SendQuery` は既定タイムアウトでこれを呼ぶ。[index.md](index.md) 参照） |
| JSON 出力 | `Message.MarshalJSON` を `json.MarshalIndent` 経由で出力 |

`cmd/dq/main.go` はテストしやすくなるように、引数の解析（`parseArgs`）、
クエリの構築（`buildQuery`）、処理全体（`run(args, stdout, stderr) int`）に
分かれています。`main` は `run(os.Args[1:], os.Stdout, os.Stderr)` の終了コードを
`os.Exit` に渡すだけです。

## 関連リンク

- [index.md](index.md) — パッケージの概要、`SendQuery` によるクエリ送信
- [edns.md](edns.md) — EDNS(0) / OPT レコードと EDNS option（NSID の wire 表現を含む）
