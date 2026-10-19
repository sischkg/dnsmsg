# devcontainer: Go 1.23 + git + OpenCode (V2) + gopls + curl/wget + BIND ツール
FROM mcr.microsoft.com/devcontainers/go:1.23

# ---------- root: システムパッケージ ----------
USER root
# ベースイメージに同梱の Yarn apt リポジトリは GPG キーが失効しており
# `apt-get update` が失敗するため、不要なリポジトリ定義を削除する
#
# BIND 関連ツール（DNSSEC / ゾーン検証用）の提供関係（Debian bookworm, bind 9.18）:
#   bind9-dnsutils : dig, delv, nslookup
#   bind9-utils    : named-checkzone, named-checkconf, named-compilezone,
#                    dnssec-keygen, dnssec-signzone, dnssec-settime など
#   （named サーバ本体の bind9 は入れない。検証・変換ツールのみ必要）
RUN rm -f /etc/apt/sources.list.d/yarn.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        git \
        build-essential \
        ca-certificates \
        curl \
        wget \
        bind9-dnsutils \
        bind9-utils \
        && \
    rm -rf /var/lib/apt/lists/*

# ---------- vscode: ユーザーツール ----------
USER vscode

# ユーザーの GOPATH / PATH を固定して再現性を担保
ENV GOPATH=/home/vscode/go
ENV PATH="/home/vscode/go/bin:/home/vscode/.opencode/bin:/usr/local/go/bin:$PATH"

# OpenCode が Go 開発で使う Go LSP（gopls）
# ビルドには cgo/gcc が使えることが前提（build-essential をインストール済み）
# 注: gopls は Go 1.23 適合の最新版 v0.18.1（v0.19.1 以降は go ≥1.24.2 を要求）を固定している
RUN go install golang.org/x/tools/gopls@v0.18.1

# OpenCode CLI (V2) — 公式インストーラーでステンドアロンバイナリを
# $HOME/.opencode/bin へインストール（Node.js 不要）
# 注: バージョンを固定することで、バージョン一覧 API への依存を排除し再現性を担保する
RUN curl -fsSL https://opencode.ai/v2/install | bash -s -- --no-modify-path --version 2.0.22 \
    && opencode --version

# ホストからマウントする OpenCode 設定ディレクトリを事前作成
# （存在していないと devcontainer の bind mount が失敗するため）
RUN mkdir -p /home/vscode/.config/opencode \
             /home/vscode/.local/share/opencode

# ---------- root: ログインシェル用 PATH 補完 ----------
# ベースイメージの /etc/profile が PATH を上書きし ENV の PATH を消すため、
# ログインシェル（bash -l / VSCode ターミナル）でも gopls と opencode が
# 解決できるように profile.d スクリプトを追加する
USER root
RUN printf '%s\n' 'export PATH="/home/vscode/go/bin:/home/vscode/.opencode/bin:$PATH"' \
        > /etc/profile.d/99-gopls-opencode.sh
USER vscode
