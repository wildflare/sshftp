# sshftp

Windows PowerShell向け SSH クライアント。インタラクティブシェル・SFTP ファイラー・接続先マネージャーを備えた単一実行ファイル。

![Platform](https://img.shields.io/badge/platform-Windows-blue)
![Language](https://img.shields.io/badge/language-C-lightgrey)

## 機能

- **インタラクティブ SSH シェル** — vim・htop などフル対応、マウスもそのまま使える
- **SFTP ファイラー** — ローカル↔リモートの2ペイン、複数ファイル選択・転送・削除
- **接続先マネージャー** — パスワード／公開鍵認証、接続先を JSON で保存


## ビルド

[MSYS2](https://www.msys2.org/) の MinGW64 環境が必要です。

```bash
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-libssh2 mingw-w64-x86_64-openssl
make
```

## 使い方

```bash
# 接続先マネージャーを起動
sshftp.exe

# パスワード認証で直接接続
sshftp.exe 192.168.1.10 22 user password

# 公開鍵認証
sshftp.exe 192.168.1.10 22 user pubkey C:/Users/you/.ssh/id_rsa
sshftp.exe 192.168.1.10 22 user pubkey C:/Users/you/.ssh/id_rsa passphrase

# ファイラーのホットキーを変更（デフォルト: F12）
sshftp.exe --filer-key=f10
sshftp.exe --filer-key=ctrl-g 192.168.1.10 22 user password
```

## 操作

### 接続先マネージャー

| キー | 動作 |
|------|------|
| ↑↓ | 選択 |
| Shift+↑↓ | 並び替え |
| Enter | 接続 |
| N | 新規追加 |
| E | 編集 |
| D | 削除 |
| Q / Esc | 終了 |

### SSH シェル

| キー | 動作 |
|------|------|
| F12 | SFTP ファイラーを開く |
| exit | 切断・終了 |

### SFTP ファイラー

```
[Local] C:\Users\you\Documents    |  [Remote] /home/user
 [..]                  <DIR>      |  [..]                  <DIR>
 {docs          }      <DIR>      |  *readme.md *            1.2K  2024-01-01
  main.c               34.0K     |  [src           ]        <DIR>
```

| キー | 動作 |
|------|------|
| ↑↓ | 選択移動 |
| Space | マーク切り替え（黄色表示） |
| Ctrl+A | 全ファイルマーク / 全解除 |
| Tab | ローカル↔リモートペイン切替 |
| Enter | ディレクトリに入る（`..` で上へ） |
| F5 | コピー（マーク中は全マークファイル） |
| F6 | 移動（マーク中は全マークファイル） |
| F8 / Delete | 削除（Y で確認） |
| F12 / Q / Esc | シェルに戻る |

ローカルペインでは `..` を上に辿ることで `My Computer`（ドライブ一覧）に移動できます。



## ライセンス

MIT
