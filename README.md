# 🛡️ Java Trust Repair · eMudhra

Javaの版はそのままで、eMudhra関連ルートの信頼を解除したい。
そんな環境で、[Oracleの回避策](https://ops.java/emudhra)に沿って関連4ルートを信頼ストアから削除する、Windows用アプリです。
変更前のバックアップを作り、必要になったらアプリから元に戻せます。

## 🔧 ソースからビルドする

Windows x64で、次を用意してください。

- Rustの管理ツール [rustup](https://rustup.rs/)。使用するRustは `rust-toolchain.toml` の **1.99.1** です。
- Visual Studio 2022 / Build ToolsのC++ x64ビルドツールとWindows SDK。
  導入方法は [RustのMSVC環境案内](https://rust-lang.github.io/rustup/installation/windows-msvc.html)をご覧ください。

リポジトリのルートで実行します。初回はRustと依存crateの取得にネット接続が必要です。

```powershell
rustup show
.\build.ps1
```

完成するexeは **`output/JavaTrustRepair.exe`** です。毎回のビルドで、この場所へexeと必要な許諾文を配置します。
使用中で置換できない場合は既存exeを残して停止します。アプリを終了してから再実行してください。
`CARGO_TARGET_DIR` を指定した場合も、Cargoが返す実際の生成先から配置します。
直接 `cargo build` を実行したときの生成物はCargo内部のtarget側に残ります。受渡しには `build.ps1` を使ってください。
`output/` の生成物はGit管理・ソース公開の対象外です。
`.cargo/config.toml` でWindows x64とstatic CRTを指定しています。この設定も一緒に使ってください。
EXEとタイトルバーには同じ自作の盾アイコンを使います。Windows SDKのresource compilerで
アイコンを埋め込み、生成できない場合はビルドを停止します。PNG/ICOはソースに同梱しています。
ビルドにJavaや署名証明書は不要です。アプリの利用時には、選択するJava環境が必要です。

通常の単体テストとドキュメント内の例も確認できます。

```powershell
cargo test --locked --workspace --lib --bins
cargo test --locked --workspace --doc
```

`gui-qa` / `internal-qa` は開発用の機能です。通常ビルドでは指定しません。
隔離Javaを別途準備する結合試験は、上の単体テストには含まれません。

## 🚀 はじめて使う

まずはJavaフォルダを別の場所へ丸ごとコピーして試してみてください。

1. exeを起動し、`bin/java.exe` と `bin/keytool.exe` があるJavaフォルダを選びます。
2. 「eMudhra 関連証明書を無効化」を押し、対象と影響、バックアップ先を確認して進めます。
3. 完了したら、そのJavaを使っているアプリを再起動します。

フォルダを選ぶと現在の状態を自動確認し、「未無効化」「無効化済み」「判定不可」を表示します。
「無効化済み」は、確認した信頼ストアに対象の4ルートが見つからなかったという意味です。
確認・バックアップ・変更・結果の検証は、アプリが順に行います。
新しいバックアップは、選択したJDK/JRE内の `emudhra-backup` フォルダへ処理ごとに保存します。
フォルダ選択時の自動確認では作成しません。権限が足りない場合は、このアプリを閉じ、
右クリックの「管理者として実行」で起動し直してください。
標準パスワードは `changeit` です。変更済みの場合や追加の信頼ストアを扱う場合は、
「通常と異なる環境の設定」で指定してください。Windowsの表示言語に合わせて日本語・英語で表示します。

元に戻すときは同じJavaフォルダを選び、「元に戻す」から直近の変更を復元します。
復元後もJavaアプリを再起動してください。バックアップを消すと復元できません。
変更後に別の更新があった場合やバックアップが一致しない場合は、上書きせず理由を表示します。
Javaやバックアップを移動・コピーした場合は自動復元できません。復元確認が終わるまで元の場所と記録を保持してください。
従来のLocalAppDataのバックアップは移動せず、同じJavaと照合できた履歴を復元に利用します。

このリポジトリではビルド用のソースと必要な資材を公開しています。ソースからビルドしたEXEには署名は付きません。

## 🖥️ 対応と影響の範囲

- Windows 10/11 x64、Windows用Java **11 / 17 / 21 / 25 LTS** のJDK/JREが対象です。
- 選んだJavaの `cacerts`、存在する `jssecacerts`、明示追加した信頼ストアを確認します。
  JKS / PKCS12、ローカルNTFS上の通常ファイルに対応します。秘密鍵を含むストアは変更しません。
- 対象は emSign Root CA - G1 / G2、emSign ECC Root CA - G3、AAA Certificate Services の4ルートです。
  証明書全体のSHA-256で照合し、別名や名前だけでは削除しません。
- 関連する通信や署名の検証が失敗する場合があります。「元に戻す」は変更前の信頼状態への復元です。
- 別のJava、OS証明書ストア、アプリ独自の信頼設定まで確認するものではありません。
  対象が見つからない結果だけで、環境全体の安全を判断しないでください。

別PC・RDP・異なる画面環境やJava配布元などは、利用する環境での動作確認をお願いします。

画面は小さめの文字と灰色の立体枠を使った、従来のWindows風の表示です。
OSにあるMSゴシックを優先し、利用できない場合や不足する文字には同梱のNoto Sans JPを使います。
代替時は字形や文字幅が変わります。MSゴシック本体は同梱・再配布していません。

## 📄 ライセンス

Copyright (c) 2026 EnterSystem CO.,LTD. / Author: Shunji Ogawa

更新: 2026/10/26 / Java内バックアップと管理者案内、MSゴシック優先の表示に対応。

自作ソースは [Apache License 2.0](LICENSE) です。
フォント・証明書データ・依存crateについては [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) をご覧ください。
