# 第三者の資材について

## 同梱フォント

- `assets/NotoSansJP.ttf`: Noto Sans JP。Copyright 2014–2021 Adobe、Reserved Font Name: Source。
  SIL Open Font License 1.1の全文と表示を [assets/OFL-NotoSansJP.txt](assets/OFL-NotoSansJP.txt) に保持しています。
- eguiの固定依存 `epaint_default_fonts 0.37.0` に含まれるフォントの許諾原文も保持しています。
  Hack / DejaVu / Bitstream Veraは [licenses/egui-Hack-Regular.txt](licenses/egui-Hack-Regular.txt)、
  Ubuntuは [licenses/egui-UFL.txt](licenses/egui-UFL.txt)、
  Noto Emojiは [licenses/egui-OFL.txt](licenses/egui-OFL.txt)、
  emoji-icon-fontは [licenses/egui-emoji-icon-font-mit-license.txt](licenses/egui-emoji-icon-font-mit-license.txt) を参照してください。
  各字形の組込みは依存crateのfeature設定によります。これらのフォント本体はCargoが取得します。

フォントの許諾条件は自作ソースのApache-2.0とは別に適用されます。

MSゴシックは利用者のWindows内から実行時に読み取ります。フォント本体はこのソース一式にも
ビルド出力にも含めず、再配布しません。利用できない場合は同梱のNoto Sans JPへ戻ります。

## 公開証明書と試験データ

`data/roots/*.pem` は [OpenJDK jdk-25-gaの公開CAデータ](https://github.com/openjdk/jdk/tree/jdk-25-ga/src/java.base/share/data/cacerts)
から抽出した公開証明書です。出典とDER SHA-256は `data/policy.json` に記載しています。
証明書の名義人は各証明書のSubject / Issuerを参照してください。
アプリの試験入力として使い、信頼ストアへの追加は行いません。

`crates/trust_repair_core/testdata/*.pem` は同名別DERと日本語名の解析試験用の公開証明書です。
秘密鍵や署名用証明書は含みません。

## アプリアイコン

盾とチェックのアイコン（`crates/trust_repair_app/assets/app.png` / `app.ico`）は自作資材です。
Copyright (c) 2026 EnterSystem CO.,LTD. / Author: Shunji Ogawa / Apache-2.0。

## Rustの依存crate

Windowsのリソース埋込みにはビルド時だけ `embed-resource 3.0.12`（MIT）を使用します。
依存crateの版は `Cargo.lock` に固定し、Cargo経由で取得します。
このソース一式へ第三者crateのソースをvendoringしていません。
各crateのライセンス表示・許諾文は取得したcrateに含まれるものを参照してください。
MSゴシックのfamily照合には、既存の依存物でもある `skrifa 0.44.0`（MIT OR Apache-2.0）を直接利用します。
exeを再配布する際には、そのビルドに含まれる依存物と埋込みフォントの必要な表示・許諾文も揃えてください。
この文書は全依存物のライセンス監査完了を示すものではありません。
