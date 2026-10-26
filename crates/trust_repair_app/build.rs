//------------------------------------------------------------------------------
/*!
 * - ファイル: build.rs
 * - 概要: Windows の実行ファイルへアプリアイコンを埋め込みます。
 * - バージョン: 01.00.00
 * - 作成日: 2026/10/26
 * - 制作者: Shunji Ogawa
 * - 著作権: Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * ライセンス: SPDX-License-Identifier: Apache-2.0
 * Apache License, Version 2.0。全文はルートの LICENSE を参照してください。
 *
 * 会社名: EnterSystem
 *
 * 更新履歴:
 * ```text
 * Ver.01.00.00  Shunji Ogawa  2026/10/26  ICO を通常の Cargo build で exe へ埋込み。
 * ```
 *
 * 備考: 入力は assets/app.rc と app.ico、生成物は Cargo の OUT_DIR に限定します。
 * Windows SDK の resource compiler を使用し、ネットワーク取得や実機設定変更は行いません。
 */
//------------------------------------------------------------------------------
#![forbid(unsafe_code)]

//------------------------------------------------------------------------------
/**
 * RC と ICO の変更時に再実行し、アプリ exe だけへ icon resource をリンクします。
 *
 * # 戻り値
 *
 * Windows の resource compiler が不在・失敗の場合は build を失敗させます。
 * アイコンを欠いた exe を成功扱いにせず、既存の配布用 exe は更新しません。
 */
//------------------------------------------------------------------------------
fn main() -> Result<(), embed_resource::CompilationResult> {
	println!("cargo:rerun-if-changed=assets/app.rc");
	println!("cargo:rerun-if-changed=assets/app.ico");
	embed_resource::compile_for("assets/app.rc", ["java-trust-repair"], embed_resource::NONE)
		.manifest_required()
}
