//------------------------------------------------------------------------------
/*!
 * - ファイル: build.rs
 * - 概要: Windows の実行ファイルへアプリアイコンと製品版数を埋め込みます
 * - バージョン: 01.01.00
 * - 作成日: 2026/10/27
 * - 制作者: Shunji Ogawa
 * - 著作権: Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * ライセンス:
 *
 * SPDX-License-Identifier: Apache-2.0
 * 本ファイルには Apache License, Version 2.0 が適用されます。
 * ライセンス全文はプロジェクトルートの LICENSE を参照してください
 * <https://www.apache.org/licenses/LICENSE-2.0>
 *
 * 会社名: EnterSystem
 *
 * 更新履歴:
 *
 * ```text
 * VerNo.        author        update      comment
 * Ver.01.00.00  Shunji Ogawa  2026/10/27  新規作成
 * Ver.01.01.00  Shunji Ogawa  2026/10/27  Cargo の製品版数を Windows の版情報へ連携
 * ```
 *
 * 備考:
 *
 * 入力は assets/app.rc と app.ico、Cargo の製品版数です。生成物は OUT_DIR に限定します。
 * Windows SDK の resource compiler を使用し、ネットワーク取得や実機設定変更は行いません
 */
//------------------------------------------------------------------------------
#![forbid(unsafe_code)]

//------------------------------------------------------------------------------
/**
 * RC・ICO・製品版数の変更時に再実行し、アプリ exe だけへ icon と版情報をリンクします
 *
 * # Returns
 *
 * resource のコンパイルと、指定アプリへのリンク設定が完了すれば `Ok(())`
 *
 * # Errors
 *
 * Windows SDK の resource compiler が不在、または RC/ICO のコンパイルに失敗した場合
 *
 * # Notes
 *
 * 入力変更の rerun 条件を Cargo へ通知し、生成物を OUT_DIR に限定します。
 * プロジェクトの配布用 output は更新しません
 */
//------------------------------------------------------------------------------
fn main() -> Result<(), embed_resource::CompilationResult> {
	println!("cargo:rerun-if-changed=assets/app.rc");
	println!("cargo:rerun-if-changed=assets/app.ico");
	println!("cargo:rerun-if-env-changed=CARGO_PKG_VERSION");
	// Cargo の製品版数を唯一の入力とし、RC 内に独立した製品版数を残さない
	let version_definitions = [
		format!("APP_VERSION_MAJOR={}", env!("CARGO_PKG_VERSION_MAJOR")),
		format!("APP_VERSION_MINOR={}", env!("CARGO_PKG_VERSION_MINOR")),
		format!("APP_VERSION_PATCH={}", env!("CARGO_PKG_VERSION_PATCH")),
		format!("APP_VERSION_TEXT=\"{}\"", env!("CARGO_PKG_VERSION")),
	];
	embed_resource::compile_for("assets/app.rc", ["java-trust-repair"], version_definitions)
		.manifest_required()
}
