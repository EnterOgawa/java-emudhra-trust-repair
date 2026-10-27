//------------------------------------------------------------------------------
/*!
 * - ファイル: build.rs
 * - 概要: Windows の実行ファイルへアプリアイコンを埋め込みます
 * - バージョン: 01.00.00
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
 * ```
 *
 * 備考:
 *
 * 入力は assets/app.rc と app.ico、生成物は Cargo の OUT_DIR に限定します。
 * Windows SDK の resource compiler を使用し、ネットワーク取得や実機設定変更は行いません
 */
//------------------------------------------------------------------------------
#![forbid(unsafe_code)]

//------------------------------------------------------------------------------
/**
 * RC と ICO の変更時に再実行し、アプリ exe だけへ icon resource をリンクします
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
	embed_resource::compile_for("assets/app.rc", ["java-trust-repair"], embed_resource::NONE)
		.manifest_required()
}
