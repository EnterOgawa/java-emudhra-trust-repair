//------------------------------------------------------------------------------
/*!
 * - ファイル: ui_language.rs
 * - 概要: Windows の利用者表示言語を副作用なく取得します。
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
 * Ver.01.00.00  Shunji Ogawa  2026/10/26  利用者 UI の LANGID を公開。
 * ```
 *
 * 備考: OS 設定、thread の言語、環境変数を変更しません。
 */
//------------------------------------------------------------------------------

#![allow(unsafe_code)]

//------------------------------------------------------------------------------
/**
 * 現在の利用者の Windows 表示言語 LANGID を返します。
 * 引数・所有資源・書込みはありません。任意の thread から呼べます。
 * 戻り値が 0 の場合、呼出し元は英語を既定にできます。
 */
//------------------------------------------------------------------------------
pub fn user_ui_language() -> u16 {
	// SAFETY: 引数も pointer もなく、OS が所有する値を整数で取得する API です。
	unsafe { windows_sys::Win32::Globalization::GetUserDefaultUILanguage() }
}
