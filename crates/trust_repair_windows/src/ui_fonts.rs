//------------------------------------------------------------------------------
/*!
 * - ファイル: ui_fonts.rs
 * - 概要: Windowsが管理するフォントディレクトリを読み取り用に取得します。
 * - バージョン: 01.00.00
 * - 作成日: 2026/10/27
 * - 制作者: Shunji Ogawa
 * - 著作権: Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * ライセンス:
 *
 * SPDX-License-Identifier: Apache-2.0
 * 本ファイルには Apache License, Version 2.0 が適用されます。
 * ライセンス全文はプロジェクトルートの LICENSE を参照してください。
 * <https://www.apache.org/licenses/LICENSE-2.0>
 *
 * 会社名: EnterSystem
 *
 * 更新履歴:
 *
 * ```text
 * VerNo.        author        update      comment
 * Ver.01.00.00  Shunji Ogawa  2026/10/27  新規作成。
 * ```
 *
 * 備考:
 *
 * フォントをコピー・配布せず、環境変数やOS設定を変更しません。
 */
//------------------------------------------------------------------------------

#![allow(unsafe_code)]

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;

//------------------------------------------------------------------------------
/**
 * Windowsディレクトリ内のFontsパスを返します。ファイルの存在・可読性は保証しません。
 * OS取得に失敗した場合はNoneを返し、呼出し元が埋込みフォントへ戻れます。
 * 引数・所有ハンドル・書込みはなく、任意のthreadから呼べます。
 *
 * # Returns
 *
 * OS が返す Windows ディレクトリに `Fonts` を加えたパス。
 * OS の取得失敗またはバッファ不足の場合は `None`。
 */
//------------------------------------------------------------------------------
pub fn windows_fonts_directory() -> Option<PathBuf> {
	let mut buffer = vec![0_u16; 32_768];
	// SAFETY: bufferは指定長の書込み可能なUTF-16領域で、呼出し終了まで生存します。
	let length = unsafe {
		windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW(
			buffer.as_mut_ptr(),
			buffer.len() as u32,
		)
	} as usize;
	// OS の取得失敗や切り詰めをパスとして採用せず、埋込み font へ戻せるようにする
	if length == 0 || length >= buffer.len() {
		return None;
	}
	Some(PathBuf::from(OsString::from_wide(&buffer[..length])).join("Fonts"))
}
