//------------------------------------------------------------------------------
/*!
 * - ファイル: ui_fonts.rs
 * - 概要: Windowsが管理するフォントディレクトリを読み取り用に取得します。
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
 * Ver.01.00.00  Shunji Ogawa  2026/10/26  OSからフォントディレクトリを取得する安全な境界を追加。
 * ```
 *
 * 備考: フォントをコピー・配布せず、環境変数やOS設定を変更しません。
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
	if length == 0 || length >= buffer.len() {
		return None;
	}
	Some(PathBuf::from(OsString::from_wide(&buffer[..length])).join("Fonts"))
}
