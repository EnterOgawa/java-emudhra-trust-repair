//------------------------------------------------------------------------------
/*!
 * - ファイル: transaction_io.rs
 * - 概要: transaction の Windows 排他、限定 ACL、metadata 検査と置換を包みます
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
 * SACL を読めない場合も変更を拒否します。権限・readonly を変更して通しません。
 * SeSecurityPrivilege は SACL 読取り時の thread token だけで有効化し、直後に解除します
 */
//------------------------------------------------------------------------------

#![allow(unsafe_code)]

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};

use trust_repair_core::sha256_hex;
use windows_sys::Win32::Foundation::{
	ERROR_ALREADY_EXISTS, ERROR_NO_TOKEN, FILETIME, GetLastError, INVALID_HANDLE_VALUE, LocalFree,
	SetLastError,
};
use windows_sys::Win32::Security::Authorization::{
	ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
};
use windows_sys::Win32::Security::{
	AdjustTokenPrivileges, BACKUP_SECURITY_INFORMATION, DACL_SECURITY_INFORMATION,
	GROUP_SECURITY_INFORMATION, GetKernelObjectSecurity, GetTokenInformation, ImpersonateSelf,
	LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, OWNER_SECURITY_INFORMATION,
	PROTECTED_DACL_SECURITY_INFORMATION, RevertToSelf, SE_PRIVILEGE_ENABLED, SECURITY_ATTRIBUTES,
	SecurityImpersonation, SetKernelObjectSecurity, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
	TOKEN_QUERY, TOKEN_USER, TokenUser, UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::{
	BACKUP_DATA, BACKUP_SECURITY_DATA, BackupRead, BackupSeek, CREATE_NEW, CreateDirectoryW,
	CreateFileW, DELETE, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS,
	FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, MoveFileW,
	READ_CONTROL, ReplaceFileW, SetFileAttributesW, SetFileTime, WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::Threading::{
	CreateMutexW, GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};

use crate::snapshot::{FileSafetyError, FileSnapshot, check_path};

/// Windows 境界から返す、固定分類と OS code です
#[derive(Debug)]
pub(crate) struct IoFailure {
	/// SACL/追加 metadata の保持条件に合格しない場合は true
	pub unsupported_metadata: bool,
	/// 排他が既に存在する場合は true
	pub busy: bool,
	/// 直後に保存した Windows code。構造検査時は None
	pub os_code: Option<i32>,
}

impl From<io::Error> for IoFailure {
	//------------------------------------------------------------------------------
	/**
	 * OS 本文を保持せず code を所有します。ファイルや権限は変更しません
	 */
	//------------------------------------------------------------------------------
	fn from(error: io::Error) -> Self {
		Self {
			unsupported_metadata: false,
			busy: false,
			os_code: error.raw_os_error(),
		}
	}
}

/// OS の LocalAlloc の所有領域です。生成時だけ pointer を受け取ります
struct LocalDescriptor(
	/// LocalFree で一度だけ解放する、OS allocator の descriptor
	*mut std::ffi::c_void,
);

impl Drop for LocalDescriptor {
	//------------------------------------------------------------------------------
	/**
	 * OS の専用 allocator で一度だけ解放します
	 */
	//------------------------------------------------------------------------------
	fn drop(&mut self) {
		// SAFETY: SDDL 変換に成功した LocalAlloc の pointer を所有する
		unsafe {
			LocalFree(self.0);
		}
	}
}

/// OS が検査した self-relative descriptor の比較要素です
#[derive(Debug, PartialEq, Eq)]
struct SecurityParts<'a> {
	/// owner SID の byte 列
	owner: &'a [u8],
	/// group SID の byte 列
	group: &'a [u8],
	/// NULL DACL を区別する ACL の byte 列
	dacl: Option<&'a [u8]>,
	/// 親からの継承抑止
	protected: bool,
}

//------------------------------------------------------------------------------
/**
 * 不正な相対 offset を FFI に渡さず検査します。SACL を含む descriptor は拒否します
 *
 * # Returns
 *
 * owner・group・DACL の範囲と保護状態。境界・形式の不整合や SACL があれば `None`
 */
//------------------------------------------------------------------------------
fn parts(bytes: &[u8]) -> Option<SecurityParts<'_>> {
	// descriptor の既知 header が揃う前に、相対 offset や SID を解釈しない
	if bytes.len() < 20 || bytes[0] != 1 {
		return None;
	}
	let control = u16::from_le_bytes(bytes[2..4].try_into().ok()?);
	// 自己相対形式と SACL 不在を要求し、保全未対応の情報を黙って省かない
	if control & 0x8000 == 0 || bytes[12..16] != [0; 4] {
		return None;
	}
	let sid = |offset: usize| -> Option<&[u8]> {
		let start = u32::from_le_bytes(bytes[offset..offset + 4].try_into().ok()?) as usize;
		// SID の参照先を header 外の領域へ限定する
		if start < 20 {
			return None;
		}
		let header = bytes.get(start..start.checked_add(8)?)?;
		// SID の revision と要素数を確認してから、必要な byte 範囲を求める
		if header[0] != 1 || header[1] > 15 {
			return None;
		}
		bytes.get(start..start.checked_add(8 + usize::from(header[1]) * 4)?)
	};
	let offset = u32::from_le_bytes(bytes[16..20].try_into().ok()?) as usize;
	// DACL の不在・存在を区別し、存在する場合は header と ACE を検査する
	let dacl = if offset == 0 {
		None
	} else {
		// 不正な DACL offset や不整合な制御 bit を FFI へ渡さない
		if offset < 20 || control & 4 == 0 {
			return None;
		}
		let header = bytes.get(offset..offset.checked_add(8)?)?;
		let size = usize::from(u16::from_le_bytes(header[2..4].try_into().ok()?));
		// ACL の最小 header より短い宣言を拒否し、範囲外の ACE を解釈しない
		if size < 8 {
			return None;
		}
		let acl = bytes.get(offset..offset.checked_add(size)?)?;
		let count = u16::from_le_bytes(header[4..6].try_into().ok()?);
		let mut cursor = 8_usize;
		// 全 ACE の範囲を先に検査し、OS に不正な内部 pointer を評価させない
		for _ in 0..count {
			let ace = acl.get(cursor..cursor.checked_add(4)?)?;
			let size = usize::from(u16::from_le_bytes(ace[2..4].try_into().ok()?));
			// 保全対象を既知の allow/deny ACE に限定し、複雑な権限を推測して再構築しない
			if size < 16 || !matches!(ace[0], 0 | 1) || ace[1] & !0x1f != 0 {
				return None;
			}
			let full = acl.get(cursor..cursor.checked_add(size)?)?;
			// ACE 内 SID の revision・要素数・宣言長を照合し、余剰や途中欠落を受理しない
			if full[8] != 1 || full[9] > 15 || size != 16 + usize::from(full[9]) * 4 {
				return None;
			}
			cursor = cursor.checked_add(size)?;
			// 全 ACE が宣言済み ACL 領域へ収まった場合だけ、権限の比較材料にする
			if cursor > acl.len() {
				return None;
			}
		}
		Some(acl)
	};
	Some(SecurityParts {
		owner: sid(4)?,
		group: sid(8)?,
		dacl,
		protected: control & 0x1000 != 0,
	})
}

//------------------------------------------------------------------------------
/**
 * schema 内の descriptor を境界検査します。未知の SACL を空として解釈しません
 */
//------------------------------------------------------------------------------
pub(crate) fn valid_security(bytes: &[u8]) -> bool {
	bytes.len() <= 1024 * 1024 && parts(bytes).is_some()
}

//------------------------------------------------------------------------------
/**
 * padding/相対配置の差を除き、owner/group/DACL と継承抑止が一致する場合だけ true
 */
//------------------------------------------------------------------------------
pub(crate) fn same_security(left: &[u8], right: &[u8]) -> bool {
	matches!((parts(left), parts(right)), (Some(left), Some(right)) if left == right)
}

//------------------------------------------------------------------------------
/**
 * Win32 へ渡す終端 NUL path を損失変換せず作ります。上位で NUL/ADS/祖先を検査します
 */
//------------------------------------------------------------------------------
fn wide(path: &Path) -> Vec<u16> {
	path.as_os_str().encode_wide().chain([0]).collect()
}

//------------------------------------------------------------------------------
/**
 * 最後の Windows code を他の API より先に保存します
 */
//------------------------------------------------------------------------------
fn last() -> IoFailure {
	io::Error::last_os_error().into()
}

//------------------------------------------------------------------------------
/**
 * 追加 metadata を安全に扱えない分類を返します。権限を補正しません
 */
//------------------------------------------------------------------------------
fn unsupported() -> IoFailure {
	IoFailure {
		unsupported_metadata: true,
		busy: false,
		os_code: None,
	}
}

//------------------------------------------------------------------------------
/**
 * path検査の実OS失敗を保持し、リンク等の仕様非対応と権限不足を区別します
 */
//------------------------------------------------------------------------------
fn file_failure(error: FileSafetyError) -> IoFailure {
	// 実際の OS 失敗と、link 等の非対応条件を分けて上位へ伝える
	match error {
		FileSafetyError::Io {
			os_code: Some(code),
			..
		} => io::Error::from_raw_os_error(code).into(),
		_ => unsupported(),
	}
}

//------------------------------------------------------------------------------
/**
 * query に必要な整列済み領域を確保し、OS が返した descriptor だけを複製します
 *
 * # Arguments
 *
 * - `file`: query 可能な handle を持つ、呼出し中所有される file
 * - `flags`: 問い合わせる security 情報の Windows API フラグ
 *
 * # Returns
 *
 * OS が返した descriptor を所有する byte 列
 *
 * # Errors
 *
 * 必要長が 20 byte 未満・1 MiB 超過、または OS の問い合わせ失敗
 */
//------------------------------------------------------------------------------
fn descriptor(file: &File, flags: u32) -> Result<Vec<u8>, IoFailure> {
	let mut needed = 0;
	// SAFETY: 所有 file handle と容量照会専用の null を渡す
	unsafe {
		GetKernelObjectSecurity(
			file.as_raw_handle(),
			flags,
			std::ptr::null_mut(),
			0,
			&mut needed,
		);
	}
	// OS が返す必要容量に上限を設け、異常な descriptor 領域を確保しない
	if !(20..=1024 * 1024).contains(&needed) {
		return Err(last());
	}
	let mut memory = vec![0_u32; (needed as usize).div_ceil(4)];
	// SAFETY: 必要 alignment と十分な容量を持つ呼出し中不変の領域
	if unsafe {
		GetKernelObjectSecurity(
			file.as_raw_handle(),
			flags,
			memory.as_mut_ptr().cast(),
			(memory.len() * 4) as u32,
			&mut needed,
		)
	} == 0
	{
		return Err(last());
	}
	Ok(memory
		.into_iter()
		.flat_map(u32::to_ne_bytes)
		.take(needed as usize)
		.collect())
}

//------------------------------------------------------------------------------
/**
 * 現 process の SID を SDDL 用文字列として取得します。秘密や環境を読みません
 *
 * # Returns
 *
 * SDDL へ埋め込める現 process 利用者の SID。token と OS 割当て文字列は本関数で解放します
 *
 * # Errors
 *
 * token・必要長・情報・SID 文字列の取得、または UTF-16 の復号に失敗した場合
 */
//------------------------------------------------------------------------------
fn current_sid() -> Result<String, IoFailure> {
	let mut raw = std::ptr::null_mut();
	// SAFETY: 現 process の pseudo handle と token 出力を渡す
	if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
		return Err(last());
	}
	// SAFETY: 成功した token を一度だけ所有する
	let token = unsafe { OwnedHandle::from_raw_handle(raw) };
	let mut needed = 0;
	// SAFETY: 最初は必要容量だけを照会する
	unsafe {
		GetTokenInformation(
			token.as_raw_handle(),
			TokenUser,
			std::ptr::null_mut(),
			0,
			&mut needed,
		);
	}
	// token 情報の取得容量を制限し、不正な長さを allocator へ渡さない
	if needed == 0 || needed > 64 * 1024 {
		return Err(last());
	}
	let mut memory = vec![0_usize; (needed as usize).div_ceil(size_of::<usize>())];
	// SAFETY: TOKEN_USER に十分な alignment/容量を渡す
	if unsafe {
		GetTokenInformation(
			token.as_raw_handle(),
			TokenUser,
			memory.as_mut_ptr().cast(),
			(memory.len() * size_of::<usize>()) as u32,
			&mut needed,
		)
	} == 0
	{
		return Err(last());
	}
	// SAFETY: 成功した TokenUser の先頭は TOKEN_USER で、内部 SID も領域内に有効
	let user = unsafe { &*memory.as_ptr().cast::<TOKEN_USER>() };
	let mut text = std::ptr::null_mut();
	// SAFETY: 有効な SID と OS が割当てる文字列の出力を渡す
	if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 {
		return Err(last());
	}
	let owned = LocalDescriptor(text.cast());
	let mut length = 0;
	// SAFETY: API の成功した SID 文字列は終端 NUL を持つ
	while unsafe { *text.add(length) } != 0 {
		length += 1;
	}
	// SAFETY: 終端を走査した同じ割当て領域からだけ読む
	let result = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })
		.map_err(|_| unsupported())?;
	drop(owned);
	Ok(result)
}

//------------------------------------------------------------------------------
/**
 * 本人と Administrators だけを許可する、継承を止めた新規 object の ACL を作ります
 *
 * # Returns
 *
 * LocalFree で解放する owner/group/DACL の所有値
 *
 * # Errors
 *
 * 現利用者 SID の取得、または SDDL 変換の失敗
 */
//------------------------------------------------------------------------------
fn restricted_descriptor() -> Result<LocalDescriptor, IoFailure> {
	let sid = current_sid()?;
	let sddl: Vec<u16> = format!("O:{sid}G:{sid}D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;BA)")
		.encode_utf16()
		.chain([0])
		.collect();
	let mut raw = std::ptr::null_mut();
	// SAFETY: 終端 NUL SDDL と OS 所有領域の出力を渡す
	if unsafe {
		ConvertStringSecurityDescriptorToSecurityDescriptorW(
			sddl.as_ptr(),
			1,
			&mut raw,
			std::ptr::null_mut(),
		)
	} == 0
	{
		return Err(last());
	}
	Ok(LocalDescriptor(raw))
}

//------------------------------------------------------------------------------
/**
 * 既存 directory の owner と限定 DACL を照合します。既存の権限は変更しません
 *
 * # Errors
 *
 * パス・directory・owner・限定 DACL・継承保護を確認できない場合。
 * 既存の権限を広げて再試行しません
 */
//------------------------------------------------------------------------------
pub(crate) fn verify_private_directory(path: &Path) -> Result<(), IoFailure> {
	check_path(path).map_err(file_failure)?;
	let file = OpenOptions::new()
		.access_mode(READ_CONTROL)
		.share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
		.custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
		.open(path)?;
	// 通常 file を専用 directory として採用しない
	if !file.metadata()?.is_dir() {
		return Err(unsupported());
	}
	let actual = descriptor(
		&file,
		OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
	)?;
	let expected = restricted_descriptor()?;
	// SAFETY: SDDL 変換が返した descriptor の既知 header を参照する
	let length =
		unsafe { windows_sys::Win32::Security::GetSecurityDescriptorLength(expected.0) } as usize;
	// SAFETY: OS が返した同じ descriptor の長さ以内だけ参照する
	let bytes = unsafe { std::slice::from_raw_parts(expected.0.cast::<u8>(), length) };
	// 実際と期待の descriptor を同じ境界検査へ通してから権限を比較する
	let (Some(actual), Some(expected)) = (parts(&actual), parts(bytes)) else {
		return Err(unsupported());
	};
	// 本人 owner・限定 DACL・継承保護が揃う root だけを採用し、既存 ACL を緩めない
	if actual.owner != expected.owner || actual.dacl != expected.dacl || !actual.protected {
		return Err(unsupported());
	}
	Ok(())
}

//------------------------------------------------------------------------------
/**
 * 新規 directory を限定 ACL で一度だけ作ります。既存 object を上書きしません
 *
 * # Errors
 *
 * 親・descriptor の検査、directory 作成、作成後の限定 ACL の照合に失敗した場合。
 * 作成後の検査が失敗しても、作成物を自動削除しません
 */
//------------------------------------------------------------------------------
pub(crate) fn create_private_directory(path: &Path) -> Result<(), IoFailure> {
	let parent = path.parent().ok_or_else(unsupported)?;
	check_path(parent).map_err(file_failure)?;
	let sd = restricted_descriptor()?;
	let attributes = SECURITY_ATTRIBUTES {
		nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
		lpSecurityDescriptor: sd.0,
		bInheritHandle: 0,
	};
	let path_wide = wide(path);
	// SAFETY: 初期化済み security attributes と終端 NUL path を渡す
	if unsafe { CreateDirectoryW(path_wide.as_ptr(), &attributes) } == 0 {
		return Err(last());
	}
	verify_private_directory(path)
}

//------------------------------------------------------------------------------
/**
 * 同一 path の別 instance を、全 session 共通の生存期間 lock で抑止します
 *
 * # Arguments
 *
 * - `path`: 同じ正規実体について大文字小文字を揃えてハッシュ化するパス
 *
 * # Returns
 *
 * 生存期間で排他を保持する named mutex の所有 handle。drop で閉じます
 *
 * # Errors
 *
 * パスの文字列表現・descriptor・mutex 作成の失敗、または既存 mutex があれば busy
 */
//------------------------------------------------------------------------------
pub(crate) fn target_lock(path: &Path) -> Result<OwnedHandle, IoFailure> {
	let text = path.to_str().ok_or_else(unsupported)?.to_lowercase();
	let name: Vec<u16> = format!(
		"Global\\EnterSystem.JavaTrustRepair.{}",
		sha256_hex(text.as_bytes())
	)
	.encode_utf16()
	.chain([0])
	.collect();
	let sd = restricted_descriptor()?;
	let attrs = SECURITY_ATTRIBUTES {
		nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
		lpSecurityDescriptor: sd.0,
		bInheritHandle: 0,
	};
	// SAFETY: 名前と security descriptor は呼出し中有効で、所有権取得はしない
	let raw = unsafe { CreateMutexW(&attrs, 0, name.as_ptr()) };
	// SAFETY: 成否直後の code を他の API 前に取得する
	let code = unsafe { GetLastError() };
	// mutex の作成失敗時は所有化せず、取得した OS の失敗を返す
	if raw.is_null() {
		return Err(last());
	}
	// SAFETY: 作成/取得に成功した handle を一度だけ所有する
	let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
	// 既存 mutex がある場合は handle を解放して busy とし、同一 thread の再入も拒否する
	if code == ERROR_ALREADY_EXISTS {
		return Err(IoFailure {
			busy: true,
			unsupported_metadata: false,
			os_code: Some(code as i32),
		});
	}
	Ok(handle)
}

//------------------------------------------------------------------------------
/**
 * 書込みと置換の権限を要求し、内容は変えずに通常 write を抑止します
 *
 * # Returns
 *
 * 通常 write を共有しない所有 file。呼出し側が確定直前まで保持し、drop で閉じます
 *
 * # Errors
 *
 * write/delete/WRITE_DAC の権限確認、または保持用 handle の取得失敗
 */
//------------------------------------------------------------------------------
pub(crate) fn write_guard(path: &Path) -> Result<File, IoFailure> {
	// Java 11 の FileInputStream は FILE_SHARE_DELETE を指定しないため、DELETE access の
	// probe は保持せず、通常 write を拒否する handle だけを一覧取得中も保持する
	let probe = OpenOptions::new()
		.access_mode(0x4000_0000 | READ_CONTROL | DELETE | WRITE_DAC)
		.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
		.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
		.open(path)?;
	drop(probe);
	Ok(OpenOptions::new()
		.access_mode(0xc000_0000 | READ_CONTROL)
		.share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
		.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
		.open(path)?)
}

/// SACL 読取りだけのために生成した thread impersonation の所有者です
struct ReadSecurityToken;

impl ReadSecurityToken {
	//------------------------------------------------------------------------------
	/**
	 * 既存 thread token を上書きせず、利用可能な SACL 読取り特権だけを一時有効化します
	 *
	 * # Returns
	 *
	 * 現 thread だけの impersonation を所有する guard。元の thread token は変更しません
	 *
	 * # Errors
	 *
	 * 既存 thread token の存在、token・特権の取得、有効化の失敗。
	 * impersonation 開始後の失敗は guard が解除してから返します
	 *
	 * # Notes
	 *
	 * guard は生成した thread で破棄します。RevertToSelf に失敗した場合は abort します
	 */
	//------------------------------------------------------------------------------
	fn begin() -> Result<Self, IoFailure> {
		let mut existing = std::ptr::null_mut();
		// SAFETY: 現 thread の token の存在だけを検査する
		if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut existing) } != 0 {
			// SAFETY: 成功した所有 handle を閉じる
			drop(unsafe { OwnedHandle::from_raw_handle(existing) });
			return Err(unsupported());
		}
		// SAFETY: 直前の OpenThreadToken に対応する code
		if unsafe { GetLastError() } != ERROR_NO_TOKEN {
			return Err(last());
		}
		// SAFETY: 現 thread の process identity のみを複製する
		if unsafe { ImpersonateSelf(SecurityImpersonation) } == 0 {
			return Err(last());
		}
		let guard = Self;
		let mut raw = std::ptr::null_mut();
		// SAFETY: 複製した現 thread token を取得する
		if unsafe {
			OpenThreadToken(
				GetCurrentThread(),
				TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
				1,
				&mut raw,
			)
		} == 0
		{
			return Err(last());
		}
		// SAFETY: 取得に成功した token を所有する
		let token = unsafe { OwnedHandle::from_raw_handle(raw) };
		let name: Vec<u16> = "SeSecurityPrivilege".encode_utf16().chain([0]).collect();
		let mut luid = windows_sys::Win32::Foundation::LUID::default();
		// SAFETY: 固定名と正しい LUID 出力を渡す
		if unsafe { LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut luid) } == 0 {
			return Err(last());
		}
		let privileges = TOKEN_PRIVILEGES {
			PrivilegeCount: 1,
			Privileges: [LUID_AND_ATTRIBUTES {
				Luid: luid,
				Attributes: SE_PRIVILEGE_ENABLED,
			}],
		};
		// SAFETY: 一つの特権だけを現 thread token で有効化し、成功時の未割当ても検査する
		let success = unsafe {
			SetLastError(0);
			AdjustTokenPrivileges(
				token.as_raw_handle(),
				0,
				&privileges,
				0,
				std::ptr::null_mut(),
				std::ptr::null_mut(),
			)
		};
		// SAFETY: AdjustTokenPrivileges 直後の code
		let code = unsafe { GetLastError() };
		// API 成功でも特権未割当てを検査し、SACL を読めると推測しない
		if success == 0 || code != 0 {
			return Err(
				// API が code を返さない失敗にも権限不足の code を補い、実行失敗を失わない
				io::Error::from_raw_os_error(if code == 0 { 1314 } else { code as i32 }).into(),
			);
		}
		Ok(guard)
	}
}

impl Drop for ReadSecurityToken {
	//------------------------------------------------------------------------------
	/**
	 * thread の一時特権を必ず解除します。解除不能なら特権を残して継続しません
	 */
	//------------------------------------------------------------------------------
	fn drop(&mut self) {
		// SAFETY: begin がこの thread で生成した impersonation だけを解除する
		if unsafe { RevertToSelf() } == 0 {
			std::process::abort();
		}
	}
}

//------------------------------------------------------------------------------
/**
 * SACL と追加 backup stream が空であることを検査します。取得不能は明示的拒否です
 *
 * # Errors
 *
 * 限定的な読取り特権の取得、descriptor の取得、非空 SACL、
 * 追加 stream の列挙失敗、または保全未対応の stream が存在する場合
 */
//------------------------------------------------------------------------------
pub(crate) fn check_supported_metadata(path: &Path) -> Result<(), IoFailure> {
	let _token = ReadSecurityToken::begin()?;
	let file = OpenOptions::new()
		.access_mode(0x8000_0000 | READ_CONTROL | 0x0100_0000)
		.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
		.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
		.open(path)?;
	let full = descriptor(&file, BACKUP_SECURITY_INFORMATION)?;
	// SACL が存在する対象は、監査情報を失う置換へ進めない
	if full.len() < 20 || full[12..16] != [0; 4] {
		return Err(unsupported());
	}
	check_backup_streams(&file)
}

//------------------------------------------------------------------------------
/**
 * BackupRead の header を完全列挙し、EA/object-ID 等の保全未対応 stream を拒否します
 *
 * # Errors
 *
 * BackupRead の読込み・header・長さ・seek の失敗、列挙上限、
 * または通常データ・security 以外の stream や stream 名を検出した場合
 *
 * # Notes
 *
 * BackupRead の context は成否を問わず abort 指定で解放します
 */
//------------------------------------------------------------------------------
fn check_backup_streams(file: &File) -> Result<(), IoFailure> {
	let mut context = std::ptr::null_mut();
	let result = (|| {
		// ストアサイズによらず、各 header と seek だけで追加 metadata を検査する
		for _ in 0..64 {
			let mut header = [0_u8; 20];
			let mut read = 0;
			// SAFETY: BackupRead の packed header 20 byte を byte 領域へ取得する
			if unsafe {
				BackupRead(
					file.as_raw_handle(),
					header.as_mut_ptr(),
					20,
					&mut read,
					0,
					0,
					&mut context,
				)
			} == 0
			{
				return Err(last());
			}
			// 列挙終端で検査を成功終了し、context の解放処理へ進む
			if read == 0 {
				return Ok(());
			}
			// 途中までの stream header を完全な header として解釈しない
			if read != 20 {
				return Err(unsupported());
			}
			let id = u32::from_le_bytes(header[..4].try_into().map_err(|_| unsupported())?);
			let size = u64::from_le_bytes(header[8..16].try_into().map_err(|_| unsupported())?);
			// 通常データと security 以外や named stream は、保全未対応として拒否する
			if !matches!(id, BACKUP_DATA | BACKUP_SECURITY_DATA) || header[16..20] != [0; 4] {
				return Err(unsupported());
			}
			let mut low = 0;
			let mut high = 0;
			// SAFETY: 同じ context の payload だけを範囲付きで飛ばす
			if unsafe {
				BackupSeek(
					file.as_raw_handle(),
					size as u32,
					(size >> 32) as u32,
					&mut low,
					&mut high,
					&mut context,
				)
			} == 0
			{
				return Err(last());
			}
			// 指定した payload を全て飛ばせたことを確認してから、次の header を読む
			if (u64::from(high) << 32) | u64::from(low) != size {
				return Err(unsupported());
			}
		}
		Err(unsupported())
	})();
	let mut read = 0;
	// SAFETY: 成功/失敗の全経路で BackupRead の context を解放する abort 呼出し
	if unsafe {
		BackupRead(
			file.as_raw_handle(),
			std::ptr::null_mut(),
			0,
			&mut read,
			1,
			0,
			&mut context,
		)
	} == 0
	{
		return Err(last());
	}
	result
}

//------------------------------------------------------------------------------
/**
 * 新規 stage に元 descriptor で内容を保存し、元作成時刻/属性を設定します
 *
 * # Arguments
 *
 * - `path`: create_new で作成する、元対象と異なる新規 stage
 * - `bytes`: stage へ全体を書き込む内容
 * - `original`: owner/group/DACL・作成日時・属性の保持元
 * - `restore_mtime`: `true` の場合だけ、元の更新日時も設定します
 *
 * # Errors
 *
 * descriptor の検査、作成・書込み・flush/sync・日時・属性の設定失敗。
 * 途中 stage は削除せず、元対象には書き込みません
 */
//------------------------------------------------------------------------------
pub(crate) fn create_stage(
	path: &Path,
	bytes: &[u8],
	original: &FileSnapshot,
	restore_mtime: bool,
) -> Result<(), IoFailure> {
	// 保存 descriptor を境界検査し、未知の権限情報を作成 API へ渡さない
	if !valid_security(original.security_descriptor()) {
		return Err(unsupported());
	}
	let mut aligned = vec![0_u32; original.security_descriptor().len().div_ceil(4)];
	// 不正な alignment の Vec<u8> を descriptor として渡さない
	for (index, chunk) in original.security_descriptor().chunks(4).enumerate() {
		let mut word = [0_u8; 4];
		word[..chunk.len()].copy_from_slice(chunk);
		aligned[index] = u32::from_ne_bytes(word);
	}
	let attrs = SECURITY_ATTRIBUTES {
		nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
		lpSecurityDescriptor: aligned.as_mut_ptr().cast(),
		bInheritHandle: 0,
	};
	let name = wide(path);
	// SAFETY: 検証した相対 SD と既存を上書きしない CREATE_NEW を渡す
	let raw = unsafe {
		CreateFileW(
			name.as_ptr(),
			0xc000_0000 | READ_CONTROL | WRITE_DAC | WRITE_OWNER | DELETE,
			FILE_SHARE_READ,
			&attrs,
			CREATE_NEW,
			FILE_ATTRIBUTE_NORMAL,
			std::ptr::null_mut(),
		)
	};
	// stage の新規作成に成功した handle だけを所有し、既存対象を再利用しない
	if raw == INVALID_HANDLE_VALUE {
		return Err(last());
	}
	// SAFETY: 新規作成に成功した file handle を一度だけ所有する
	let mut file = unsafe { File::from_raw_handle(raw) };
	file.write_all(bytes)?;
	file.sync_all()?;
	let creation = time(original.creation_time());
	let modified = time(original.last_write_time());
	// SAFETY: 所有 file と正しい FILETIME、未設定 access time の null を渡す
	if unsafe {
		SetFileTime(
			file.as_raw_handle(),
			&creation,
			std::ptr::null(),
			// 復元 stage の場合だけ元更新日時を設定し、適用 stage では内容変更の日時を維持する
			if restore_mtime {
				&modified
			} else {
				std::ptr::null()
			},
		)
	} == 0
	{
		return Err(last());
	}
	file.sync_all()?;
	drop(file);
	// SAFETY: 元の許可済み属性だけを新規 stage に適用し、readonly 等の解除は行わない
	if unsafe { SetFileAttributesW(name.as_ptr(), original.attributes()) } == 0 {
		return Err(last());
	}
	#[cfg(feature = "internal-qa")]
	crate::qa_checkpoint("stage-created", None);
	Ok(())
}

//------------------------------------------------------------------------------
/**
 * keytool が stage を書いた後に、元の保持対象属性と作成時刻を再設定します
 *
 * # Errors
 *
 * stage の取得、元作成日時または保持対象属性の設定失敗
 */
//------------------------------------------------------------------------------
pub(crate) fn finish_stage(path: &Path, original: &FileSnapshot) -> Result<(), IoFailure> {
	let file = OpenOptions::new()
		.access_mode(0x4000_0000)
		.share_mode(FILE_SHARE_READ)
		.open(path)?;
	let creation = time(original.creation_time());
	// SAFETY: 新規 stage の作成日時だけを元へ合わせる
	if unsafe {
		SetFileTime(
			file.as_raw_handle(),
			&creation,
			std::ptr::null(),
			std::ptr::null(),
		)
	} == 0
	{
		return Err(last());
	}
	file.sync_all()?;
	drop(file);
	let name = wide(path);
	// SAFETY: 元の保持対象属性を stage にだけ適用する
	if unsafe { SetFileAttributesW(name.as_ptr(), original.attributes()) } == 0 {
		return Err(last());
	}
	Ok(())
}

//------------------------------------------------------------------------------
/**
 * 置換の継承再計算で変わり得る DACL を、保存した元 ACL と保護状態へ正確に戻します。
 * 呼出し側は直前に stage の hash/実体 ID が target にあることを確認します。
 * 任意の権限追加は行わず、WRITE_DAC がなければ明示的に失敗します
 *
 * # Arguments
 *
 * - `path`: 呼出し側が stage の実体・hash と照合済みの置換先
 * - `original`: 元 DACL と継承保護の保存値
 *
 * # Errors
 *
 * 保存 descriptor の検査、WRITE_DAC handle の取得、または DACL 設定の失敗
 */
//------------------------------------------------------------------------------
pub(crate) fn preserve_dacl(path: &Path, original: &FileSnapshot) -> Result<(), IoFailure> {
	// 保存した DACL の範囲と保護状態を検査してから、置換先へ設定する
	let Some(security) = parts(original.security_descriptor()) else {
		return Err(unsupported());
	};
	let mut aligned = vec![0_u32; original.security_descriptor().len().div_ceil(4)];
	// 元 descriptor の byte 列を整列済み領域へ複写し、FFI に必要な alignment を保つ
	for (index, chunk) in original.security_descriptor().chunks(4).enumerate() {
		let mut word = [0_u8; 4];
		word[..chunk.len()].copy_from_slice(chunk);
		aligned[index] = u32::from_ne_bytes(word);
	}
	let file = OpenOptions::new()
		.access_mode(0x4000_0000 | WRITE_DAC | READ_CONTROL)
		.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
		.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
		.open(path)?;
	let flags = DACL_SECURITY_INFORMATION
		// 保存時の保護状態に応じた flag を使い、任意に継承方針を変えない
		| if security.protected {
			PROTECTED_DACL_SECURITY_INFORMATION
		} else {
			UNPROTECTED_DACL_SECURITY_INFORMATION
		};
	// SAFETY: 境界検証済みの整列 SD の DACL と保存した保護状態だけを設定する
	if unsafe { SetKernelObjectSecurity(file.as_raw_handle(), flags, aligned.as_mut_ptr().cast()) }
		== 0
	{
		return Err(last());
	}
	file.sync_all()?;
	Ok(())
}

//------------------------------------------------------------------------------
/**
 * merge エラー無視 flag を使わず同 volume の recovery copy 付きで置換します
 *
 * # Arguments
 *
 * - `target`: 既存の置換先。呼出し側が直前に実体を照合します
 * - `stage`: 同 volume に準備した置換元
 * - `recovery`: 置換される実体の新規退避先
 *
 * # Errors
 *
 * ReplaceFileW の失敗。部分状態の照合・復旧は呼出し側が行い、ここでは証拠を削除しません
 */
//------------------------------------------------------------------------------
pub(crate) fn replace(target: &Path, stage: &Path, recovery: &Path) -> Result<(), IoFailure> {
	// 既存の recovery copy を上書きせず、先行する証拠を保全する
	if fs::symlink_metadata(recovery).is_ok() {
		return Err(unsupported());
	}
	#[cfg(feature = "internal-qa")]
	crate::qa_checkpoint("before-replace", None);
	let target = wide(target);
	let stage = wide(stage);
	let recovery = wide(recovery);
	// SAFETY: 上位が全 path/同 volume/新規 recovery を検査し、flags=0 で ACL 保持失敗を伝播する
	if unsafe {
		ReplaceFileW(
			target.as_ptr(),
			stage.as_ptr(),
			recovery.as_ptr(),
			0,
			std::ptr::null(),
			std::ptr::null(),
		)
	} == 0
	{
		return Err(last());
	}
	#[cfg(feature = "internal-qa")]
	crate::qa_checkpoint("after-replace", None);
	Ok(())
}

//------------------------------------------------------------------------------
/**
 * 検証した欠落先だけへ stage を移動します。既存 path を上書きする flag はありません
 *
 * # Arguments
 *
 * - `stage`: 同 volume の検証済み復旧元
 * - `target`: 呼出し側が根拠付きで欠落と判定した復旧先
 *
 * # Errors
 *
 * MoveFileW の失敗。既存対象を上書きしません
 */
//------------------------------------------------------------------------------
pub(crate) fn move_to_missing(stage: &Path, target: &Path) -> Result<(), IoFailure> {
	let stage = wide(stage);
	let target = wide(target);
	// SAFETY: 同 volume の stage を MOVEFILE_REPLACE_EXISTING なしで移動する
	if unsafe { MoveFileW(stage.as_ptr(), target.as_ptr()) } == 0 {
		return Err(last());
	}
	Ok(())
}

//------------------------------------------------------------------------------
/**
 * FILETIME の lossless な分解を行います
 */
//------------------------------------------------------------------------------
fn time(value: u64) -> FILETIME {
	FILETIME {
		dwLowDateTime: value as u32,
		dwHighDateTime: (value >> 32) as u32,
	}
}

//------------------------------------------------------------------------------
/**
 * 不足する通常の親 directory を作り、最終 backup root だけを限定 ACL で固定します
 *
 * # Returns
 *
 * 通常の親と限定 ACL を確認した、最終 root の canonical path
 *
 * # Errors
 *
 * 親の作成・パス検査、最終 root の作成、または既存 root の限定 ACL 検査の失敗
 */
//------------------------------------------------------------------------------
pub(crate) fn prepare_root(path: &Path) -> Result<PathBuf, IoFailure> {
	let parent = path.parent().ok_or_else(unsupported)?;
	let mut existing = parent;
	// 親を作る前に既存祖先を検査し、UNC/link の先へ先に新規 directory を作らない
	loop {
		// 既存の祖先へ達したら探索を終え、不在以外の取得失敗は親の作成前に返す
		match fs::symlink_metadata(existing) {
			Ok(_) => break,
			Err(error) if error.kind() == io::ErrorKind::NotFound => {
				existing = existing.parent().ok_or_else(unsupported)?
			}
			Err(error) => return Err(error.into()),
		}
	}
	check_path(existing).map_err(file_failure)?;
	fs::create_dir_all(parent)?;
	check_path(parent).map_err(file_failure)?;
	// 最終 root がない場合だけ限定 ACL で新規作成し、既存 root は検証へ回す
	if !path.exists() {
		create_private_directory(path)?;
	}
	verify_private_directory(path)?;
	Ok(fs::canonicalize(path)?)
}
