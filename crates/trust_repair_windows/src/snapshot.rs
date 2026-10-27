//------------------------------------------------------------------------------
/*!
 * - ファイル: snapshot.rs
 * - 概要: ローカル NTFS の通常ファイルを読み取り、実体と metadata の snapshot を取得します。
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
 * SACL、書換え権限、置換後の metadata 保持は保証しません。transaction で追加検証します。
 * 同権限の悪意ある置換への防御境界ではありません。診断中の同時変更は停止してください。
 */
//------------------------------------------------------------------------------

#![allow(unsafe_code)]

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, PathBuf, Prefix};

use trust_repair_core::sha256_hex;
use windows_sys::Win32::Foundation::{ERROR_HANDLE_EOF, ERROR_NO_MORE_FILES, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::{
	DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, GetKernelObjectSecurity,
	OWNER_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::{
	BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_DIRECTORY,
	FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED,
	FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_SYSTEM, FILE_FLAG_OPEN_REPARSE_POINT,
	FILE_ID_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FileIdInfo, FindClose,
	FindFirstStreamW, FindNextStreamW, GetDriveTypeW, GetFileInformationByHandle,
	GetFileInformationByHandleEx, GetVolumeInformationByHandleW, READ_CONTROL,
	WIN32_FIND_STREAM_DATA,
};

// snapshot は必ず READ_CONTROL を要求し、権限不足を空 metadata として扱わない
const GENERIC_READ: u32 = 0x8000_0000;
// Windows の固定ローカルディスク。UNC/redirector/removable はここでは変更対象外
const DRIVE_FIXED: u32 = 3;

/// ファイルの変更可否を確認できない理由です。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileSafetyError {
	/// 通常の絶対 DOS drive path でない、または ADS/親参照等を含みます。
	UnsupportedPath,
	/// 末端または祖先に reparse point があります。
	ReparsePoint,
	/// ローカル固定 NTFS volume ではありません。
	NotLocalNtfs,
	/// 一つの通常ファイルではありません。
	NotRegularFile,
	/// 複数 hard link があります。
	MultipleLinks,
	/// 読み取り専用/EFS/圧縮/sparse 等、未対応属性があります。
	UnsupportedAttributes {
		/// 検出した Windows 属性 bit。
		attributes: u32,
	},
	/// 通常でない named stream があります。
	NamedStreams,
	/// 入力容量上限を超えました。
	TooLarge,
	/// 読み取り中に実体/metadata/内容が変わりました。
	Changed,
	/// 読み取りまたは Win32 情報取得に失敗しました。
	Io {
		/// 固定された工程名。
		operation: &'static str,
		/// Windows のエラーコード。
		os_code: Option<i32>,
	},
}

impl std::fmt::Display for FileSafetyError {
	//------------------------------------------------------------------------------
	/**
	 * 診断用の構造化理由を表示します。GUI は variant から日英文言を選択します。
	 *
	 * # Returns
	 *
	 * 出力先の書込みに成功すれば `Ok(())`。
	 *
	 * # Errors
	 *
	 * 出力先の `fmt::Error` を伝播します。途中までの出力は取り消しません。
	 */
	//------------------------------------------------------------------------------
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(formatter, "ファイル安全性検査の失敗: {self:?}")
	}
}

impl std::error::Error for FileSafetyError {}

/// Windows の 128 bit file ID と volume ID で識別する一つの実体です。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
	/// FILE_ID_INFO の volume serial number。
	pub volume_serial: u64,
	/// volume 内での 128 bit ID。
	pub file_id: [u8; 16],
}

/// 後続の再照合に必要な、読み取りで得られた metadata です。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileSnapshot {
	/// OS が正規化した実体 path。識別に損失変換を使いません。
	canonical_path: PathBuf,
	/// volume と file ID。
	identity: FileIdentity,
	/// 読み取った全 byte 列の SHA-256。
	sha256: String,
	/// ファイル長（byte）。
	length: u64,
	/// 保持対象の Windows 属性。
	attributes: u32,
	/// 作成日時（1601-01-01 から 100ns 単位）。
	creation_time: u64,
	/// 更新日時（同単位）。読み取りで変わる access time は比較しません。
	last_write_time: u64,
	/// OWNER/GROUP/DACL の self-relative security descriptor。SACL は含みません。
	security_descriptor: Vec<u8>,
}

impl FileSnapshot {
	//------------------------------------------------------------------------------
	/**
	 * 同 volume 置換後の検査に限り、stage の検証済み snapshot の path を付け替えます。
	 *
	 * # Arguments
	 *
	 * - `path`: 同 volume の置換後に照合する実パス。
	 *
	 * # Returns
	 *
	 * hash・実体 ID・metadata を保持し、パスだけを更新した snapshot。
	 */
	//------------------------------------------------------------------------------
	pub(crate) fn at_path(mut self, path: PathBuf) -> Self {
		self.canonical_path = path;
		self
	}

	//------------------------------------------------------------------------------
	/**
	 * 正規化した通常ファイルの path を返します。
	 */
	//------------------------------------------------------------------------------
	pub fn canonical_path(&self) -> &Path {
		&self.canonical_path
	}

	//------------------------------------------------------------------------------
	/**
	 * 同一実体の重複統合と再照合に必要な ID を返します。
	 */
	//------------------------------------------------------------------------------
	pub fn identity(&self) -> FileIdentity {
		self.identity
	}

	//------------------------------------------------------------------------------
	/**
	 * 全 byte の SHA-256 を返します。
	 */
	//------------------------------------------------------------------------------
	pub fn sha256(&self) -> &str {
		&self.sha256
	}

	//------------------------------------------------------------------------------
	/**
	 * 元の byte 長を返します。
	 */
	//------------------------------------------------------------------------------
	pub fn length(&self) -> u64 {
		self.length
	}

	//------------------------------------------------------------------------------
	/**
	 * 保存と置換後の検証に必要な属性 bit を返します。
	 */
	//------------------------------------------------------------------------------
	pub fn attributes(&self) -> u32 {
		self.attributes
	}

	//------------------------------------------------------------------------------
	/**
	 * 作成日時の Windows FILETIME 値を返します。
	 */
	//------------------------------------------------------------------------------
	pub fn creation_time(&self) -> u64 {
		self.creation_time
	}

	//------------------------------------------------------------------------------
	/**
	 * 内容更新の検出に使う更新日時の FILETIME 値を返します。
	 */
	//------------------------------------------------------------------------------
	pub fn last_write_time(&self) -> u64 {
		self.last_write_time
	}

	//------------------------------------------------------------------------------
	/**
	 * owner/group/DACL の元 descriptor を返します。SACL 保持を保証する値ではありません。
	 */
	//------------------------------------------------------------------------------
	pub fn security_descriptor(&self) -> &[u8] {
		&self.security_descriptor
	}

	//------------------------------------------------------------------------------
	/**
	 * path を再度 read-only で開き、hash/実体/属性/owner/group/DACL/日時を再照合します。
	 * 不一致は [`FileSafetyError::Changed`]、取得不能は元の検査失敗を返します。
	 * lock や atomic compare-and-swap の代わりではありません。
	 *
	 * # Arguments
	 *
	 * - `max_bytes`: 再取得を許可する最大ファイル長（byte）。
	 *
	 * # Errors
	 *
	 * 保存済みの hash・実体・metadata と異なれば `Changed`。
	 * 再取得の安全性検査や I/O の失敗は、その理由を返します。
	 */
	//------------------------------------------------------------------------------
	pub fn revalidate(&self, max_bytes: usize) -> Result<(), FileSafetyError> {
		let (current, _) = read_snapshot(&self.canonical_path, max_bytes)?;
		// 内容だけでなく実体と metadata の差も変更として拒否する
		if current != *self {
			return Err(FileSafetyError::Changed);
		}
		Ok(())
	}
}

//------------------------------------------------------------------------------
/**
 * ファイルを一切書き換えず、安全な実体と全内容を一組にして返します。
 * 診断前後に同じ関数で照合してください。32 MiB を超す executable は別上限を指定できます。
 *
 * # Arguments
 *
 * - `path`: 全祖先も検査する、ローカルの絶対ファイルパス。
 * - `max_bytes`: 全読込みを許可する最大 byte 数。
 *
 * # Returns
 *
 * 同じファイルハンドルから検証した snapshot と全 byte 列。両方の所有権を返します。
 *
 * # Errors
 *
 * 通常の単一 hard link/既知属性/ローカル NTFS/既知 stream/完全 metadata のいずれかを
 * 確認できない場合は失敗します。失敗後も元ファイルと権限を変更しません。
 */
//------------------------------------------------------------------------------
pub fn read_snapshot(
	path: &Path,
	max_bytes: usize,
) -> Result<(FileSnapshot, Vec<u8>), FileSafetyError> {
	check_path(path)?;
	let canonical_path =
		fs::canonicalize(path).map_err(|error| io_error("canonicalize", &error))?;
	check_path(&canonical_path)?;
	let mut file = OpenOptions::new()
		.access_mode(GENERIC_READ | READ_CONTROL)
		.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
		.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
		.open(&canonical_path)
		.map_err(|error| io_error("open_read", &error))?;
	let before = file_information(&file)?;
	// 複数 hard link の実体は一パスの変更で影響範囲を限定できないため拒否する
	if before.nNumberOfLinks != 1 {
		return Err(FileSafetyError::MultipleLinks);
	}
	let attrs = before.dwFileAttributes;
	// directory を通常の保存対象として読み込まない
	if attrs & FILE_ATTRIBUTE_DIRECTORY != 0 {
		return Err(FileSafetyError::NotRegularFile);
	}
	let allowed = FILE_ATTRIBUTE_ARCHIVE
		| FILE_ATTRIBUTE_NORMAL
		| FILE_ATTRIBUTE_HIDDEN
		| FILE_ATTRIBUTE_SYSTEM
		| FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
	// 保持を保証していない属性を、既知属性へ黙って削減しない
	if attrs & !allowed != 0 {
		return Err(FileSafetyError::UnsupportedAttributes { attributes: attrs });
	}
	let length = (u64::from(before.nFileSizeHigh) << 32) | u64::from(before.nFileSizeLow);
	// 全読込み前に長さを制限し、巨大ファイルを buffer へ取り込まない
	if length > max_bytes as u64 {
		return Err(FileSafetyError::TooLarge);
	}
	let identity = file_identity(&file)?;
	check_volume(&file)?;
	check_streams(&canonical_path)?;
	let security_descriptor = security(&file)?;
	let mut bytes = Vec::with_capacity(length as usize);
	(&mut file)
		.take(max_bytes as u64 + 1)
		.read_to_end(&mut bytes)
		.map_err(|error| io_error("read", &error))?;
	let after = file_information(&file)?;
	// 読込み中の内容・実体・metadata・path の変化を検出し、混在した snapshot を返さない
	if bytes.len() as u64 != length
		|| length > max_bytes as u64
		|| !same_information(&before, &after)
		|| security_descriptor != security(&file)?
		|| identity != file_identity(&file)?
		|| canonical_path
			!= fs::canonicalize(path).map_err(|error| io_error("canonicalize_after", &error))?
	{
		return Err(FileSafetyError::Changed);
	}
	check_path(path)?;
	let snapshot = FileSnapshot {
		canonical_path,
		identity,
		sha256: sha256_hex(&bytes),
		length,
		attributes: attrs,
		creation_time: filetime(before.ftCreationTime),
		last_write_time: filetime(before.ftLastWriteTime),
		security_descriptor,
	};
	Ok((snapshot, bytes))
}

//------------------------------------------------------------------------------
/**
 * 入力の絶対 path と全祖先の reparse を検査します。未知の prefix や ADS は拒否します。
 *
 * # Errors
 *
 * 相対パス、非対応 prefix、ADS、NUL、または祖先を含む reparse を拒否し、
 * metadata の取得失敗は工程と OS コードを保持して返します。
 */
//------------------------------------------------------------------------------
pub(crate) fn check_path(path: &Path) -> Result<(), FileSafetyError> {
	// 相対パスを作業先へ依存させず、操作対象を絶対パスへ限定する
	if !path.is_absolute() {
		return Err(FileSafetyError::UnsupportedPath);
	}
	let mut drive = None;
	// 元の path 自体を検査するため、canonicalize が隠す junction を見逃さない
	for component in path.components() {
		// prefix・root・通常要素だけを許可し、親参照や ADS を受理しない
		match component {
			// ローカル DOS drive に限定し、UNC や未知の device prefix を拒否する
			Component::Prefix(prefix) => match prefix.kind() {
				Prefix::Disk(value) | Prefix::VerbatimDisk(value) => drive = Some(value),
				_ => return Err(FileSafetyError::UnsupportedPath),
			},
			Component::ParentDir | Component::CurDir => {
				return Err(FileSafetyError::UnsupportedPath);
			}
			Component::Normal(value)
				if value
					.encode_wide()
					.any(|unit| unit == 0 || unit == u16::from(b':')) =>
			{
				return Err(FileSafetyError::UnsupportedPath);
			}
			Component::RootDir | Component::Normal(_) => {}
		}
	}
	let drive = drive.ok_or(FileSafetyError::UnsupportedPath)?;
	let root = [u16::from(drive), u16::from(b':'), u16::from(b'\\'), 0];
	// SAFETY: root は終端 NUL のある固定 DOS drive root
	if unsafe { GetDriveTypeW(root.as_ptr()) } != DRIVE_FIXED {
		return Err(FileSafetyError::NotLocalNtfs);
	}
	// 末端から drive root まで、symlink_metadata でリンク自身の属性を読む
	for ancestor in path.ancestors() {
		let metadata =
			fs::symlink_metadata(ancestor).map_err(|error| io_error("ancestor", &error))?;
		// 対象だけでなく全祖先の reparse を拒否し、途中の別実体への誘導を防ぐ
		if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return Err(FileSafetyError::ReparsePoint);
		}
	}
	Ok(())
}

//------------------------------------------------------------------------------
/**
 * 所有借用中の file handle から標準情報を取得します。API 失敗は伝播します。
 *
 * # Returns
 *
 * 借用した同じ handle から取得した標準ファイル情報。
 *
 * # Errors
 *
 * Windows API が失敗した場合、直後に取得した OS コードを返します。
 */
//------------------------------------------------------------------------------
fn file_information(file: &File) -> Result<BY_HANDLE_FILE_INFORMATION, FileSafetyError> {
	let mut info = BY_HANDLE_FILE_INFORMATION::default();
	// SAFETY: file は有効で、info は正しい型と容量の書込み領域
	if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
		return Err(last_error("file_information"));
	}
	Ok(info)
}

//------------------------------------------------------------------------------
/**
 * 同じ handle から 128 bit ID を取得します。不明時は変更を許可しません。
 *
 * # Returns
 *
 * volume serial と 128 bit の file ID。
 *
 * # Errors
 *
 * Windows API で ID を取得できなければ、工程と OS コードを返します。
 */
//------------------------------------------------------------------------------
fn file_identity(file: &File) -> Result<FileIdentity, FileSafetyError> {
	let mut info = FILE_ID_INFO::default();
	// SAFETY: FileIdInfo に対応する FILE_ID_INFO の正しいサイズと可変 pointer を渡す
	if unsafe {
		GetFileInformationByHandleEx(
			file.as_raw_handle(),
			FileIdInfo,
			(&mut info as *mut FILE_ID_INFO).cast(),
			size_of::<FILE_ID_INFO>() as u32,
		)
	} == 0
	{
		return Err(last_error("file_id"));
	}
	Ok(FileIdentity {
		volume_serial: info.VolumeSerialNumber,
		file_id: info.FileId.Identifier,
	})
}

//------------------------------------------------------------------------------
/**
 * 開いた実体の filesystem が NTFS であることを handle から確認します。
 *
 * # Errors
 *
 * volume 情報を取得できない、または filesystem が NTFS でない場合に失敗します。
 */
//------------------------------------------------------------------------------
fn check_volume(file: &File) -> Result<(), FileSafetyError> {
	let mut name = [0_u16; 64];
	// SAFETY: file は有効、name の容量を渡し、不要な省略可能出力には null を渡す
	if unsafe {
		GetVolumeInformationByHandleW(
			file.as_raw_handle(),
			std::ptr::null_mut(),
			0,
			std::ptr::null_mut(),
			std::ptr::null_mut(),
			std::ptr::null_mut(),
			name.as_mut_ptr(),
			name.len() as u32,
		)
	} == 0
	{
		return Err(last_error("volume"));
	}
	let end = name
		.iter()
		.position(|value| *value == 0)
		.ok_or(FileSafetyError::NotLocalNtfs)?;
	// ローカル NTFS の保証範囲だけを採用し、未知の filesystem へ適用しない
	if OsString::from_wide(&name[..end]) != "NTFS" {
		return Err(FileSafetyError::NotLocalNtfs);
	}
	Ok(())
}

//------------------------------------------------------------------------------
/**
 * owner/group/DACL の self-relative descriptor を alignment を保った領域へ取得します。
 *
 * # Returns
 *
 * owner・group・DACL を取得した descriptor の byte 列。
 *
 * # Errors
 *
 * 必要長を取得できない、1 MiB を超える、または descriptor の取得に失敗した場合。
 */
//------------------------------------------------------------------------------
fn security(file: &File) -> Result<Vec<u8>, FileSafetyError> {
	let flags = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
	let mut needed = 0;
	// SAFETY: 最初は必要容量だけを取得し、descriptor の領域は渡さない
	unsafe {
		GetKernelObjectSecurity(
			file.as_raw_handle(),
			flags,
			std::ptr::null_mut(),
			0,
			&mut needed,
		);
	}
	// 必要容量の異常を検出してから、descriptor の取得領域を確保する
	if needed == 0 || needed > 1024 * 1024 {
		return Err(last_error("security_size"));
	}
	let mut aligned = vec![0_u32; (needed as usize).div_ceil(4)];
	let capacity = (aligned.len() * 4) as u32;
	// SAFETY: Vec<u32> は descriptor に必要な alignment/容量を満たし、呼出し中に再配置しない
	if unsafe {
		GetKernelObjectSecurity(
			file.as_raw_handle(),
			flags,
			aligned.as_mut_ptr().cast(),
			capacity,
			&mut needed,
		)
	} == 0
	{
		return Err(last_error("security"));
	}
	Ok(aligned
		.into_iter()
		.flat_map(u32::to_ne_bytes)
		.take(needed as usize)
		.collect())
}

//------------------------------------------------------------------------------
/**
 * `::$DATA` 以外の named stream がないことを完全列挙で確認します。
 *
 * # Errors
 *
 * 列挙 API の失敗、または通常の `::$DATA` 以外の stream が存在する場合。
 * 列挙ハンドルは成功・失敗のどちらでも閉じます。
 */
//------------------------------------------------------------------------------
fn check_streams(path: &Path) -> Result<(), FileSafetyError> {
	let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
	let mut info = WIN32_FIND_STREAM_DATA::default();
	// SAFETY: 終端 NUL path と FindStreamInfoStandard=0 に合う正しい出力型を渡す
	let handle = unsafe {
		FindFirstStreamW(
			wide.as_ptr(),
			0,
			(&mut info as *mut WIN32_FIND_STREAM_DATA).cast(),
			0,
		)
	};
	// 列挙開始の失敗を確認し、正常な列挙終端だけを空一覧として扱う
	if handle == INVALID_HANDLE_VALUE {
		let error = io::Error::last_os_error();
		// stream の列挙終端だけは成功とし、アクセス失敗を不在へ変換しない
		if error.raw_os_error() == Some(ERROR_HANDLE_EOF as i32) {
			return Ok(());
		}
		return Err(io_error("streams", &error));
	}
	let result = (|| {
		// 全 stream を EOF まで検査し、API の別エラーを列挙完了と混同しない
		loop {
			let end = info
				.cStreamName
				.iter()
				.position(|unit| *unit == 0)
				.ok_or(FileSafetyError::NamedStreams)?;
			// 通常データ以外の stream があれば、保存で失われる metadata として拒否する
			if OsString::from_wide(&info.cStreamName[..end]) != "::$DATA" {
				return Err(FileSafetyError::NamedStreams);
			}
			// SAFETY: 同じ列挙 handle と再利用可能な出力領域
			if unsafe { FindNextStreamW(handle, (&mut info as *mut WIN32_FIND_STREAM_DATA).cast()) }
				== 0
			{
				let error = io::Error::last_os_error();
				// 既知の列挙終端でだけ反復を終え、途中の OS 失敗は伝播する
				if matches!(
					error.raw_os_error(),
					Some(code) if code == ERROR_HANDLE_EOF as i32 || code == ERROR_NO_MORE_FILES as i32
				) {
					return Ok(());
				}
				return Err(io_error("next_stream", &error));
			}
		}
	})();
	// SAFETY: 成功した列挙 handle を一度だけ閉じ、失敗も呼出し元へ返す
	let closed = unsafe { FindClose(handle) };
	// 列挙が成功しても、所有 handle の close 失敗を成功へ変換しない
	if closed == 0 {
		return Err(last_error("close_streams"));
	}
	result
}

//------------------------------------------------------------------------------
/**
 * access time を除く比較対象の metadata を比較します。
 */
//------------------------------------------------------------------------------
fn same_information(left: &BY_HANDLE_FILE_INFORMATION, right: &BY_HANDLE_FILE_INFORMATION) -> bool {
	left.dwFileAttributes == right.dwFileAttributes
		&& left.nNumberOfLinks == right.nNumberOfLinks
		&& left.nFileSizeHigh == right.nFileSizeHigh
		&& left.nFileSizeLow == right.nFileSizeLow
		&& filetime(left.ftCreationTime) == filetime(right.ftCreationTime)
		&& filetime(left.ftLastWriteTime) == filetime(right.ftLastWriteTime)
}

//------------------------------------------------------------------------------
/**
 * FILETIME の二つの DWORD を lossless な u64 値へ結合します。
 */
//------------------------------------------------------------------------------
fn filetime(value: windows_sys::Win32::Foundation::FILETIME) -> u64 {
	(u64::from(value.dwHighDateTime) << 32) | u64::from(value.dwLowDateTime)
}

//------------------------------------------------------------------------------
/**
 * 最後の OS エラーを取得し、固定工程を付加します。
 */
//------------------------------------------------------------------------------
fn last_error(operation: &'static str) -> FileSafetyError {
	io_error(operation, &io::Error::last_os_error())
}

//------------------------------------------------------------------------------
/**
 * 外部エラー本文を複製せず、OS コードを保持します。
 */
//------------------------------------------------------------------------------
fn io_error(operation: &'static str, error: &io::Error) -> FileSafetyError {
	FileSafetyError::Io {
		operation,
		os_code: error.raw_os_error(),
	}
}

/// 通常ファイルの再照合と、危険な link/属性/stream の拒否を実データで確認します。
#[cfg(test)]
mod tests {
	use std::fs;
	use std::path::PathBuf;
	use std::sync::atomic::{AtomicUsize, Ordering};

	use super::{FileSafetyError, read_snapshot};

	// 同一 test executable 内の fixture を分離する番号
	static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

	//------------------------------------------------------------------------------
	/**
	 * artifacts 配下の新しい単一ファイル path を作ります。既存の対象を上書きしません。
	 */
	//------------------------------------------------------------------------------
	fn fixture_path() -> PathBuf {
		let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
			.join("../../artifacts/diagnostics/snapshot")
			.join(format!(
				"{}-{}",
				std::process::id(),
				NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
			));
		fs::create_dir_all(&root).expect("fixture directory");
		root.canonicalize()
			.expect("absolute fixture")
			.join("通常 file 日本語.bin")
	}

	//------------------------------------------------------------------------------
	/**
	 * 全 byte・128 bit ID・owner/group/DACL を取得し、外部内容変更を再照合で拒否します。
	 */
	//------------------------------------------------------------------------------
	#[test]
	fn snapshots_metadata_and_detects_content_replacement() {
		let path = fixture_path();
		fs::write(&path, b"original bytes").expect("fixture");
		let (snapshot, bytes) = read_snapshot(&path, 1024).expect("normal NTFS file");
		assert_eq!(bytes, b"original bytes");
		assert_eq!(snapshot.length(), 14);
		assert!(!snapshot.security_descriptor().is_empty());
		assert!(snapshot.identity().file_id.iter().any(|value| *value != 0));
		snapshot.revalidate(1024).expect("不変");
		fs::write(&path, b"replaced bytes").expect("外部変更");
		assert_eq!(snapshot.revalidate(1024), Err(FileSafetyError::Changed));
	}

	//------------------------------------------------------------------------------
	/**
	 * hardlink・named stream・readonly・容量超過・相対 path を変更可能と判定しません。
	 */
	//------------------------------------------------------------------------------
	#[test]
	fn rejects_links_streams_readonly_size_and_relative_paths() {
		let linked = fixture_path();
		fs::write(&linked, b"data").expect("fixture");
		fs::hard_link(&linked, linked.with_extension("link")).expect("hardlink");
		assert_eq!(
			read_snapshot(&linked, 1024).expect_err("hardlink"),
			FileSafetyError::MultipleLinks
		);
		let streamed = fixture_path();
		fs::write(&streamed, b"data").expect("fixture");
		let mut named = streamed.as_os_str().to_owned();
		named.push(":unexpected");
		fs::write(&named, b"stream").expect("named stream");
		assert_eq!(
			read_snapshot(&streamed, 1024).expect_err("named stream"),
			FileSafetyError::NamedStreams
		);
		assert_eq!(
			read_snapshot(std::path::Path::new("relative.bin"), 1024).expect_err("relative"),
			FileSafetyError::UnsupportedPath
		);
		let readonly = fixture_path();
		fs::write(&readonly, b"data").expect("fixture");
		let mut permissions = fs::metadata(&readonly).expect("metadata").permissions();
		permissions.set_readonly(true);
		fs::set_permissions(&readonly, permissions).expect("readonly fixture");
		assert!(matches!(
			read_snapshot(&readonly, 1024),
			Err(FileSafetyError::UnsupportedAttributes { .. })
		));
		let large = fixture_path();
		fs::write(&large, [0_u8; 2048]).expect("fixture");
		assert_eq!(
			read_snapshot(&large, 1024).expect_err("size"),
			FileSafetyError::TooLarge
		);
	}

	//------------------------------------------------------------------------------
	/**
	 * 診断後の属性変更も、内容が同じというだけで元の安全性判定を再利用しません。
	 */
	//------------------------------------------------------------------------------
	#[test]
	fn rejects_metadata_change_even_with_identical_content() {
		let path = fixture_path();
		fs::write(&path, b"data").expect("fixture");
		let (snapshot, _) = read_snapshot(&path, 1024).expect("snapshot");
		let mut permissions = fs::metadata(&path).expect("metadata").permissions();
		permissions.set_readonly(true);
		fs::set_permissions(&path, permissions).expect("external readonly");
		assert!(snapshot.revalidate(1024).is_err());
	}
}
