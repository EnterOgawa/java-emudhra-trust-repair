//------------------------------------------------------------------------------
/*!
 * - ファイル: advisory_http.rs
 * - 概要: 公式の公開元から Java の勧告を HTTPS で取得します
 * - バージョン: 01.01.01
 * - 作成日: 2026/11/19
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
 * Ver.01.00.00  Shunji Ogawa  2026/11/19  新規作成
 * Ver.01.01.00  Shunji Ogawa  2026/11/19  Oracle と OpenJDK の公式配布元を直接取得
 * Ver.01.01.01  Shunji Ogawa  2026/11/19  管理者権限での定義キャッシュを抑止する判定を追加
 * ```
 *
 * 備考:
 *
 * 証明書の検証とプロキシの選択には Windows の設定を使用します
 */
//------------------------------------------------------------------------------

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::{from_mut, from_ref, null, null_mut};
use std::time::{Duration, Instant};

use windows_sys::Win32::Networking::WinHttp::{
	INTERNET_DEFAULT_HTTPS_PORT, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
	WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH, WINHTTP_DISABLE_AUTHENTICATION, WINHTTP_DISABLE_COOKIES,
	WINHTTP_DISABLE_REDIRECTS, WINHTTP_FLAG_SECURE, WINHTTP_OPTION_AUTOLOGON_POLICY,
	WINHTTP_OPTION_CONNECT_RETRIES, WINHTTP_OPTION_DISABLE_FEATURE,
	WINHTTP_OPTION_RECEIVE_RESPONSE_TIMEOUT, WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_QUERY_STATUS_CODE,
	WinHttpCloseHandle, WinHttpConnect, WinHttpOpen, WinHttpOpenRequest, WinHttpQueryHeaders,
	WinHttpReadData, WinHttpReceiveResponse, WinHttpSendRequest, WinHttpSetOption,
	WinHttpSetTimeouts,
};
use windows_sys::Win32::Security::{
	GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::core::{BOOL, PCWSTR};
use windows_sys::w;

/// 公式勧告の応答本文に許す最大バイト数
const MAX_ADVISORY_BYTES: usize = 16 * 1024 * 1024;
/// 名前解決、接続、送信、個々の受信操作を待つ時間の設定値（ミリ秒）
const IO_TIMEOUT_MS: i32 = 4_000;
/// 接続タイムアウトに達するまでに試行できる IP アドレスの数
const MAX_CONNECT_ATTEMPTS: u32 = 2;
/// 応答ヘッダ全体の受信を待つ時間の設定値（ミリ秒）
const HEADER_TIMEOUT_MS: u32 = 8_000;
/// 取得開始から応答を採用できるまでの経過時間の上限
const FETCH_BUDGET: Duration = Duration::from_secs(15);
/// WinHTTP の受信バッファに合わせた最大読込みバイト数
const READ_BUFFER_BYTES: usize = 8 * 1024;

/// WinHTTP が返したセッション、接続、または要求ハンドルの所有権を保持します
struct HttpHandle(
	/// クローズ前の有効なハンドル
	*mut c_void,
);

impl HttpHandle {
	//------------------------------------------------------------------------------
	/**
	 * WinHTTP の生成結果が有効ならハンドルを引き取ります
	 *
	 * # Arguments
	 *
	 * - `handle`: WinHTTP の生成関数が直前に返した結果
	 *
	 * # Returns
	 *
	 * 所有してクローズできるハンドル
	 *
	 * # Errors
	 *
	 * NULL の場合は直前の OS エラーを返します
	 */
	//------------------------------------------------------------------------------
	fn from_created(handle: *mut c_void) -> io::Result<Self> {
		// 失敗を表す NULL を所有ハンドルにせず、WinHTTP のエラーをその場で取得する
		if handle.is_null() {
			return Err(io::Error::last_os_error());
		}
		Ok(Self(handle))
	}

	//------------------------------------------------------------------------------
	/**
	 * WinHTTP のハンドルに DWORD のオプションを設定します
	 *
	 * # Arguments
	 *
	 * - `option`: 対象のハンドルで設定可能な DWORD オプション番号
	 * - `value`: 設定する DWORD 値
	 *
	 * # Errors
	 *
	 * Windows が設定を拒否した場合は OS エラーを返します
	 */
	//------------------------------------------------------------------------------
	fn set_dword_option(&self, option: u32, value: u32) -> io::Result<()> {
		// SAFETY: 自分が所有する有効なハンドルと指定サイズの DWORD 参照を渡します
		http_result(unsafe {
			WinHttpSetOption(
				self.0,
				option,
				from_ref(&value).cast(),
				size_of::<u32>() as u32,
			)
		})
	}
}

impl Drop for HttpHandle {
	//------------------------------------------------------------------------------
	/**
	 * 所有する WinHTTP ハンドルを終了経路に関わらず解放します
	 */
	//------------------------------------------------------------------------------
	fn drop(&mut self) {
		// SAFETY: ハンドルはこの値だけが所有し、同期呼出しの途中で解放されることはありません
		unsafe { WinHttpCloseHandle(self.0) };
	}
}

//------------------------------------------------------------------------------
/**
 * WinHTTP の BOOL 戻り値を I/O の実行結果に変換します
 *
 * # Arguments
 *
 * - `result`: WinHTTP の直前の呼出しで得た BOOL 値
 *
 * # Errors
 *
 * 失敗を表す 0 の場合は直前の OS エラーを返します
 */
//------------------------------------------------------------------------------
fn http_result(result: BOOL) -> io::Result<()> {
	// OS の退避エラーは失敗を示した場合だけ取得する
	if result == 0 {
		return Err(io::Error::last_os_error());
	}
	Ok(())
}

//------------------------------------------------------------------------------
/**
 * 取得開始からの経過時間が上限に達していないことを確認します
 *
 * # Arguments
 *
 * - `started`: 取得を開始した時点
 *
 * # Errors
 *
 * 取得期限に達した場合は [`io::ErrorKind::TimedOut`] を返します
 */
//------------------------------------------------------------------------------
fn ensure_fetch_budget(started: Instant) -> io::Result<()> {
	// 個々の WinHTTP 操作が成功しても、取得全体が時間枠を超えた場合は中断する
	if started.elapsed() >= FETCH_BUDGET {
		return Err(io::Error::new(
			io::ErrorKind::TimedOut,
			"Java 助言一覧の取得期限を超えました",
		));
	}
	Ok(())
}

//------------------------------------------------------------------------------
/**
 * Oracle または OpenJDK の公式勧告の応答本文を取得します
 *
 * # Arguments
 *
 * - `url`: 許可した公式サイト上の勧告または索引の HTTPS URL
 * - `max_bytes`: 採用する本文の最大バイト数。16 MiB 以下に制限します
 *
 * # Returns
 *
 * HTTPS の HTTP 200 応答から読み切った本文のバイト列
 *
 * # Errors
 *
 * HTTPS や HTTP ステータスの異常、取得期限の超過、本文の容量超過で失敗します
 *
 * # Notes
 *
 * Windows の証明書検証とプロキシの選択を使用します。要求は転送先を追わず、
 * Windows のログオン資格情報と Cookie を送信しません。
 * UI スレッドの外で呼び出す同期処理です。取得した本文は呼出し元で検証してください
 */
//------------------------------------------------------------------------------
pub fn fetch_official_advisory(url: &str, max_bytes: usize) -> io::Result<Vec<u8>> {
	let (host, path) = official_request(url).ok_or_else(|| {
		io::Error::new(
			io::ErrorKind::InvalidInput,
			"公式勧告の URL が許可範囲外です",
		)
	})?;
	let path: Vec<u16> = path.encode_utf16().chain([0]).collect();
	let max_bytes = max_bytes.min(MAX_ADVISORY_BYTES);
	let started = Instant::now();
	// SAFETY: エージェント名は終端された静的 UTF-16 文字列です。プロキシの指定は不要です
	let session = HttpHandle::from_created(unsafe {
		WinHttpOpen(
			w!("Java-eMudhra-Trust-Repair"),
			WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
			null(),
			null(),
			0,
		)
	})?;
	// SAFETY: セッションは有効で、各タイムアウトには正のミリ秒を指定します
	http_result(unsafe {
		WinHttpSetTimeouts(
			session.0,
			IO_TIMEOUT_MS,
			IO_TIMEOUT_MS,
			IO_TIMEOUT_MS,
			IO_TIMEOUT_MS,
		)
	})?;
	session.set_dword_option(WINHTTP_OPTION_CONNECT_RETRIES, MAX_CONNECT_ATTEMPTS)?;
	// SAFETY: セッションは有効で、ホストは終端された静的 UTF-16 文字列です
	let connection = HttpHandle::from_created(unsafe {
		WinHttpConnect(session.0, host, INTERNET_DEFAULT_HTTPS_PORT, 0)
	})?;
	// SAFETY: 接続は有効で、メソッドとパスは終端された UTF-16 文字列です。パスは呼出し中有効です
	let request = HttpHandle::from_created(unsafe {
		WinHttpOpenRequest(
			connection.0,
			w!("GET"),
			path.as_ptr(),
			null(),
			null(),
			null(),
			WINHTTP_FLAG_SECURE,
		)
	})?;
	// 保護設定が有効な場合に限り、要求を送信する
	request.set_dword_option(
		WINHTTP_OPTION_DISABLE_FEATURE,
		WINHTTP_DISABLE_AUTHENTICATION | WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_REDIRECTS,
	)?;
	request.set_dword_option(
		WINHTTP_OPTION_AUTOLOGON_POLICY,
		WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH,
	)?;
	request.set_dword_option(WINHTTP_OPTION_RECEIVE_RESPONSE_TIMEOUT, HEADER_TIMEOUT_MS)?;
	// SAFETY: 要求は有効で、追加ヘッダや本文を送らないため各バッファは NULL、長さは 0 です
	http_result(unsafe { WinHttpSendRequest(request.0, null(), 0, null(), 0, 0, 0) })?;
	ensure_fetch_budget(started)?;
	// SAFETY: 要求の送信は完了し、予約引数には NULL を渡します
	http_result(unsafe { WinHttpReceiveResponse(request.0, null_mut()) })?;
	ensure_fetch_budget(started)?;

	let mut status = 0_u32;
	let mut status_size = size_of::<u32>() as u32;
	// SAFETY: 受信済みの応答から数値を取得し、指定サイズの書込み領域を渡します
	http_result(unsafe {
		WinHttpQueryHeaders(
			request.0,
			WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
			null(),
			from_mut(&mut status).cast(),
			&mut status_size,
			null_mut(),
		)
	})?;
	// 転送応答、認証要求、部分応答、エラーページを一覧として採用しない
	if status != 200 {
		return Err(io::Error::other(format!(
			"Java 助言一覧の取得先から HTTP {status} が返されました"
		)));
	}

	let mut bytes = Vec::new();
	let mut buffer = [0; READ_BUFFER_BYTES];
	// 全体の経過時間を監視し、EOF または本文の上限で読込みを終える
	loop {
		let remaining = max_bytes - bytes.len();
		// 上限に達した場合も 1 バイトの読込みを許し、過大な本文と EOF を区別する
		let to_read = (remaining + 1).min(buffer.len());
		let mut read = 0;
		// SAFETY: 要求は同期モードで応答受信済みです。バッファと読込み量の領域は呼出し中有効です
		http_result(unsafe {
			WinHttpReadData(
				request.0,
				buffer.as_mut_ptr().cast(),
				to_read as u32,
				&mut read,
			)
		})?;
		ensure_fetch_budget(started)?;
		let read = read as usize;
		// 上限を超えたバイトは本文に加えず、呼出し元にも部分データを返さない
		if read > remaining || read > to_read {
			return Err(io::Error::new(
				io::ErrorKind::InvalidData,
				"Java 助言一覧が取得容量の上限を超えました",
			));
		}
		// WinHTTP が EOF を返した時点で読み切った本文を返す
		if read == 0 {
			return Ok(bytes);
		}
		bytes.extend_from_slice(&buffer[..read]);
	}
}

//------------------------------------------------------------------------------
/**
 * 公式勧告の固定ホストと、公開ディレクトリ内の曖昧さのないパスを認めます
 */
//------------------------------------------------------------------------------
fn official_request(url: &str) -> Option<(PCWSTR, &str)> {
	if url.len() > 512 {
		return None;
	}
	let rest = url.strip_prefix("https://")?;
	let (host, path) = rest.split_at(rest.find('/')?);
	if !path
		.bytes()
		.all(|byte| byte.is_ascii_alphanumeric() || b"/._-".contains(&byte))
		|| path.contains("//")
		|| path.split('/').any(|item| matches!(item, "." | ".."))
	{
		return None;
	}
	match host {
		"openjdk.org" if path.starts_with("/groups/vulnerability/advisories/") => {
			Some((w!("openjdk.org"), path))
		}
		"www.oracle.com"
			if path.starts_with("/a/tech/docs/security-alerts/")
				&& (path.ends_with(".xml") || path.ends_with(".json")) =>
		{
			Some((w!("www.oracle.com"), path))
		}
		_ => None,
	}
}

//------------------------------------------------------------------------------
/**
 * 通常権限のプロセスと確認できた場合だけ、ユーザー領域への定義保存を許可します
 *
 * # Returns
 *
 * 管理者権限に昇格していないと確認できた場合は `true`
 */
//------------------------------------------------------------------------------
pub fn can_use_advisory_cache() -> bool {
	let mut raw = null_mut();
	// SAFETY: 現在のプロセスの疑似ハンドルと、トークンを受ける有効な書込み領域を渡します
	if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
		return false;
	}
	// SAFETY: 成功した OpenProcessToken が返した所有ハンドルを一回だけ引き継ぎます
	let token = unsafe { OwnedHandle::from_raw_handle(raw) };
	let mut elevation = TOKEN_ELEVATION::default();
	let mut written = 0;
	let size = size_of::<TOKEN_ELEVATION>() as u32;
	// SAFETY: token と出力バッファは呼出し中有効で、指定する情報クラスとサイズが一致します
	let success = unsafe {
		GetTokenInformation(
			token.as_raw_handle(),
			TokenElevation,
			from_mut(&mut elevation).cast(),
			size,
			&mut written,
		)
	};
	success != 0 && written == size && elevation.TokenIsElevated == 0
}
