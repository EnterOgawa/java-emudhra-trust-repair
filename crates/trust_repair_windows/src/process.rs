//------------------------------------------------------------------------------
/*!
 * - ファイル: process.rs
 * - 概要: 秘密を子専用環境で渡し、上限・中断・終了回収を持つ直接起動を提供します。
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
 * 所有する子だけを kill/wait します。子/OS/Command 内部の秘密コピーの消去は保証しません。
 */
//------------------------------------------------------------------------------

use std::ffi::OsString;
use std::fmt;
use std::io::{self, Read};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use trust_repair_core::MAX_INPUT_BYTES;
use windows_sys::Win32::Foundation::{ERROR_BROKEN_PIPE, ERROR_NO_DATA};
use windows_sys::Win32::System::Pipes::PeekNamedPipe;
use zeroize::{Zeroize, Zeroizing};

// コマンドラインには値でなく、この固定の子環境の名前だけを置く
const PASSWORD_ENV: &str = "JAVA_TRUST_REPAIR_STOREPASS";
// GUI から呼び出す Java/keytool に console を生成しない
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
/// 一回の Java/keytool 呼出しの最大待機時間です。
pub const PROCESS_TIMEOUT: Duration = Duration::from_secs(120);

/// 所有する文字列を drop 時に消去する password です。複製と内容の Debug を提供しません。
pub struct StorePassword(
	/// drop 時に内容を消去する、パスワードの所有 buffer。
	Zeroizing<String>,
);

impl StorePassword {
	//------------------------------------------------------------------------------
	/**
	 * 入力の所有権を受け取り、終了時に消去する秘密として検証します。
	 * GUI は元の入力 buffer も移動または別途消去し、失敗時の自動再試行は行いません。
	 *
	 * # Arguments
	 *
	 * - `input`: 消去責任ごと受け取るパスワード。
	 *
	 * # Returns
	 *
	 * 終了時に消去する秘密の所有値。
	 *
	 * # Errors
	 *
	 * 空、NUL、CR/LF、4096 byte 超過の場合は、受け取った入力を消去して失敗します。
	 */
	//------------------------------------------------------------------------------
	pub fn new(input: String) -> Result<Self, ProcessError> {
		let value = Zeroizing::new(input);
		// 制御文字や過大・空の入力を子の環境へ渡さず、所有 buffer の消去へ戻す
		if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
			return Err(ProcessError::InvalidPassword);
		}
		Ok(Self(value))
	}
}

impl fmt::Debug for StorePassword {
	//------------------------------------------------------------------------------
	/**
	 * [`fmt::Debug`] に従い、秘密の内容も長さも表示しません。
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
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str("StorePassword([REDACTED])")
	}
}

/// UI と同期 worker が共有できる、一方向の中断要求です。
#[derive(Debug, Clone, Default)]
pub struct Cancellation(
	/// 複製先の thread と共有する、一方向の中断要求。
	Arc<AtomicBool>,
);

impl Cancellation {
	//------------------------------------------------------------------------------
	/**
	 * 中断を要求します。別スレッドから呼び出せます。解除は新しい値の生成で行います。
	 */
	//------------------------------------------------------------------------------
	pub fn cancel(&self) {
		self.0.store(true, Ordering::Release);
	}

	//------------------------------------------------------------------------------
	/**
	 * 一度でも中断が要求されていれば `true` を返します。
	 */
	//------------------------------------------------------------------------------
	pub fn is_cancelled(&self) -> bool {
		self.0.load(Ordering::Acquire)
	}
}

/// GUI が文言を選択できるプロセス失敗です。外部 stdout/stderr 本文は保持しません。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessError {
	/// password の必須条件に合格しません。
	InvalidPassword,
	/// OS 呼出しに失敗しました。
	Io {
		/// 実施していた固定の工程。
		operation: &'static str,
		/// 利用可能な Win32 のエラーコード。
		os_code: Option<i32>,
	},
	/// 終了コードが成功ではありません。生の出力は公開しません。
	Unsuccessful {
		/// 子の終了コード。OS により取得できなければ None。
		exit_code: Option<i32>,
	},
	/// stdout または stderr が厳密な UTF-8 ではありません。
	InvalidUtf8,
	/// stdout または stderr の容量上限を超えました。
	OutputLimit,
	/// 時間上限で所有する子を終了・回収しました。
	Timeout,
	/// 中断要求で所有する子を終了・回収しました。
	Cancelled,
	/// 子の終了・回収自体に失敗しました。元の原因も保持します。
	Cleanup {
		/// 終了処理を開始した原因。
		cause: Box<ProcessError>,
		/// kill または wait の OS エラー。
		os_code: Option<i32>,
	},
}

impl fmt::Display for ProcessError {
	//------------------------------------------------------------------------------
	/**
	 * [`fmt::Display`] の診断用表現です。GUI は variant をローカライズします。
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
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(formatter, "Java プロセスの失敗: {self:?}")
	}
}

impl std::error::Error for ProcessError {}

/// 成功終了した厳密 UTF-8 出力です。非公開で Debug/ログ出力を提供せず drop 時に消去します。
pub(crate) struct ProcessOutput {
	/// stdout 全体。上限検査済み。
	pub stdout: String,
	/// stderr 全体。上限検査済み。
	pub stderr: String,
}

impl Drop for ProcessOutput {
	//------------------------------------------------------------------------------
	/**
	 * 解析に使った payload を終了時に消去します。外部へ全文を返しません。
	 */
	//------------------------------------------------------------------------------
	fn drop(&mut self) {
		self.stdout.zeroize();
		self.stderr.zeroize();
	}
}

/// プロセス所有権を保持し、全経路で終了・wait を行う内部 guard です。
struct OwnedChild {
	/// 呼出し元の child。回収済みなら None。
	child: Option<Child>,
}

impl OwnedChild {
	//------------------------------------------------------------------------------
	/**
	 * エラー時に kill と wait を試行し、後始末の失敗でも最初の原因を保持します。
	 *
	 * # Arguments
	 *
	 * - `cause`: kill/wait より前に検出した主原因。
	 *
	 * # Returns
	 *
	 * 後始末を試みた後の主原因。kill/wait の失敗で元の原因を置換しません。
	 */
	//------------------------------------------------------------------------------
	fn stop(&mut self, cause: ProcessError) -> ProcessError {
		// 既に子の所有を解いた経路では、重ねて終了操作を試みない
		let Some(child) = self.child.as_mut() else {
			return cause;
		};
		let kill_error = child.kill().err();
		let waited = child.wait();
		// 終了待ちに成功した子だけを guard から外し、未回収なら drop の再試行対象に残す
		if waited.is_ok() {
			self.child = None;
			// 既に終了していた子への kill 失敗は wait 成功なら回収失敗ではない
			return cause;
		}
		let os_code = waited
			.err()
			.or(kill_error)
			.and_then(|error| error.raw_os_error());
		ProcessError::Cleanup {
			cause: Box::new(cause),
			os_code,
		}
	}
}

impl Drop for OwnedChild {
	//------------------------------------------------------------------------------
	/**
	 * panic 等でも所有する子を残さず終了・回収します。通常経路は明示的に結果を返します。
	 */
	//------------------------------------------------------------------------------
	fn drop(&mut self) {
		// 所有中の子が残る場合だけ、例外経路でも終了と回収を試みる
		if let Some(child) = self.child.as_mut() {
			// Drop は失敗を返せない。通常のエラーは stop で返し、この最終防御だけは無視する
			let _ = child.kill();
			let _ = child.wait();
		}
	}
}

//------------------------------------------------------------------------------
/**
 * 読み取り専用 Java/keytool コマンドを直接起動し、両 pipe を交互に非 blocking drain します。
 * 引数は個別の OsString で渡し、親の環境を変更しません。callback や非同期 runtime は不要です。
 * エラー出力本文は返さず、成功時も password と一致する部分を除去します。
 *
 * # Arguments
 *
 * - `executable`: 直接起動する検証済み executable のパス。
 * - `arguments`: shell 展開を行わず個別に渡す引数。
 * - `password`: 子の環境へ一時供給する秘密。`None` は秘密を供給しない操作。
 * - `cancellation`: 子の終了回収まで監視する中断要求。
 *
 * # Returns
 *
 * 成功終了した子の UTF-8 出力。表示用途では秘密と一致する部分を除去します。
 *
 * # Errors
 *
 * 起動・pipe・入出力・終了待ち、異常終了、UTF-8、時間・各 stream の容量上限、
 * または中断で失敗します。成功前の出力は返さず、所有する子を終了・回収して戻ります。
 *
 * # Notes
 *
 * 実行は同期です。UI thread から呼ばず、呼出し元が完了まで待ちます。
 */
//------------------------------------------------------------------------------
pub(crate) fn run_readonly(
	executable: &Path,
	arguments: &[OsString],
	password: Option<&StorePassword>,
	cancellation: &Cancellation,
) -> Result<ProcessOutput, ProcessError> {
	run_with_limits(
		executable,
		arguments,
		password,
		cancellation,
		PROCESS_TIMEOUT,
		MAX_INPUT_BYTES,
	)
}

//------------------------------------------------------------------------------
/**
 * 厳密 RFC 解析用の成功 payload を変更せず返します。password と PEM 境界が同じでも壊しません。
 * 出力は非公開の ProcessOutput だけが所有し、Debug/ログ禁止・drop 時消去を維持します。
 * 失敗出力の全文は一切返しません。表示用の通常呼出しは run_readonly の除去を維持します。
 *
 * # Arguments
 *
 * - `executable`: 直接起動する検証済み executable のパス。
 * - `arguments`: shell 展開を行わず個別に渡す引数。
 * - `password`: keytool へ一時供給する秘密。参照を出力へ保持しません。
 * - `cancellation`: 子の終了回収まで監視する中断要求。
 *
 * # Returns
 *
 * 厳密な解析用の、秘密除去を行わない成功出力。所有する payload は drop 時に消去します。
 *
 * # Errors
 *
 * 起動・pipe・入出力・終了待ち、異常終了、UTF-8、時間・各 stream の容量上限、
 * または中断で失敗します。成功前の出力は返さず、所有する子を終了・回収して戻ります。
 */
//------------------------------------------------------------------------------
pub(crate) fn run_inventory(
	executable: &Path,
	arguments: &[OsString],
	password: &StorePassword,
	cancellation: &Cancellation,
) -> Result<ProcessOutput, ProcessError> {
	run_with_limits_output(
		executable,
		arguments,
		Some(password),
		cancellation,
		PROCESS_TIMEOUT,
		MAX_INPUT_BYTES,
		false,
	)
}

//------------------------------------------------------------------------------
/**
 * 上限の短い異常系試験も同じ実行経路で検証します。通常 API は固定上限を使用します。
 *
 * # Arguments
 *
 * - `executable`: 直接起動する検証済み executable のパス。
 * - `arguments`: shell 展開を行わず個別に渡す引数。
 * - `password`: 子の環境へ一時供給する秘密。`None` は秘密を供給しない操作。
 * - `cancellation`: 子の終了回収まで監視する中断要求。
 * - `timeout`: 起動後の収集開始から測る制限時間。
 * - `limit`: stdout と stderr それぞれに許可する最大 byte 数。
 *
 * # Returns
 *
 * 表示用の秘密除去を行った成功出力。
 *
 * # Errors
 *
 * 起動・pipe・入出力・終了待ち、異常終了、UTF-8、時間・各 stream の容量上限、
 * または中断で失敗します。成功前の出力は返さず、所有する子を終了・回収して戻ります。
 */
//------------------------------------------------------------------------------
fn run_with_limits(
	executable: &Path,
	arguments: &[OsString],
	password: Option<&StorePassword>,
	cancellation: &Cancellation,
	timeout: Duration,
	limit: usize,
) -> Result<ProcessOutput, ProcessError> {
	run_with_limits_output(
		executable,
		arguments,
		password,
		cancellation,
		timeout,
		limit,
		true,
	)
}

//------------------------------------------------------------------------------
/**
 * 同じ子の所有/回収契約で、表示用除去と解析用無改変を明示的に分けます。
 *
 * # Arguments
 *
 * - `executable`: 直接起動する検証済み executable のパス。
 * - `arguments`: shell 展開を行わず個別に渡す引数。
 * - `password`: 子の環境へ一時供給する秘密。`None` は秘密を供給しない操作。
 * - `cancellation`: 子の終了回収まで監視する中断要求。
 * - `timeout`: 収集を継続できる制限時間。
 * - `limit`: 各出力 stream の最大 byte 数。
 * - `redact`: `true` は表示用の秘密除去、`false` は解析用の無改変出力。
 *
 * # Returns
 *
 * 検証に合格した成功出力。引数と秘密への参照は保持しません。
 *
 * # Errors
 *
 * 起動・pipe・入出力・終了待ち、異常終了、UTF-8、時間・各 stream の容量上限、
 * または中断で失敗します。成功前の出力は返さず、所有する子を終了・回収して戻ります。
 */
//------------------------------------------------------------------------------
fn run_with_limits_output(
	executable: &Path,
	arguments: &[OsString],
	password: Option<&StorePassword>,
	cancellation: &Cancellation,
	timeout: Duration,
	limit: usize,
	redact: bool,
) -> Result<ProcessOutput, ProcessError> {
	// 開始前の中断要求で不要な子を生成しない
	if cancellation.is_cancelled() {
		return Err(ProcessError::Cancelled);
	}
	let mut command = Command::new(executable);
	command
		.args(arguments)
		.env_clear()
		.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.creation_flags(CREATE_NO_WINDOW);
	// Java の起動に必要な Windows の基本環境だけを許可し、Java 注入変数や PATH は継承しない
	for name in ["SystemRoot", "WINDIR", "TEMP", "TMP"] {
		// 許可した基本環境だけを、存在する場合に個別継承する
		if let Some(value) = std::env::var_os(name) {
			command.env(name, value);
		}
	}
	// 実行ファイルの親を作業先にし、親アプリの作業先へ依存させない
	if let Some(directory) = executable.parent() {
		command.current_dir(directory);
	}
	// 認証が必要な操作だけに一時の子環境を用意する
	if let Some(secret) = password {
		command.env(PASSWORD_ENV, secret.0.as_str());
	}
	let child = command.spawn().map_err(|error| io_error("spawn", &error))?;
	// OS が子環境を受け取った後、Command の環境を保持し続けない
	drop(command);
	let mut owned = OwnedChild { child: Some(child) };
	let result = collect(
		owned.child.as_mut().ok_or(ProcessError::Io {
			operation: "child",
			os_code: None,
		})?,
		cancellation,
		timeout,
		limit,
	);
	// 収集失敗は所有 guard による終了回収を通し、成功時だけ所有を解除する
	let (stdout, stderr, status) = match result {
		Ok(value) => {
			owned.child = None;
			value
		}
		Err(error) => return Err(owned.stop(error)),
	};
	let stdout = Zeroizing::new(stdout);
	let stderr = Zeroizing::new(stderr);
	// 子の異常終了を、途中の出力があるだけで成功にしない
	if !status.success() {
		return Err(ProcessError::Unsuccessful {
			exit_code: status.code(),
		});
	}
	let stdout_text = std::str::from_utf8(&stdout).map_err(|_| ProcessError::InvalidUtf8)?;
	let stderr_text = std::str::from_utf8(&stderr).map_err(|_| ProcessError::InvalidUtf8)?;
	// 起動した実体が秘密を出力しても公開しない。置換前の buffer も drop 時に消去する
	let clean = |value: &str| {
		// 解析用途では payload を保持し、表示用途でだけ秘密の一致部分を除去する
		if !redact {
			return value.to_owned();
		}
		password.map_or_else(
			|| value.to_owned(),
			|secret| value.replace(secret.0.as_str(), "[REDACTED]"),
		)
	};
	Ok(ProcessOutput {
		stdout: clean(stdout_text),
		stderr: clean(stderr_text),
	})
}

//------------------------------------------------------------------------------
/**
 * 二つの pipe を片方で待たずに読み、上限・中断を 10ms 間隔で検査して子を wait します。
 * PeekNamedPipe で利用可能な byte だけ読むため、reader thread を detach しません。
 * 終了観測より前の empty 判定は使わず、観測後に両 pipe が空になるまで交互に収集します。
 * 継承先が writer を保持していても EOF を待たず、開始時からの時間・容量上限を維持します。
 *
 * # Arguments
 *
 * - `child`: 呼出し元の guard が所有する実行中の子。両出力 pipe を借用します。
 * - `cancellation`: 収集中に検査する中断要求。
 * - `timeout`: 本関数の収集開始から測る最大時間。
 * - `limit`: stdout と stderr それぞれの最大 byte 数。
 *
 * # Returns
 *
 * 子の終了を観測した後に両 pipe を再検査して集めた byte 列と終了状態。
 *
 * # Errors
 *
 * 中断、制限時間・容量の超過、pipe の取得・読込み・終了待ちの失敗。
 * 子の kill/wait は、この結果を受け取る所有 guard が行います。
 */
//------------------------------------------------------------------------------
fn collect(
	child: &mut Child,
	cancellation: &Cancellation,
	timeout: Duration,
	limit: usize,
) -> Result<(Vec<u8>, Vec<u8>, std::process::ExitStatus), ProcessError> {
	let mut stdout_pipe = child.stdout.take().ok_or(ProcessError::Io {
		operation: "stdout",
		os_code: None,
	})?;
	let mut stderr_pipe = child.stderr.take().ok_or(ProcessError::Io {
		operation: "stderr",
		os_code: None,
	})?;
	let started = Instant::now();
	let mut stdout = Zeroizing::new(Vec::new());
	let mut stderr = Zeroizing::new(Vec::new());
	let mut exit_status = None;
	// 子終了と両 pipe の残データ消費まで繰り返す。子が pipe を閉じなくても時間上限で終了する
	loop {
		// 中断要求を各周で検査し、実行中の子は呼出し側の guard で回収する
		if cancellation.is_cancelled() {
			return Err(ProcessError::Cancelled);
		}
		// pipe 継承先が残る場合も、収集開始からの時間上限で打ち切る
		if started.elapsed() >= timeout {
			return Err(ProcessError::Timeout);
		}
		let out_count = drain_available(&mut stdout_pipe, &mut stdout, limit)?;
		let err_count = drain_available(&mut stderr_pipe, &mut stderr, limit)?;
		#[cfg(test)]
		tests::after_empty_drain(child, out_count, err_count);
		// 子終了後の両 pipe の empty だけを、収集完了の証拠にする
		if let Some(status) = exit_status
			&& out_count == 0
			&& err_count == 0
		{
			child.wait().map_err(|error| io_error("wait", &error))?;
			return Ok((
				std::mem::take(&mut *stdout),
				std::mem::take(&mut *stderr),
				status,
			));
		}
		// 初回の終了観測後は次周で必ず再 drain し、観測前の count では返さない
		if exit_status.is_none() {
			exit_status = child
				.try_wait()
				.map_err(|error| io_error("try_wait", &error))?;
		}
		// 実行中に出力がない場合だけ待機し、終了後の残データは続けて消費する
		if out_count == 0 && err_count == 0 && exit_status.is_none() {
			std::thread::sleep(Duration::from_millis(10));
		}
	}
}

//------------------------------------------------------------------------------
/**
 * 利用可能な pipe byte を一塊だけ読みます。上限超過または OS の失敗を伝播します。
 *
 * # Arguments
 *
 * - `pipe`: 現在利用可能な byte 数を問い合わせる所有中の pipe。
 * - `output`: 既に読んだ byte の末尾へ追加する buffer。
 * - `limit`: 追加後に許可する合計 byte 数。
 *
 * # Returns
 *
 * 今回追加した byte 数。現在読める byte がない、または pipe が閉じていれば 0。
 *
 * # Errors
 *
 * pipe の問い合わせ・読込み失敗、または容量上限超過。
 * 既に追加済みの byte は巻き戻しません。
 */
//------------------------------------------------------------------------------
#[allow(unsafe_code)]
fn drain_available(
	pipe: &mut (impl Read + AsRawHandle),
	output: &mut Vec<u8>,
	limit: usize,
) -> Result<usize, ProcessError> {
	let mut available = 0;
	// SAFETY: pipe の所有借用中だけ有効な HANDLE と、書込み可能な DWORD を渡す
	let success = unsafe {
		PeekNamedPipe(
			pipe.as_raw_handle(),
			std::ptr::null_mut(),
			0,
			std::ptr::null_mut(),
			&mut available,
			std::ptr::null_mut(),
		)
	};
	// pipe 問い合わせの失敗を確認し、終端と実際の OS 失敗を区別する
	if success == 0 {
		let error = io::Error::last_os_error();
		// 既知の pipe 終端は空として扱い、他の OS 失敗は上位へ返す
		if matches!(
			error.raw_os_error(),
			Some(code) if code == ERROR_BROKEN_PIPE as i32 || code == ERROR_NO_DATA as i32
		) {
			return Ok(0);
		}
		return Err(io_error("peek_pipe", &error));
	}
	// 現在読める byte がなければ待機せず、もう一方の pipe と子終了を検査する
	if available == 0 {
		return Ok(0);
	}
	let mut buffer = Zeroizing::new([0_u8; 8192]);
	let length = (available as usize).min(buffer.len());
	let read = pipe
		.read(&mut buffer[..length])
		.map_err(|error| io_error("read_pipe", &error))?;
	// 追加前に残容量を検査し、上限超過の部分出力を成功へ渡さない
	if read > limit.saturating_sub(output.len()) {
		return Err(ProcessError::OutputLimit);
	}
	output.extend_from_slice(&buffer[..read]);
	Ok(read)
}

//------------------------------------------------------------------------------
/**
 * 外部メッセージを持ち込まず、固定工程と OS コードだけを保持します。
 */
//------------------------------------------------------------------------------
fn io_error(operation: &'static str, error: &io::Error) -> ProcessError {
	ProcessError::Io {
		operation,
		os_code: error.raw_os_error(),
	}
}

//------------------------------------------------------------------------------
/**
 * 固定の英語/UTF-8 JVM 設定を個別引数として返します。
 */
//------------------------------------------------------------------------------
pub(crate) fn english_jvm_arguments() -> Vec<OsString> {
	[
		"-J-Duser.language=en",
		"-J-Duser.country=US",
		"-J-Dfile.encoding=UTF-8",
		"-J-Dsun.stdout.encoding=UTF-8",
		"-J-Dsun.stderr.encoding=UTF-8",
	]
	.into_iter()
	.map(OsString::from)
	.collect()
}

//------------------------------------------------------------------------------
/**
 * 診断専用の list 引数を作ります。秘密は名前のみを渡し、値は一切含めません。
 */
//------------------------------------------------------------------------------
pub(crate) fn list_arguments(store: &Path) -> Vec<OsString> {
	let mut args = english_jvm_arguments();
	args.extend(
		["-list", "-rfc", "-keystore"]
			.into_iter()
			.map(OsString::from),
	);
	// Java 11 の java.io.File は Win32 verbatim prefix を受理しないため、
	// 検査済み local DOS path の prefix だけを UTF-16 のまま除く。識別用 path は保持する
	args.push(java_path_argument(store));
	args.extend(
		["-storepass:env", PASSWORD_ENV]
			.into_iter()
			.map(OsString::from),
	);
	args
}

//------------------------------------------------------------------------------
/**
 * stage 専用の削除引数を作ります。呼出し側が元 path と異なる新規 stage を検証します。
 *
 * # Arguments
 *
 * - `store`: 呼出し側が検証した、元ファイルと異なる新規 stage。
 * - `alias`: inventory から取得した削除対象の別名。
 *
 * # Returns
 *
 * 指定 stage の一別名を削除する個別引数。パスワード値を含みません。
 */
//------------------------------------------------------------------------------
pub(crate) fn delete_arguments(store: &Path, alias: &str) -> Vec<OsString> {
	let mut args = english_jvm_arguments();
	args.extend(
		["-delete", "-alias", alias, "-keystore"]
			.into_iter()
			.map(OsString::from),
	);
	args.push(java_path_argument(store));
	args.extend(
		["-storepass:env", PASSWORD_ENV]
			.into_iter()
			.map(OsString::from),
	);
	args
}

//------------------------------------------------------------------------------
/**
 * 検査済み local DOS path の verbatim prefix だけを UTF-16 のまま除きます。
 */
//------------------------------------------------------------------------------
pub(crate) fn java_path_argument(path: &Path) -> OsString {
	// Java が扱える DOS path に限って verbatim prefix を外し、他の prefix は保持する
	if matches!(
		path.components().next(),
		Some(std::path::Component::Prefix(prefix))
			if matches!(prefix.kind(), std::path::Prefix::VerbatimDisk(_))
	) {
		let wide: Vec<u16> = path.as_os_str().encode_wide().collect();
		OsString::from_wide(&wide[4..])
	} else {
		path.as_os_str().to_owned()
	}
}

/// 実際の子を使い、pipe の飽和と中断時の終了回収を確認します。
#[cfg(test)]
mod tests {
	use super::{
		CREATE_NO_WINDOW, Cancellation, OwnedChild, PASSWORD_ENV, PROCESS_TIMEOUT, ProcessError,
		StorePassword, collect, english_jvm_arguments, list_arguments, run_inventory,
		run_with_limits,
	};
	use std::cell::RefCell;
	use std::ffi::OsString;
	use std::io::{Read, Write};
	use std::os::windows::process::CommandExt;
	use std::process::{Child, Command, ExitStatus, Stdio};
	use std::time::{Duration, Instant};

	// 最終書込みだけで既定 pipe を満たさないよう、各 payload を 4KiB 未満に固定する
	const TAIL_STDOUT: &str = concat!(
		"stdout final: 0123456789abcdefghijklmnopqrstuvwxyz\n",
		"0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz\n",
		"0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz\n",
		"stdout 最終出力完了\n",
	);
	const TAIL_STDERR: &str = concat!(
		"stderr final: 0123456789abcdefghijklmnopqrstuvwxyz\n",
		"0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz\n",
		"0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz\n",
		"warning: 終了直前の警告を保持\n",
	);

	/// 両 pipe の empty 検査直後だけ実子の終了を許可する、試験スレッド専用の同期処理です。
	type EmptyDrainHook = Box<dyn FnOnce(&mut Child)>;

	thread_local! {
		// 他の並列テストや通常 build の子には同期処理を適用しない
		static EMPTY_DRAIN_HOOK: RefCell<Option<EmptyDrainHook>> = const { RefCell::new(None) };
	}

	//------------------------------------------------------------------------------
	/**
	 * 両 pipe が実際に空だった一回だけ、同じスレッドが登録した同期処理を実行します。
	 *
	 * # Arguments
	 *
	 * - `child`: 同期処理へ貸し出す、この試験が所有する子。
	 * - `out_count`: 直前に stdout から読んだ byte 数。
	 * - `err_count`: 直前に stderr から読んだ byte 数。
	 *
	 * # Notes
	 *
	 * thread-local の処理を取り出してから実行し、同じ同期点の再入を避けます。
	 */
	//------------------------------------------------------------------------------
	pub(super) fn after_empty_drain(child: &mut Child, out_count: usize, err_count: usize) {
		// 出力の収集中は子を待機させ、競合する二つの empty 判定の直後に限定する
		if out_count == 0 && err_count == 0 {
			let hook = EMPTY_DRAIN_HOOK.with(|slot| slot.borrow_mut().take());
			// 同期点を明示登録した回帰だけが、実子の最終書込みと終了を許可する
			if let Some(hook) = hook {
				hook(child);
			}
		}
	}

	//------------------------------------------------------------------------------
	/**
	 * 同じ test executable の一つの無視試験だけを子として起動する引数です。
	 */
	//------------------------------------------------------------------------------
	fn fixture_arguments() -> Vec<OsString> {
		[
			"--exact",
			"process::tests::child_fixture",
			"--ignored",
			"--nocapture",
			"--test-threads=1",
		]
		.into_iter()
		.map(OsString::from)
		.collect()
	}

	//------------------------------------------------------------------------------
	/**
	 * 子専用の試験 fixture です。値の内容は非秘密の試験 mode だけです。
	 * 必須環境以外が継承されていないことも、子自身で検査します。
	 */
	//------------------------------------------------------------------------------
	#[test]
	#[ignore = "親の process 契約試験からだけ直接起動"]
	fn child_fixture() {
		// 禁止した注入変数が子へ一つも渡っていないことを確認する
		for name in [
			"JAVA_TOOL_OPTIONS",
			"_JAVA_OPTIONS",
			"JDK_JAVA_OPTIONS",
			"CLASSPATH",
			"PATH",
		] {
			assert!(std::env::var_os(name).is_none(), "外部環境を継承しました");
		}
		let mode = std::env::var(PASSWORD_ENV).expect("fixture mode");
		// 親が指定した待機 mode だけで長時間の子を再現する
		if mode.starts_with("sleep|") {
			let path = mode.strip_prefix("sleep|").expect("prefix");
			std::fs::write(path, std::process::id().to_string()).expect("PID marker");
			std::thread::sleep(Duration::from_secs(30));
		// 両 pipe の容量を超える出力を作り、交互収集の deadlock と上限を検証する
		} else if mode == "flood" {
			let buffer = vec![b'x'; 2 * 1024 * 1024];
			std::io::stdout().write_all(&buffer).expect("stdout");
			std::io::stderr().write_all(&buffer).expect("stderr");
		// 親の同期合図後に両末尾を書き、終了観測前の最終書込みを固定する
		} else if mode == "tail" {
			// 親の両 pipe の empty 検査後だけ書込み、libtest の末尾を加えず実終了する
			let mut release = [0];
			std::io::stdin().read_exact(&mut release).expect("release");
			assert_eq!(release, [1]);
			std::io::stdout()
				.write_all(TAIL_STDOUT.as_bytes())
				.expect("final stdout");
			std::io::stdout().flush().expect("flush stdout");
			std::io::stderr()
				.write_all(TAIL_STDERR.as_bytes())
				.expect("final stderr");
			std::io::stderr().flush().expect("flush stderr");
			std::process::exit(23);
		// 指定 mode ごとに不正な UTF-8 を stdout または stderr へ作り、両方の厳密検査を確認する
		} else if mode == "invalid-utf8" {
			std::io::stdout().write_all(&[0xff]).expect("stdout");
		}
		// stderr だけが不正な UTF-8 の場合も、stdout が正常だからと成功にしないことを確認する
		else if mode == "invalid-stderr-utf8" {
			// 正常な stdout があっても stderr の不正 byte を成功にしない
			std::io::stderr().write_all(&[0xff]).expect("stderr");
		// 明示した異常終了 mode だけに失敗コードを返す
		} else if mode == "fail" {
			std::process::exit(19);
		} else {
			println!("{mode}");
			eprintln!("{mode}");
		}
	}

	//------------------------------------------------------------------------------
	/**
	 * 実子の最終書込みと終了を、両 pipe の empty と次の try_wait の間へ固定します。
	 * 各 payload は pipe 容量未満のため、同期点で wait しても pipe 飽和を起こしません。
	 * エラー時も本番と同じ所有 guard で kill/wait し、戻る前に実子の終了を照合します。
	 *
	 * # Arguments
	 *
	 * - `limit`: 本番の collect に渡す各 pipe の容量上限（byte）。
	 *
	 * # Returns
	 *
	 * 所有する子の終了を確認した、両 stream の収集結果と終了状態。
	 *
	 * # Errors
	 *
	 * 本番 collect の制限・I/O エラーを返します。fixture の準備・同期・回収確認は試験の失敗にします。
	 */
	//------------------------------------------------------------------------------
	fn collect_tail_fixture(limit: usize) -> Result<(Vec<u8>, Vec<u8>, ExitStatus), ProcessError> {
		let executable = std::env::current_exe().expect("test executable");
		let child = Command::new(executable)
			.args(fixture_arguments())
			.env_clear()
			.env(PASSWORD_ENV, "tail")
			.stdin(Stdio::piped())
			.stdout(Stdio::piped())
			.stderr(Stdio::piped())
			.creation_flags(CREATE_NO_WINDOW)
			.spawn()
			.expect("tail fixture");
		let pid = child.id();
		let mut owned = OwnedChild { child: Some(child) };
		EMPTY_DRAIN_HOOK.with(|slot| {
			assert!(
				slot.borrow_mut()
					.replace(Box::new(|child| {
						child
							.stdin
							.take()
							.expect("release pipe")
							.write_all(&[1])
							.expect("release child after empty");
						assert_eq!(child.wait().expect("actual child exit").code(), Some(23));
					}))
					.is_none()
			);
		});
		let result = collect(
			owned.child.as_mut().expect("owned child"),
			&Cancellation::default(),
			Duration::from_secs(5),
			limit,
		);
		EMPTY_DRAIN_HOOK.with(|slot| {
			assert!(slot.borrow_mut().take().is_none(), "empty 同期点が未実行");
		});
		// 本番同様に成功時だけ所有を解除し、失敗時は最初の原因を保って終了回収する
		let result = match result {
			Ok(output) => {
				owned.child = None;
				Ok(output)
			}
			Err(error) => Err(owned.stop(error)),
		};
		assert!(!is_running(pid), "回収後に最終出力の子が残っています");
		result
	}

	//------------------------------------------------------------------------------
	/**
	 * empty→実子の両末尾書込み→終了→try_wait の順序でも、全 byte と終了コードを保持します。
	 */
	//------------------------------------------------------------------------------
	#[test]
	fn collects_final_output_written_before_exit_observation() {
		let (stdout, stderr, status) = collect_tail_fixture(4096).expect("final output");
		assert!(
			stdout.ends_with(TAIL_STDOUT.as_bytes()),
			"stdout 末尾の欠落"
		);
		assert_eq!(stderr, TAIL_STDERR.as_bytes(), "stderr 警告末尾の欠落");
		assert_eq!(status.code(), Some(23));
		assert!(!status.success());
	}

	//------------------------------------------------------------------------------
	/**
	 * 子終了後に初めて見える byte にも上限を適用し、部分出力を成功として返しません。
	 */
	//------------------------------------------------------------------------------
	#[test]
	fn enforces_limit_on_output_written_before_exit_observation() {
		let result = collect_tail_fixture(128);
		assert!(matches!(result, Err(ProcessError::OutputLimit)));
	}

	//------------------------------------------------------------------------------
	/**
	 * 両 pipe の合計が pipe 容量を超えても deadlock せず、個別上限が働くことを確認します。
	 */
	//------------------------------------------------------------------------------
	#[test]
	fn drains_both_pipes_and_enforces_per_stream_limit() {
		let executable = std::env::current_exe().expect("test executable");
		let password = StorePassword::new("flood".to_owned()).expect("mode");
		let output = run_with_limits(
			&executable,
			&fixture_arguments(),
			Some(&password),
			&Cancellation::default(),
			Duration::from_secs(5),
			3 * 1024 * 1024,
		)
		.expect("両 pipe drain");
		assert!(output.stdout.len() > 2 * 1024 * 1024);
		assert_eq!(output.stderr.len(), 2 * 1024 * 1024);
		let result = run_with_limits(
			&executable,
			&fixture_arguments(),
			Some(&password),
			&Cancellation::default(),
			Duration::from_secs(5),
			64 * 1024,
		);
		assert!(matches!(result, Err(ProcessError::OutputLimit)));
	}

	//------------------------------------------------------------------------------
	/**
	 * 表示用の秘密除去と解析用の無改変を守り、異常終了と両 stream の UTF8 違反を拒否します。
	 */
	//------------------------------------------------------------------------------
	#[test]
	fn redacts_secrets_and_rejects_exit_and_encoding_failures() {
		let executable = std::env::current_exe().expect("test executable");
		let password = StorePassword::new("EchoTestSecret123".to_owned()).expect("secret");
		let output = run_with_limits(
			&executable,
			&fixture_arguments(),
			Some(&password),
			&Cancellation::default(),
			Duration::from_secs(5),
			1024 * 1024,
		)
		.expect("echo");
		assert!(!output.stdout.contains("EchoTestSecret123"));
		assert!(!output.stderr.contains("EchoTestSecret123"));
		let inventory = run_inventory(
			&executable,
			&fixture_arguments(),
			&password,
			&Cancellation::default(),
		)
		.expect("raw inventory output");
		assert!(inventory.stdout.contains("EchoTestSecret123"));
		assert!(inventory.stderr.contains("EchoTestSecret123"));
		assert!(!format!("{password:?}").contains("EchoTestSecret123"));
		assert!(
			!format!(
				"{:?}",
				list_arguments(std::path::Path::new("C:\\test store\\cacerts"))
			)
			.contains("EchoTestSecret123")
		);
		assert_eq!(PROCESS_TIMEOUT, Duration::from_secs(120));
		assert_eq!(english_jvm_arguments().len(), 5);
		// UTF8 違反と終了コード異常を別々に起こして分類を照合する
		for (mode, expected) in [
			("invalid-utf8", ProcessError::InvalidUtf8),
			("invalid-stderr-utf8", ProcessError::InvalidUtf8),
			(
				"fail",
				ProcessError::Unsuccessful {
					exit_code: Some(19),
				},
			),
		] {
			let password = StorePassword::new(mode.to_owned()).expect("mode");
			let result = run_with_limits(
				&executable,
				&fixture_arguments(),
				Some(&password),
				&Cancellation::default(),
				Duration::from_secs(5),
				1024 * 1024,
			);
			assert!(matches!(result, Err(error) if error == expected));
		}
	}

	//------------------------------------------------------------------------------
	/**
	 * timeout/cancel は待機中の所有する子だけを終了し、戻った時点で実際に生存していません。
	 */
	//------------------------------------------------------------------------------
	#[test]
	fn timeout_and_cancel_kill_and_reap_owned_child() {
		let executable = std::env::current_exe().expect("test executable");
		let directory = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
			.join("../../artifacts/diagnostics/process");
		std::fs::create_dir_all(&directory).expect("fixture directory");
		// 時間上限と利用者中断の二経路で、実子 PID の終了を確認する
		for cancelled in [false, true] {
			let marker = directory.join(format!("{}-{cancelled}.pid", std::process::id()));
			let password = StorePassword::new(format!("sleep|{}", marker.display())).expect("mode");
			let cancellation = Cancellation::default();
			let request = cancellation.clone();
			// 中断と timeout の二経路で、要求を与える方法と期待する終了理由を分ける
			let thread = if cancelled {
				Some(std::thread::spawn(move || {
					std::thread::sleep(Duration::from_millis(250));
					request.cancel();
				}))
			} else {
				None
			};
			let started = Instant::now();
			let result = run_with_limits(
				&executable,
				&fixture_arguments(),
				Some(&password),
				&cancellation,
				// 中断試験では timeout に余裕を持たせ、時間上限の試験とは終了原因を分ける
				if cancelled {
					Duration::from_secs(5)
				} else {
					Duration::from_millis(250)
				},
				1024 * 1024,
			);
			// 生成した中断 thread の終了を確認してから、子の終了状態を照合する
			if let Some(thread) = thread {
				thread.join().expect("cancel thread");
			}
			assert!(started.elapsed() < Duration::from_secs(3));
			assert!(matches!(
				result,
				Err(error) if error == if cancelled {
					ProcessError::Cancelled
				} else {
					ProcessError::Timeout
				}
			));
			let pid: u32 = std::fs::read_to_string(marker)
				.expect("子が起動した証拠")
				.parse()
				.expect("PID");
			assert!(!is_running(pid), "回収後に子が残っています");
		}
	}

	//------------------------------------------------------------------------------
	/**
	 * PID が終了済みか検査します。既に OS が削除した PID も終了済みとして扱います。
	 *
	 * # Arguments
	 *
	 * - `pid`: この試験が起動した子の process ID。
	 *
	 * # Returns
	 *
	 * ハンドルを取得でき、終了コードが `STILL_ACTIVE` の場合だけ `true`。
	 */
	//------------------------------------------------------------------------------
	#[allow(unsafe_code)]
	fn is_running(pid: u32) -> bool {
		use windows_sys::Win32::Foundation::CloseHandle;
		use windows_sys::Win32::System::Threading::{
			GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
		};
		// SAFETY: query 権限だけで子 PID を開き、得た handle はこの関数内で必ず閉じる
		let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
		// 既に取得できない PID は終了済みとし、他 process の操作へ進めない
		if handle.is_null() {
			return false;
		}
		let mut exit = 259;
		// SAFETY: handle は有効、exit は書込み可能な DWORD
		let success = unsafe { GetExitCodeProcess(handle, &mut exit) };
		// SAFETY: 所有する process handle を一度だけ閉じる
		assert_ne!(unsafe { CloseHandle(handle) }, 0);
		assert_ne!(success, 0);
		exit == 259
	}
}
