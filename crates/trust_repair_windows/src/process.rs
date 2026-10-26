//------------------------------------------------------------------------------
/*!
 * - ファイル: process.rs
 * - 概要: 秘密を子専用環境で渡し、上限・中断・終了回収を持つ直接起動を提供します。
 * - バージョン: 01.00.02
 * - 作成日: 2026/10/26
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
 * Ver.01.00.00  Shunji Ogawa  2026/10/26  子の環境隔離と二つの pipe の同時 drain を追加。
 * Ver.01.00.01  Shunji Ogawa  2026/10/26  検証した stage 専用 delete 引数を追加。
 * Ver.01.00.02  Shunji Ogawa  2026/10/26  RFC 解析 payload は変更せず、非公開の所有 buffer を消去。
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
pub struct StorePassword(Zeroizing<String>);

impl StorePassword {
	//------------------------------------------------------------------------------
	/**
	 * 入力の所有権を受け取ります。空/NUL/改行/4096 byte 超過では入力を消去して失敗します。
	 * GUI は元の入力 buffer も移動または別途消去し、失敗時の自動再試行は行いません。
	 */
	//------------------------------------------------------------------------------
	pub fn new(input: String) -> Result<Self, ProcessError> {
		let value = Zeroizing::new(input);
		if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
			return Err(ProcessError::InvalidPassword);
		}
		Ok(Self(value))
	}
}

impl fmt::Debug for StorePassword {
	//------------------------------------------------------------------------------
	/** [`fmt::Debug`] に従い、秘密の内容も長さも表示しません。 */
	//------------------------------------------------------------------------------
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str("StorePassword([REDACTED])")
	}
}

/// UI と同期 worker が共有できる、一方向の中断要求です。
#[derive(Debug, Clone, Default)]
pub struct Cancellation(Arc<AtomicBool>);

impl Cancellation {
	//------------------------------------------------------------------------------
	/** 中断を要求します。別スレッドから呼び出せます。解除は新しい値の生成で行います。 */
	//------------------------------------------------------------------------------
	pub fn cancel(&self) {
		self.0.store(true, Ordering::Release);
	}

	//------------------------------------------------------------------------------
	/** 一度でも中断が要求されていれば `true` を返します。 */
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
	/** [`fmt::Display`] の診断用表現です。GUI は variant をローカライズします。 */
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
	/** 解析に使った payload を終了時に消去します。外部へ全文を返しません。 */
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
	/** エラー時に kill と wait を試行し、後始末の失敗でも最初の原因を保持します。 */
	//------------------------------------------------------------------------------
	fn stop(&mut self, cause: ProcessError) -> ProcessError {
		let Some(child) = self.child.as_mut() else {
			return cause;
		};
		let kill_error = child.kill().err();
		let waited = child.wait();
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
	/** panic 等でも所有する子を残さず終了・回収します。通常経路は明示的に結果を返します。 */
	//------------------------------------------------------------------------------
	fn drop(&mut self) {
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
/** 上限の短い異常系試験も同じ実行経路で検証します。通常 API は固定上限を使用します。 */
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
/** 同じ子の所有/回収契約で、表示用除去と解析用無改変を明示的に分けます。 */
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
		if let Some(value) = std::env::var_os(name) {
			command.env(name, value);
		}
	}
	if let Some(directory) = executable.parent() {
		command.current_dir(directory);
	}
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
	let (stdout, stderr, status) = match result {
		Ok(value) => {
			owned.child = None;
			value
		}
		Err(error) => return Err(owned.stop(error)),
	};
	let stdout = Zeroizing::new(stdout);
	let stderr = Zeroizing::new(stderr);
	if !status.success() {
		return Err(ProcessError::Unsuccessful {
			exit_code: status.code(),
		});
	}
	let stdout_text = std::str::from_utf8(&stdout).map_err(|_| ProcessError::InvalidUtf8)?;
	let stderr_text = std::str::from_utf8(&stderr).map_err(|_| ProcessError::InvalidUtf8)?;
	// 起動した実体が秘密を出力しても公開しない。置換前の buffer も drop 時に消去する
	let clean = |value: &str| {
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
	// 子終了と両 pipe の残データ消費まで繰り返す。子が pipe を閉じなくても時間上限で終了する
	loop {
		if cancellation.is_cancelled() {
			return Err(ProcessError::Cancelled);
		}
		if started.elapsed() >= timeout {
			return Err(ProcessError::Timeout);
		}
		let out_count = drain_available(&mut stdout_pipe, &mut stdout, limit)?;
		let err_count = drain_available(&mut stderr_pipe, &mut stderr, limit)?;
		if let Some(status) = child
			.try_wait()
			.map_err(|error| io_error("try_wait", &error))?
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
		if out_count == 0 && err_count == 0 {
			std::thread::sleep(Duration::from_millis(10));
		}
	}
}

//------------------------------------------------------------------------------
/** 利用可能な pipe byte を一塊だけ読みます。上限超過または OS の失敗を伝播します。 */
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
	if success == 0 {
		let error = io::Error::last_os_error();
		if matches!(error.raw_os_error(), Some(code) if code == ERROR_BROKEN_PIPE as i32 || code == ERROR_NO_DATA as i32)
		{
			return Ok(0);
		}
		return Err(io_error("peek_pipe", &error));
	}
	if available == 0 {
		return Ok(0);
	}
	let mut buffer = Zeroizing::new([0_u8; 8192]);
	let length = (available as usize).min(buffer.len());
	let read = pipe
		.read(&mut buffer[..length])
		.map_err(|error| io_error("read_pipe", &error))?;
	if read > limit.saturating_sub(output.len()) {
		return Err(ProcessError::OutputLimit);
	}
	output.extend_from_slice(&buffer[..read]);
	Ok(read)
}

//------------------------------------------------------------------------------
/** 外部メッセージを持ち込まず、固定工程と OS コードだけを保持します。 */
//------------------------------------------------------------------------------
fn io_error(operation: &'static str, error: &io::Error) -> ProcessError {
	ProcessError::Io {
		operation,
		os_code: error.raw_os_error(),
	}
}

//------------------------------------------------------------------------------
/** 固定の英語/UTF-8 JVM 設定を個別引数として返します。 */
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
/** 診断専用の list 引数を作ります。秘密は名前のみを渡し、値は一切含めません。 */
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
/** stage 専用の削除引数を作ります。呼出し側が元 path と異なる新規 stage を検証します。 */
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
/** 検査済み local DOS path の verbatim prefix だけを UTF-16 のまま除きます。 */
//------------------------------------------------------------------------------
pub(crate) fn java_path_argument(path: &Path) -> OsString {
	if matches!(path.components().next(), Some(std::path::Component::Prefix(prefix)) if matches!(prefix.kind(), std::path::Prefix::VerbatimDisk(_)))
	{
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
		Cancellation, PASSWORD_ENV, PROCESS_TIMEOUT, ProcessError, StorePassword,
		english_jvm_arguments, list_arguments, run_with_limits,
	};
	use std::ffi::OsString;
	use std::io::Write;
	use std::time::{Duration, Instant};

	//------------------------------------------------------------------------------
	/** 同じ test executable の一つの無視試験だけを子として起動する引数です。 */
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
		if mode.starts_with("sleep|") {
			let path = mode.strip_prefix("sleep|").expect("prefix");
			std::fs::write(path, std::process::id().to_string()).expect("PID marker");
			std::thread::sleep(Duration::from_secs(30));
		} else if mode == "flood" {
			let buffer = vec![b'x'; 2 * 1024 * 1024];
			std::io::stdout().write_all(&buffer).expect("stdout");
			std::io::stderr().write_all(&buffer).expect("stderr");
		} else if mode == "invalid-utf8" {
			std::io::stdout().write_all(&[0xff]).expect("stdout");
		} else if mode == "fail" {
			std::process::exit(19);
		} else {
			println!("{mode}");
			eprintln!("{mode}");
		}
	}

	//------------------------------------------------------------------------------
	/** 両 pipe の合計が pipe 容量を超えても deadlock せず、個別上限が働くことを確認します。 */
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
	/** 子が秘密を出力しても結果/Debug/引数へ漏らさず、異常終了と UTF8 違反を拒否します。 */
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
	/** timeout/cancel は待機中の所有する子だけを終了し、戻った時点で実際に生存していません。 */
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
				if cancelled {
					Duration::from_secs(5)
				} else {
					Duration::from_millis(250)
				},
				1024 * 1024,
			);
			if let Some(thread) = thread {
				thread.join().expect("cancel thread");
			}
			assert!(started.elapsed() < Duration::from_secs(3));
			assert!(
				matches!(result, Err(error) if error == if cancelled { ProcessError::Cancelled } else { ProcessError::Timeout })
			);
			let pid: u32 = std::fs::read_to_string(marker)
				.expect("子が起動した証拠")
				.parse()
				.expect("PID");
			assert!(!is_running(pid), "回収後に子が残っています");
		}
	}

	//------------------------------------------------------------------------------
	/** PID が終了済みか検査します。既に OS が削除した PID も終了済みとして扱います。 */
	//------------------------------------------------------------------------------
	#[allow(unsafe_code)]
	fn is_running(pid: u32) -> bool {
		use windows_sys::Win32::Foundation::CloseHandle;
		use windows_sys::Win32::System::Threading::{
			GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
		};
		// SAFETY: query 権限だけで子 PID を開き、得た handle はこの関数内で必ず閉じる
		let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
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
