//------------------------------------------------------------------------------
/*!
 * - ファイル: java.rs
 * - 概要: 選択 Java の release・PE 実体・実行 metadata を照合します
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
 * vendor の表示は署名や発行者の証明ではありません。Java の全 DLL は hash 対象外です
 */
//------------------------------------------------------------------------------

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use trust_repair_core::{IssueCode, SUPPORTED_JAVA_MAJORS};

use crate::process::{Cancellation, ProcessError, run_readonly};
use crate::snapshot::{FileSafetyError, FileSnapshot, check_path, read_snapshot};

/// Java 選択を完了できない理由です。GUI は variant を翻訳できます
#[derive(Debug)]
pub enum JavaError {
	/// 製品対象の Windows x64 MSVC ビルドではありません
	UnsupportedTarget,
	/// release または executable のファイル検査に失敗しました
	File(
		/// 元のファイル安全性検査の失敗
		FileSafetyError,
	),
	/// release の必須項目/形式/重複が不正です
	InvalidRelease,
	/// Windows x64 PE executable ではありません
	InvalidExecutable,
	/// 選択した java.exe の起動に失敗しました
	Process(
		/// 元の子プロセス実行の失敗
		ProcessError,
	),
	/// release と Java 実行結果、または java.home の実体が一致しません
	MetadataMismatch,
}

impl std::fmt::Display for JavaError {
	//------------------------------------------------------------------------------
	/**
	 * 診断用の失敗分類を表示します。自由文から状態判定する必要はありません
	 *
	 * # Returns
	 *
	 * 出力先の書込みに成功すれば `Ok(())`
	 *
	 * # Errors
	 *
	 * 出力先の `fmt::Error` を伝播します。途中までの出力は取り消しません
	 */
	//------------------------------------------------------------------------------
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(formatter, "Java 選択検査の失敗: {self:?}")
	}
}

impl std::error::Error for JavaError {}

/// 検査した Windows x64 Java です。非対応 major も明示的な抑止理由を保持します
#[derive(Debug)]
pub struct JavaEnvironment {
	/// 選択 root の正規 path
	root: PathBuf,
	/// release と実行結果で照合した版文字列
	version: String,
	/// 明示リストと比較する major
	major: u16,
	/// release と実行結果で照合した vendor
	vendor: String,
	/// JDK または JRE の表示用の区別
	image_kind: JavaImageKind,
	/// release、java.exe、keytool.exe の順の snapshot
	snapshots: [FileSnapshot; 3],
	/// 非対応版を自動変更しないための理由
	issues: Vec<IssueCode>,
}

/// 選択環境の JDK/JRE の区別です
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JavaImageKind {
	/// javac または release により判定した開発キット
	Jdk,
	/// runtime image
	Jre,
}

impl JavaEnvironment {
	//------------------------------------------------------------------------------
	/**
	 * 検証済み root の path を返します
	 */
	//------------------------------------------------------------------------------
	pub fn root(&self) -> &Path {
		&self.root
	}

	//------------------------------------------------------------------------------
	/**
	 * 実測した Java の完全な版文字列を返します。版だけで安全とは判定しません
	 */
	//------------------------------------------------------------------------------
	pub fn version(&self) -> &str {
		&self.version
	}

	//------------------------------------------------------------------------------
	/**
	 * 対応リストと照合した major を返します
	 */
	//------------------------------------------------------------------------------
	pub fn major(&self) -> u16 {
		self.major
	}

	//------------------------------------------------------------------------------
	/**
	 * 選択環境が名乗る vendor を返します。署名検証の代わりにはなりません
	 */
	//------------------------------------------------------------------------------
	pub fn vendor(&self) -> &str {
		&self.vendor
	}

	//------------------------------------------------------------------------------
	/**
	 * 選択環境の JDK/JRE の区別を返します
	 */
	//------------------------------------------------------------------------------
	pub fn image_kind(&self) -> JavaImageKind {
		self.image_kind
	}

	//------------------------------------------------------------------------------
	/**
	 * 選択した Java 自体による変更抑止理由を返します
	 */
	//------------------------------------------------------------------------------
	pub fn issues(&self) -> &[IssueCode] {
		&self.issues
	}

	//------------------------------------------------------------------------------
	/**
	 * 検査した keytool.exe の正規実体 path を返します
	 */
	//------------------------------------------------------------------------------
	pub fn keytool(&self) -> &Path {
		self.snapshots[2].canonical_path()
	}

	//------------------------------------------------------------------------------
	/**
	 * release/java/keytool の再照合材料を返します
	 */
	//------------------------------------------------------------------------------
	pub fn snapshots(&self) -> &[FileSnapshot; 3] {
		&self.snapshots
	}

	//------------------------------------------------------------------------------
	/**
	 * cacerts を必ず含め、存在する jssecacerts を追加します。
	 * 明示 custom は scan の入力へ別途追加します。不在の cacerts は診断失敗にします
	 */
	//------------------------------------------------------------------------------
	pub fn candidate_stores(&self) -> Vec<PathBuf> {
		let security = self.root.join("lib/security");
		let mut candidates = vec![security.join("cacerts")];
		let jsse = security.join("jssecacerts");
		// jssecacerts は不在だけを省略し、権限等の失敗は診断範囲から隠さない
		if !matches!(fs::symlink_metadata(&jsse), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
		{
			candidates.push(jsse);
		}
		candidates
	}

	//------------------------------------------------------------------------------
	/**
	 * 入力時からの Java 実体の変化を確認します。失敗時は再選択が必要です
	 *
	 * # Errors
	 *
	 * release、java.exe、keytool.exe の内容・実体・metadata が変化したか、
	 * 再取得できない場合に失敗します。元ファイルは変更しません
	 */
	//------------------------------------------------------------------------------
	pub fn revalidate(&self) -> Result<(), JavaError> {
		// release と両 executable を同じ上限で再取得し、metadata/hash を比較する
		for snapshot in &self.snapshots {
			snapshot
				.revalidate(32 * 1024 * 1024)
				.map_err(JavaError::File)?;
		}
		Ok(())
	}
}

//------------------------------------------------------------------------------
/**
 * Java root の release、AMD64 PE、実行中 metadata を照合し、選択を完了します。
 * java.exe は選択環境だけを直接起動します。環境や信頼ストアを書き換えません
 *
 * # Arguments
 *
 * - `root`: 利用者が選択した Java の絶対パス。参照を結果へ保持しません
 * - `cancellation`: Java 子プロセスの開始前と収集中に検査する中断要求
 *
 * # Returns
 *
 * release と実行中の情報、および三ファイルの snapshot を持つ選択結果。
 * 対応外の Java も、読み取り可能なら抑止理由を付けて返します
 *
 * # Errors
 *
 * 実体/metadata/UTF-8/実行の検証失敗では [`JavaError`]。Java 8/非 LTS/将来版は
 * 実体を読める場合に `UnsupportedJava` を保持した結果を返し、変更を無効にします
 */
//------------------------------------------------------------------------------
pub fn select_java(root: &Path, cancellation: &Cancellation) -> Result<JavaEnvironment, JavaError> {
	crate::ensure_supported_target().map_err(|_| JavaError::UnsupportedTarget)?;
	check_path(root).map_err(JavaError::File)?;
	let root = fs::canonicalize(root).map_err(|error| {
		JavaError::File(FileSafetyError::Io {
			operation: "java_root",
			os_code: error.raw_os_error(),
		})
	})?;
	let (release_snapshot, release) =
		read_snapshot(&root.join("release"), 1024 * 1024).map_err(JavaError::File)?;
	let metadata = parse_release(&release)?;
	let version = metadata
		.get("JAVA_VERSION")
		.ok_or(JavaError::InvalidRelease)?
		.clone();
	let vendor = metadata
		.get("IMPLEMENTOR")
		.ok_or(JavaError::InvalidRelease)?
		.clone();
	let major = java_major(&version).ok_or(JavaError::InvalidRelease)?;
	// release が Windows x64 を示さなければ、実行確認へ進めない
	if metadata.get("OS_NAME").map(String::as_str) != Some("Windows")
		|| !matches!(
			metadata.get("OS_ARCH").map(String::as_str),
			Some("amd64" | "x86_64")
		) {
		return Err(JavaError::MetadataMismatch);
	}
	let (java_snapshot, java_bytes) =
		read_snapshot(&root.join("bin/java.exe"), 32 * 1024 * 1024).map_err(JavaError::File)?;
	let (keytool_snapshot, keytool_bytes) =
		read_snapshot(&root.join("bin/keytool.exe"), 32 * 1024 * 1024).map_err(JavaError::File)?;
	// 両 executable の実ヘッダを確認し、release の自己申告だけで採用しない
	if !is_amd64_pe(&java_bytes) || !is_amd64_pe(&keytool_bytes) {
		return Err(JavaError::InvalidExecutable);
	}
	let arguments: Vec<OsString> = [
		"-Duser.language=en",
		"-Duser.country=US",
		"-Dfile.encoding=UTF-8",
		"-Dsun.stdout.encoding=UTF-8",
		"-Dsun.stderr.encoding=UTF-8",
		"-XshowSettings:properties",
		"-version",
	]
	.into_iter()
	.map(OsString::from)
	.collect();
	let output = run_readonly(
		java_snapshot.canonical_path(),
		&arguments,
		None,
		cancellation,
	)
	.map_err(JavaError::Process)?;
	// 想定外の stdout があれば、既知の metadata 専用実行と扱わない
	if !output.stdout.is_empty() {
		return Err(JavaError::MetadataMismatch);
	}
	let required = [
		"java.version",
		"java.vendor",
		"java.home",
		"os.arch",
		"os.name",
		"sun.arch.data.model",
	];
	let mut observed = BTreeMap::new();
	// 必須 property だけを厳密に一回ずつ収集し、その他の version 表示を識別には使わない
	for line in output.stderr.lines() {
		// 同じ必須項目が複数現れた場合、どちらを信頼するか推測せず拒否する
		if let Some((key, value)) = line.trim().split_once(" = ")
			&& required.contains(&key)
			&& observed.insert(key, value).is_some()
		{
			return Err(JavaError::MetadataMismatch);
		}
	}
	// 実行中の版・vendor・OS・bit 数を release と照合してから環境を採用する
	if observed.len() != required.len()
		|| observed.get("java.version") != Some(&version.as_str())
		|| observed.get("java.vendor") != Some(&vendor.as_str())
		|| !matches!(observed.get("os.arch"), Some(&"amd64" | &"x86_64"))
		|| observed.get("sun.arch.data.model") != Some(&"64")
		|| !observed
			.get("os.name")
			.is_some_and(|value| value.starts_with("Windows"))
	{
		return Err(JavaError::MetadataMismatch);
	}
	let home = observed
		.get("java.home")
		.ok_or(JavaError::MetadataMismatch)?;
	// 実行した java.home が選択 root 以外を示す場合、別 Java の混入を拒否する
	if fs::canonicalize(home).map_err(|_| JavaError::MetadataMismatch)? != root {
		return Err(JavaError::MetadataMismatch);
	}
	// IMAGE_TYPE を優先し、未記載の場合だけ javac の存在から JDK/JRE を区別する
	let image_kind = match metadata.get("IMAGE_TYPE").map(String::as_str) {
		Some("JDK") => JavaImageKind::Jdk,
		Some("JRE") => JavaImageKind::Jre,
		None => {
			// IMAGE_TYPE がない旧環境では、JDK 固有 executable の存在で区別する
			if root.join("bin/javac.exe").is_file() {
				JavaImageKind::Jdk
			} else {
				JavaImageKind::Jre
			}
		}
		Some(_) => return Err(JavaError::InvalidRelease),
	};
	let issues = support_issues(major);
	let environment = JavaEnvironment {
		root,
		version,
		major,
		vendor,
		image_kind,
		snapshots: [release_snapshot, java_snapshot, keytool_snapshot],
		issues,
	};
	environment.revalidate()?;
	Ok(environment)
}

//------------------------------------------------------------------------------
/**
 * release の key="value" を解釈します。shell 展開はせず、未知キーも重複を検査します
 *
 * # Arguments
 *
 * - `input`: 選択した Java の release ファイル全体
 *
 * # Returns
 *
 * 重複のないキーと、引用符を除いた値の対応表
 *
 * # Errors
 *
 * UTF-8、行構造、キー、引用符、制御文字または重複キーの不正で失敗します
 */
//------------------------------------------------------------------------------
fn parse_release(input: &[u8]) -> Result<BTreeMap<String, String>, JavaError> {
	let text = std::str::from_utf8(input).map_err(|_| JavaError::InvalidRelease)?;
	let mut values = BTreeMap::new();
	// 空行を除くすべての release 行を検査し、必須値の上書きや制御文字を拒否する
	for line in text.lines().filter(|line| !line.is_empty()) {
		let (key, quoted) = line.split_once('=').ok_or(JavaError::InvalidRelease)?;
		// 未知の行構造を正常キーへ補正せず、release の項目境界を守る
		if key.is_empty()
			|| !key
				.bytes()
				.all(|value| value.is_ascii_uppercase() || value.is_ascii_digit() || value == b'_')
		{
			return Err(JavaError::InvalidRelease);
		}
		let value = quoted
			.strip_prefix('"')
			.and_then(|value| value.strip_suffix('"'))
			.ok_or(JavaError::InvalidRelease)?;
		// 引用符・制御文字・重複を受理せず、唯一の値だけを後続照合へ渡す
		if value.chars().any(char::is_control)
			|| value.contains('"')
			|| values.insert(key.to_owned(), value.to_owned()).is_some()
		{
			return Err(JavaError::InvalidRelease);
		}
	}
	Ok(values)
}

//------------------------------------------------------------------------------
/**
 * 旧来 1.x 表記も major に変換します。識別は対応リストとの完全比較で行います
 *
 * # Returns
 *
 * 先頭の版番号。旧式の `1.x` は `x` を返し、数値を取得できなければ `None`
 */
//------------------------------------------------------------------------------
fn java_major(version: &str) -> Option<u16> {
	let version = version.strip_prefix("1.").unwrap_or(version);
	version.split(['.', '-', '+', '_']).next()?.parse().ok()
}

//------------------------------------------------------------------------------
/**
 * 試験済み明示 major 以外は、将来 LTS も含め変更を抑止します
 *
 * # Returns
 *
 * 明示対応する 11・17・21・25 なら空、その他は `UnsupportedJava` を一件返します
 */
//------------------------------------------------------------------------------
fn support_issues(major: u16) -> Vec<IssueCode> {
	// 明示した四つの LTS だけを対応済みとし、将来版を自動許可しない
	if SUPPORTED_JAVA_MAJORS.contains(&major) {
		Vec::new()
	} else {
		vec![IssueCode::UnsupportedJava]
	}
}

//------------------------------------------------------------------------------
/**
 * DOS/PE 署名と AMD64/PE32+ を境界検査付きで検証します。コード署名検証ではありません
 *
 * # Returns
 *
 * 必要なヘッダが範囲内にあり、PE の machine と optional header が AMD64/PE32+ なら `true`
 */
//------------------------------------------------------------------------------
fn is_amd64_pe(bytes: &[u8]) -> bool {
	// DOS 署名を先に確認し、任意 byte を PE の offset として解釈しない
	if bytes.get(..2) != Some(b"MZ") {
		return false;
	}
	// PE offset の四 byte を取得できなければ、不完全なヘッダとして拒否する
	let Some(offset_bytes) = bytes
		.get(0x3c..0x40)
		.and_then(|value| value.try_into().ok())
	else {
		return false;
	};
	let offset = u32::from_le_bytes(offset_bytes) as usize;
	// 計算した位置のヘッダを全て取得できた場合だけ、AMD64 と PE32+ を照合する
	let Some(header) = offset
		.checked_add(26)
		.and_then(|end| bytes.get(offset..end))
	else {
		return false;
	};
	header[..4] == *b"PE\0\0" && header[4..6] == [0x64, 0x86] && header[24..26] == [0x0b, 0x02]
}

/// 対応版・release・実行形式の曖昧さを拒否する契約を確認します
#[cfg(test)]
mod tests {
	use super::{is_amd64_pe, java_major, parse_release, support_issues};
	use trust_repair_core::IssueCode;

	//------------------------------------------------------------------------------
	/**
	 * Java 8/非 LTS/将来 LTS を版が新しいというだけで対応済みにしないことを確認します
	 */
	//------------------------------------------------------------------------------
	#[test]
	fn supports_only_explicit_four_lts_majors() {
		// 旧表記と suffix を含む実際の版数から major を取り出す
		for (version, major) in [
			("1.8.0_492", 8),
			("11.0.32", 11),
			("17.0.16", 17),
			("21.0.12.1", 21),
			("25.0.4+101", 25),
			("26-ea", 26),
			("29", 29),
		] {
			assert_eq!(java_major(version), Some(major));
		}
		// 明示した四版だけが変更候補になれる
		for major in [11, 17, 21, 25] {
			assert!(support_issues(major).is_empty());
		}
		// 将来 LTS を含むリスト外の版を、数値の大小で許可しない
		for major in [0, 8, 9, 12, 22, 26, 29, 65535] {
			assert_eq!(support_issues(major), [IssueCode::UnsupportedJava]);
		}
	}

	//------------------------------------------------------------------------------
	/**
	 * release の重複・未引用・制御文字・不正 UTF8 と PE 境界の不足を拒否します
	 */
	//------------------------------------------------------------------------------
	#[test]
	fn rejects_untrusted_release_and_non_amd64_images() {
		assert!(parse_release(b"JAVA_VERSION=\"21.0.1\"\nIMPLEMENTOR=\"test\"\n").is_ok());
		// release の各違反を独立に拒否する
		for input in [
			b"JAVA_VERSION=21".as_slice(),
			b"JAVA_VERSION=\"21\"\nJAVA_VERSION=\"25\"",
			b"lowercase=\"test\"",
			b"JAVA_VERSION=\"21\0\"",
			&[0xff],
		] {
			assert!(parse_release(input).is_err());
		}
		assert!(!is_amd64_pe(b"MZ"));
		assert!(!is_amd64_pe(&vec![0; 4096]));
		let mut pe = vec![0_u8; 128];
		pe[..2].copy_from_slice(b"MZ");
		pe[0x3c..0x40].copy_from_slice(&64_u32.to_le_bytes());
		pe[64..68].copy_from_slice(b"PE\0\0");
		pe[68..70].copy_from_slice(&[0x64, 0x86]);
		pe[88..90].copy_from_slice(&[0x0b, 0x02]);
		assert!(is_amd64_pe(&pe));
		pe[68..70].copy_from_slice(&[0x4c, 0x01]);
		assert!(!is_amd64_pe(&pe));
	}
}
