//------------------------------------------------------------------------------
/*!
 * - ファイル: scan.rs
 * - 概要: 同期 worker 向けに読み取り診断・進捗・snapshot と変更計画を結び付けます。
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
 * Ver.01.00.00  Shunji Ogawa  2026/10/26  二回の inventory と前後 snapshot の照合を追加。
 * Ver.01.00.01  Shunji Ogawa  2026/10/26  同一の厳密一覧を transaction の stage 検査へ再利用。
 * Ver.01.00.02  Shunji Ogawa  2026/10/26  password と RFC 語句の一致でも解析 payload を壊さない。
 * ```
 *
 * 備考:
 *
 * 全操作は read-only です。鍵を含むストアの byte 列や外部出力全体は結果へ保持しません。
 */
//------------------------------------------------------------------------------

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use trust_repair_core::{
	ChangePlan, InventoryError, IssueCode, MAX_INPUT_BYTES, PlanError, Policy, ScanReport,
	StoreFormat, StoreInventory, parse_keytool_rfc,
};

use crate::java::{JavaEnvironment, JavaError};
use crate::process::{
	Cancellation, ProcessError, StorePassword, java_path_argument, list_arguments, run_inventory,
};
use crate::snapshot::{FileIdentity, FileSafetyError, FileSnapshot, read_snapshot};

/// 自動検出するストアの password を明示的に指定します。標準値の自動試行はしません。
pub struct BuiltinPasswords<'a> {
	/// cacerts に使用する、利用者が明示した password。
	pub cacerts: &'a StorePassword,
	/// 存在する jssecacerts に使用する password。cacerts と同じ参照も指定できます。
	pub jssecacerts: &'a StorePassword,
}

/// 利用者が明示追加した一つの custom truststore です。
#[derive(Debug)]
pub struct CustomStore {
	/// 対象の絶対 path。選択 root の外も明示指定で検査できます。
	pub path: PathBuf,
	/// このファイル用の password。Debug は内容を公開しません。
	pub password: StorePassword,
}

/// UI が OS 言語に応じた進捗文言へ変換する工程です。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanPhase {
	/// 選択した Java の snapshot を再照合しています。
	ValidateJava,
	/// 対象の実体/hash/metadata を取得しています。
	Snapshot,
	/// 一回目の keytool の全一覧を取得しています。
	ListInventory,
	/// 二回目の全一覧および前後 snapshot を照合しています。
	VerifyUnchanged,
	/// 全群の診断を終了しました。
	Complete,
}

/// 同期 worker の実際の工程に対応する進捗です。時間から百分率を作りません。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanProgress {
	/// 現在の工程。
	pub phase: ScanPhase,
	/// 選択順の 0 始まりの位置。Java/完了では None。
	pub input_index: Option<usize>,
	/// 重複統合前の入力総数。
	pub input_count: usize,
}

/// 成功終了した keytool が出す既知の情報通知です。診断の警告とは分離します。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanNotice {
	/// 明示 path で標準 cacerts を読んだ際の `use -cacerts` の操作案内。
	ExplicitCacertsPath,
}

/// 実測した既知の警告です。すべて群全体の plan を抑止します。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanWarning {
	/// 鍵を含む JKS に対して OpenJDK が表示する形式移行の警告。
	JksProprietaryFormat,
}

/// 一回の完全な一覧と、本文を保持しない既知メッセージです。
#[derive(PartialEq, Eq)]
pub(crate) struct ListedStore {
	/// 完全に解析した inventory。
	pub(crate) inventory: StoreInventory,
	/// 明示 cacerts path の情報通知。
	notices: Vec<ScanNotice>,
	/// すべて変更を抑止する警告。
	pub(crate) warnings: Vec<ScanWarning>,
}

/// 変更できなかった詳細です。本文を自由文へ潰さず GUI に判定材料を渡します。
#[derive(Debug)]
pub enum ScanFailure {
	/// 実体や metadata の読み取り失敗。
	File(FileSafetyError),
	/// Java の入力からの変化または実行検証の失敗。
	Java(JavaError),
	/// keytool の起動・上限・中断・終了の失敗。
	Process(ProcessError),
	/// 全一覧の解析失敗。外部出力は含みません。
	Inventory(InventoryError),
	/// stderr に未知または警告の出力がありました。本文を保持しません。
	UnrecognizedStderr,
	/// 元 byte で識別した形式と一覧の形式が一致しません。
	FormatMismatch,
	/// 二つの全 inventory が一致しません。
	InventoryChanged,
}

/// 一つの実体に対応する診断と後続の再照合材料です。
#[derive(Debug)]
pub struct StoreScan {
	/// 同一実体へ統合した入力 path の全一覧。
	input_paths: Vec<PathBuf>,
	/// 安全なファイル検査に合格した場合の診断前 snapshot。
	snapshot: Option<FileSnapshot>,
	/// DER 照合と群全体の計画可否に使用する診断。
	report: ScanReport,
	/// 上記とは別に表示できる keytool 固有の操作案内。
	notices: Vec<ScanNotice>,
	/// 形式やセキュリティ上の既知警告。全群の変更を抑止します。
	warnings: Vec<ScanWarning>,
	/// 診断失敗の型付き詳細。秘密や keytool 全文は含めません。
	failure: Option<ScanFailure>,
}

impl StoreScan {
	//------------------------------------------------------------------------------
	/** 重複指定を統合した元の全 path を返します。 */
	//------------------------------------------------------------------------------
	pub fn input_paths(&self) -> &[PathBuf] {
		&self.input_paths
	}

	//------------------------------------------------------------------------------
	/** 元実体の再照合材料を返します。ファイル検査失敗時は None。 */
	//------------------------------------------------------------------------------
	pub fn snapshot(&self) -> Option<&FileSnapshot> {
		self.snapshot.as_ref()
	}

	//------------------------------------------------------------------------------
	/** 全 inventory と判定理由を持つ、不変の診断を返します。 */
	//------------------------------------------------------------------------------
	pub fn report(&self) -> &ScanReport {
		&self.report
	}

	//------------------------------------------------------------------------------
	/** 正確に識別できた操作案内だけを返します。 */
	//------------------------------------------------------------------------------
	pub fn notices(&self) -> &[ScanNotice] {
		&self.notices
	}

	//------------------------------------------------------------------------------
	/** 全群の適用を抑止する、実測済みの既知警告を返します。 */
	//------------------------------------------------------------------------------
	pub fn warnings(&self) -> &[ScanWarning] {
		&self.warnings
	}

	//------------------------------------------------------------------------------
	/** 解析や I/O 失敗を GUI が翻訳できる形で返します。 */
	//------------------------------------------------------------------------------
	pub fn failure(&self) -> Option<&ScanFailure> {
		self.failure.as_ref()
	}
}

/// 選択された群全体の読み取り結果です。一部だけの成功から計画を作りません。
#[derive(Debug)]
pub struct ScanGroup {
	/// Java の選択時点の snapshot。transaction は実行直前にも再照合します。
	java_snapshots: [FileSnapshot; 3],
	/// 実体の重複を統合したストア群。
	stores: Vec<StoreScan>,
}

impl ScanGroup {
	//------------------------------------------------------------------------------
	/** cacerts/jssecacerts/custom を含む、今回検査したファイルの範囲を返します。 */
	//------------------------------------------------------------------------------
	pub fn stores(&self) -> &[StoreScan] {
		&self.stores
	}

	//------------------------------------------------------------------------------
	/** release/java/keytool の診断時 snapshot を返します。 */
	//------------------------------------------------------------------------------
	pub fn java_snapshots(&self) -> &[FileSnapshot; 3] {
		&self.java_snapshots
	}

	//------------------------------------------------------------------------------
	/**
	 * 全群の診断が合格し、対象がある場合だけ未適用の計画を返します。
	 * # Errors
	 *
	 * 一つでも失敗/警告/変更不可がある、定義が異なる、対象ゼロなら [`PlanError`]。
	 * 計画生成は disk を再照合しないため、後続は必ず各 snapshot を再検査します。
	 */
	//------------------------------------------------------------------------------
	pub fn plan(&self, policy: &Policy) -> Result<ChangePlan, PlanError> {
		let reports: Vec<_> = self
			.stores
			.iter()
			.map(|store| store.report.clone())
			.collect();
		ChangePlan::build(policy, &reports)
	}
}

//------------------------------------------------------------------------------
/**
 * 自動検出二種と明示 custom を読み取り診断します。同期の単一 worker から呼べます。
 * progress は呼出し元と同じスレッドで実行し、UI は channel へ転送できます。
 * 中断時も子の回収後に戻ります。元ファイルへの write/属性変更/削除は行いません。
 *
 * Java または必須ストアの失敗も結果へ残し、群全体の plan を無効にします。
 * 二回の全 inventory と診断前後・全群終了時の hash/ID/metadata の一致を必要とします。
 */
//------------------------------------------------------------------------------
pub fn scan_java(
	environment: &JavaEnvironment,
	policy: &Policy,
	passwords: &BuiltinPasswords<'_>,
	custom: &[CustomStore],
	cancellation: &Cancellation,
	mut progress: impl FnMut(ScanProgress),
) -> ScanGroup {
	let candidates = environment.candidate_stores();
	let mut inputs: Vec<(&Path, &StorePassword)> = candidates
		.iter()
		.enumerate()
		.map(|(index, path)| {
			(
				path.as_path(),
				if index == 0 {
					passwords.cacerts
				} else {
					passwords.jssecacerts
				},
			)
		})
		.collect();
	inputs.extend(
		custom
			.iter()
			.map(|store| (store.path.as_path(), &store.password)),
	);
	let count = inputs.len();
	progress(ScanProgress {
		phase: ScanPhase::ValidateJava,
		input_index: None,
		input_count: count,
	});
	if let Err(error) = environment.revalidate() {
		// 入力から変わった keytool を一度も起動せず、再選択を要求する
		let mut stores: Vec<_> = inputs
			.iter()
			.map(|(path, _)| {
				failed(
					policy,
					path,
					None,
					IssueCode::ChangedDuringScan,
					ScanFailure::InventoryChanged,
				)
			})
			.collect();
		if let Some(first) = stores.first_mut() {
			first.failure = Some(ScanFailure::Java(error));
		}
		progress(ScanProgress {
			phase: ScanPhase::Complete,
			input_index: None,
			input_count: count,
		});
		return ScanGroup {
			java_snapshots: environment.snapshots().clone(),
			stores,
		};
	}
	let mut stores: Vec<StoreScan> = Vec::new();
	let mut identities: HashMap<FileIdentity, usize> = HashMap::new();
	// 各入力を検査し、同じ file ID の指定だけを一件に統合する
	for (index, (path, password)) in inputs.into_iter().enumerate() {
		progress(ScanProgress {
			phase: ScanPhase::Snapshot,
			input_index: Some(index),
			input_count: count,
		});
		if cancellation.is_cancelled() {
			stores.push(failed(
				policy,
				path,
				None,
				IssueCode::Cancelled,
				ScanFailure::Process(ProcessError::Cancelled),
			));
			continue;
		}
		let snapshot = match read_snapshot(path, MAX_INPUT_BYTES) {
			Ok((snapshot, _)) => snapshot,
			Err(error) => {
				stores.push(failed(
					policy,
					path,
					None,
					IssueCode::UnsafeFile,
					ScanFailure::File(error),
				));
				continue;
			}
		};
		if let Some(existing) = identities.get(&snapshot.identity()) {
			stores[*existing].input_paths.push(path.to_path_buf());
			continue;
		}
		identities.insert(snapshot.identity(), stores.len());
		stores.push(scan_store(
			environment,
			policy,
			path,
			snapshot,
			password,
			cancellation,
			|phase| {
				progress(ScanProgress {
					phase,
					input_index: Some(index),
					input_count: count,
				})
			},
		));
	}
	// 群の最初のストアを読んだ後の外部変更も、全群終了時の再照合で検出する
	for store in &mut stores {
		if let Some(snapshot) = &store.snapshot
			&& let Err(error) = snapshot.revalidate(MAX_INPUT_BYTES)
		{
			store.report = ScanReport::failed(policy, IssueCode::ChangedDuringScan);
			store.failure = Some(ScanFailure::File(error));
		}
	}
	if let Err(error) = environment.revalidate() {
		// Java の変化は全群を無効にする。詳細の所有権は先頭の結果へ残す
		for store in &mut stores {
			store.report = ScanReport::failed(policy, IssueCode::ChangedDuringScan);
		}
		if let Some(first) = stores.first_mut() {
			first.failure = Some(ScanFailure::Java(error));
		}
	}
	progress(ScanProgress {
		phase: ScanPhase::Complete,
		input_index: None,
		input_count: count,
	});
	ScanGroup {
		java_snapshots: environment.snapshots().clone(),
		stores,
	}
}

//------------------------------------------------------------------------------
/** 一つの実体に対し、二回の keytool と間の hash/metadata/全 inventory を照合します。 */
//------------------------------------------------------------------------------
fn scan_store(
	environment: &JavaEnvironment,
	policy: &Policy,
	path: &Path,
	snapshot: FileSnapshot,
	password: &StorePassword,
	cancellation: &Cancellation,
	mut progress: impl FnMut(ScanPhase),
) -> StoreScan {
	let result = (|| {
		progress(ScanPhase::ListInventory);
		let first = list(environment, &snapshot, password, cancellation)?;
		snapshot
			.revalidate(MAX_INPUT_BYTES)
			.map_err(ScanFailure::File)?;
		progress(ScanPhase::VerifyUnchanged);
		let second = list(environment, &snapshot, password, cancellation)?;
		if first != second {
			return Err(ScanFailure::InventoryChanged);
		}
		snapshot
			.revalidate(MAX_INPUT_BYTES)
			.map_err(ScanFailure::File)?;
		Ok(first)
	})();
	match result {
		Ok(listed) => {
			let mut issues = environment.issues().to_vec();
			if !listed.warnings.is_empty() {
				issues.push(IssueCode::KeytoolWarning);
			}
			StoreScan {
				input_paths: vec![path.to_path_buf()],
				snapshot: Some(snapshot),
				report: ScanReport::evaluate(policy, listed.inventory, issues),
				notices: listed.notices,
				warnings: listed.warnings,
				failure: None,
			}
		}
		Err(error) => {
			let issue = match &error {
				ScanFailure::Process(ProcessError::Cancelled) => IssueCode::Cancelled,
				ScanFailure::Process(_) | ScanFailure::Java(_) => IssueCode::ProcessFailure,
				ScanFailure::File(FileSafetyError::Changed) | ScanFailure::InventoryChanged => {
					IssueCode::ChangedDuringScan
				}
				ScanFailure::File(_) => IssueCode::UnsafeFile,
				ScanFailure::UnrecognizedStderr => IssueCode::KeytoolWarning,
				ScanFailure::Inventory(_) | ScanFailure::FormatMismatch => {
					IssueCode::InvalidInventory
				}
			};
			failed(policy, path, Some(snapshot), issue, error)
		}
	}
}

//------------------------------------------------------------------------------
/** 成功終了・既知 stderr・元形式・RFC 全文の全条件に合格する一覧だけを返します。 */
//------------------------------------------------------------------------------
pub(crate) fn list(
	environment: &JavaEnvironment,
	snapshot: &FileSnapshot,
	password: &StorePassword,
	cancellation: &Cancellation,
) -> Result<ListedStore, ScanFailure> {
	let output = run_inventory(
		environment.keytool(),
		&list_arguments(snapshot.canonical_path()),
		password,
		cancellation,
	)
	.map_err(ScanFailure::Process)?;
	let normalized = output.stderr.replace("\r\n", "\n");
	let mut remaining = normalized.trim_matches('\n');
	let mut notices = Vec::new();
	if let Some(rest) =
		remaining.strip_prefix("Warning: use -cacerts option to access cacerts keystore")
	{
		if snapshot.canonical_path() != environment.root().join("lib/security/cacerts")
			|| (!rest.is_empty() && !rest.starts_with('\n'))
		{
			return Err(ScanFailure::UnrecognizedStderr);
		}
		notices.push(ScanNotice::ExplicitCacertsPath);
		remaining = rest.trim_matches('\n');
	}
	let mut warnings = Vec::new();
	if !remaining.is_empty() {
		let argument = java_path_argument(snapshot.canonical_path());
		let path = argument.to_str().ok_or(ScanFailure::UnrecognizedStderr)?;
		let expected = format!(
			"Warning:\nThe JKS keystore uses a proprietary format. It is recommended to migrate to PKCS12 which is an industry standard format using \"keytool -importkeystore -srckeystore {path} -destkeystore {path} -deststoretype pkcs12\"."
		);
		if remaining != expected {
			return Err(ScanFailure::UnrecognizedStderr);
		}
		warnings.push(ScanWarning::JksProprietaryFormat);
	}
	let inventory = parse_keytool_rfc(output.stdout.as_bytes()).map_err(ScanFailure::Inventory)?;
	// magic と keytool 形式を照合し、互換機能の暗黙変換や別形式を成功としない
	let (current, bytes) =
		read_snapshot(snapshot.canonical_path(), MAX_INPUT_BYTES).map_err(ScanFailure::File)?;
	if current != *snapshot {
		return Err(ScanFailure::File(FileSafetyError::Changed));
	}
	let expected = if bytes.starts_with(&[0xfe, 0xed, 0xfe, 0xed]) {
		Some(StoreFormat::Jks)
	} else if bytes.first() == Some(&0x30) {
		Some(StoreFormat::Pkcs12)
	} else {
		None
	};
	if expected != Some(inventory.format()) {
		return Err(ScanFailure::FormatMismatch);
	}
	Ok(ListedStore {
		inventory,
		notices,
		warnings,
	})
}

//------------------------------------------------------------------------------
/** 不完全な一覧を含まない失敗を作り、元ファイルへの変更がない状態で返します。 */
//------------------------------------------------------------------------------
fn failed(
	policy: &Policy,
	path: &Path,
	snapshot: Option<FileSnapshot>,
	issue: IssueCode,
	failure: ScanFailure,
) -> StoreScan {
	StoreScan {
		input_paths: vec![path.to_path_buf()],
		snapshot,
		report: ScanReport::failed(policy, issue),
		notices: Vec::new(),
		warnings: Vec::new(),
		failure: Some(failure),
	}
}
