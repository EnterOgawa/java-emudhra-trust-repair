//------------------------------------------------------------------------------
/*!
 * - ファイル: transaction.rs
 * - 概要: 検証済み診断から backup・順次適用・rollback・復元を実行します。
 * - バージョン: 01.01.00
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
 * Ver.01.00.00  Shunji Ogawa  2026/10/26  全件準備・順次置換・逆順 rollback・検証付き復元を追加。
 * Ver.01.00.01  Shunji Ogawa  2026/10/26  明示内部 QA で検証済 stage と DACL 保持後を観測。
 * Ver.01.00.02  Shunji Ogawa  2026/10/26  退避現物の競合を復元/rollback/次回照合でも拒否。
 * Ver.01.01.00  Shunji Ogawa  2026/10/26  選択Java内backupと保存時Javaの拘束、履歴の実保存先を追加。
 * ```
 *
 * 備考:
 *
 * 同期 worker 用です。複数 file 全体の atomicity や電源断時の完全永続化は保証しません。
 * 確定・rollback・復元確定中は cancel を受理せず終了まで待ちます。
 * 実行時の password は保持・保存しません。同権限の敵対的 process への防御境界ではありません。
 */
//------------------------------------------------------------------------------

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use trust_repair_core::{ChangePlan, MAX_INPUT_BYTES, PlanError, embedded_policy};

use crate::java::{JavaEnvironment, JavaError};
use crate::process::{Cancellation, ProcessError, StorePassword, delete_arguments, run_readonly};
use crate::scan::{ScanFailure, ScanGroup, list};
use crate::snapshot::{FileSafetyError, FileSnapshot, read_snapshot};
use crate::transaction_data::{
	Journal, JournalEvent, JournalStatus, MAX_STORES, Manifest, ManifestItem, SavedInventory,
	backup_name, load_manifest, read_journal, same_content_metadata, same_preserved_metadata,
	valid_id, work_directory, write_manifest, write_new,
};
use crate::transaction_io::{self as native, IoFailure};

// ID は時刻/process/同 process 内番号で作り、新規 directory の OS 排他でも衝突を拒否する
static NEXT_ID: AtomicU32 = AtomicU32::new(0);

/// 日英 UI が翻訳する、実際に実行している工程です。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionPhase {
	/// 診断・定義・Java・元実体を再検査しています。
	Validate,
	/// 別 instance と通常 write を抑止しています。
	Lock,
	/// 新規 backup と読戻しを確認しています。
	Backup,
	/// 同 volume stage にだけ削除し全件を照合しています。
	Stage,
	/// immutable manifest を保存しています。
	Prepare,
	/// journal を flush/sync しています。
	Journal,
	/// Windows 置換を実行しています。中断は受け付けません。
	Commit,
	/// 実 path の内容と metadata を再検査しています。
	Verify,
	/// 変更済み item を逆順で戻しています。中断は受け付けません。
	Rollback,
	/// 正規の復元を準備・実行しています。
	Restore,
	/// 履歴の整合性と現在の状態を調べています。
	History,
	/// 未完了 transaction を実体から復旧しています。
	Recovery,
	/// 全件の処理を終了しました。
	Complete,
}

/// transaction の主状態。自由文から成功を推測する必要はありません。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionState {
	/// 元対象を変更する前に終了しました。
	Aborted,
	/// 全 stage と manifest を保存しました。
	Prepared,
	/// 一件ずつ確定中です。
	Committing,
	/// 全件の適用と検証が成功しました。
	Applied,
	/// 逆順 rollback 中です。
	RollingBack,
	/// 変更前の byte/metadata を全件で確認しました。
	RolledBack,
	/// 復元中です。
	Restoring,
	/// 変更前の全件を復元・検証しました。
	Restored,
	/// 既に変更前の完全な状態です。対象の書換えを行っていません。
	AlreadyRestored,
	/// 部分状態または未知状態があり、自動上書きを止めました。
	RecoveryRequired,
}

/// 日英 UI 用の安定した失敗分類です。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionCode {
	/// 他のアプリ instance が対象を操作中です。
	Busy,
	/// 確定前に中断されました。
	Cancelled,
	/// 診断群と計画または password 数が一致しません。
	InvalidPlan,
	/// 選択した Java が診断/適用時から変わりました。
	StaleJava,
	/// Java 内 backup が保存時と異なる Java フォルダへ移動・コピーされています。
	BackupLocationMismatch,
	/// 診断後に元実体が変わりました。
	StaleScan,
	/// ファイルの安全性条件を満たしません。
	UnsafeFile,
	/// SACL/追加 metadata の不存在または保持を確認できません。
	UnsupportedMetadata,
	/// 書換え/置換に必要な権限がありません。
	PermissionDenied,
	/// ファイル操作または永続化の OS 失敗です。
	Io,
	/// keytool の起動/終了/警告/一覧解析を検証できません。
	Keytool,
	/// 差分、形式、全 inventory または metadata が一致しません。
	VerificationFailed,
	/// schema、ID、path、列挙値、重複等が不正です。
	InvalidManifest,
	/// journal の順序/状態/完全行が不正です。
	InvalidJournal,
	/// 元 backup の byte hash が一致しません。
	BackupCorrupt,
	/// 適用後の外部変更または未知実体があり上書きを拒否します。
	ExternalChange,
	/// 一意な自動復旧を決定できません。
	RecoveryRequired,
	/// 明示された試験境界での失敗です。
	InjectedFailure,
}

/// 書換えを試行した API の戻り値だけで判断せず調べた artifact の証拠です。
#[derive(Debug)]
pub struct ArtifactEvidence {
	/// 調べた target/stage/recovery の path。
	pub path: PathBuf,
	/// 安全な通常 file として読めた場合の全 byte hash。
	pub sha256: Option<String>,
	/// 読めない/欠落/未知属性の型付き理由。
	pub failure: Option<FileSafetyError>,
}

/// 元の失敗と rollback の失敗を両方保持する、UI 向けの失敗結果です。
#[derive(Debug)]
pub struct TransactionError {
	/// 翻訳可能な主分類。
	pub code: TransactionCode,
	/// 失敗した実工程。
	pub phase: TransactionPhase,
	/// この失敗後に確認できた群の状態。
	pub state: TransactionState,
	/// 大きい OS/診断詳細を所有する context。Deref でも各 field を参照できます。
	pub context: Box<TransactionContext>,
	/// 復旧の各失敗。主失敗を置き換えません。
	pub rollback_errors: Vec<TransactionError>,
}

/// エラーの対象・原因・置換失敗の現物証拠です。password は保持しません。
#[derive(Debug)]
pub struct TransactionContext {
	/// backup 作成後なら選択できる transaction ID。
	pub transaction_id: Option<String>,
	/// manifest/計画内の item 位置。
	pub item: Option<usize>,
	/// 関連 path。秘密や外部 stdout/stderr は含めません。
	pub path: Option<PathBuf>,
	/// 直接の Windows code。
	pub os_code: Option<i32>,
	/// 元のファイル安全性分類。
	pub file_error: Option<FileSafetyError>,
	/// 元のプロセス分類。
	pub process_error: Option<ProcessError>,
	/// 元の計画分類。
	pub plan_error: Option<PlanError>,
	/// 元の Java 分類。
	pub java_error: Option<JavaError>,
	/// 元の厳密一覧検証分類。
	pub scan_error: Option<ScanFailure>,
	/// 置換が失敗しても実 path/stage/recovery を調べた証拠。
	pub evidence: Vec<ArtifactEvidence>,
}

impl std::ops::Deref for TransactionError {
	type Target = TransactionContext;
	//------------------------------------------------------------------------------
	/** code/phase と同じ読みやすさで所有 context の field を参照します。 */
	//------------------------------------------------------------------------------
	fn deref(&self) -> &Self::Target {
		&self.context
	}
}

impl std::ops::DerefMut for TransactionError {
	//------------------------------------------------------------------------------
	/** 内部処理が最初の原因を失わず context を補足できる可変参照を返します。 */
	//------------------------------------------------------------------------------
	fn deref_mut(&mut self) -> &mut Self::Target {
		&mut self.context
	}
}

impl TransactionError {
	//------------------------------------------------------------------------------
	/** 秘密を含まない型付き失敗を、元対象を未変更の既定状態で生成します。 */
	//------------------------------------------------------------------------------
	pub(crate) fn new(code: TransactionCode, phase: TransactionPhase) -> Self {
		Self {
			code,
			phase,
			state: TransactionState::Aborted,
			context: Box::new(TransactionContext {
				transaction_id: None,
				item: None,
				path: None,
				os_code: None,
				file_error: None,
				process_error: None,
				plan_error: None,
				java_error: None,
				scan_error: None,
				evidence: Vec::new(),
			}),
			rollback_errors: Vec::new(),
		}
	}

	//------------------------------------------------------------------------------
	/** OS code と context を保持し、外部エラーの自由文を保存しません。 */
	//------------------------------------------------------------------------------
	pub(crate) fn io(phase: TransactionPhase, path: &Path, error: std::io::Error) -> Self {
		let mut value = Self::new(
			if error.kind() == std::io::ErrorKind::PermissionDenied {
				TransactionCode::PermissionDenied
			} else {
				TransactionCode::Io
			},
			phase,
		);
		value.path = Some(path.to_path_buf());
		value.os_code = error.raw_os_error();
		value
	}

	//------------------------------------------------------------------------------
	/** 元 snapshot の失敗分類を失わずに返します。 */
	//------------------------------------------------------------------------------
	pub(crate) fn file(phase: TransactionPhase, path: &Path, error: FileSafetyError) -> Self {
		let permission = matches!(
			&error,
			FileSafetyError::Io {
				os_code: Some(5 | 1300 | 1314),
				..
			}
		);
		let mut value = Self::new(
			if permission {
				TransactionCode::PermissionDenied
			} else {
				TransactionCode::UnsafeFile
			},
			phase,
		);
		value.path = Some(path.to_path_buf());
		value.file_error = Some(error);
		value
	}
}

impl std::fmt::Display for TransactionError {
	//------------------------------------------------------------------------------
	/** 開発向けに固定 code/工程だけを表示します。UI は公開 field から翻訳します。 */
	//------------------------------------------------------------------------------
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(
			formatter,
			"transaction {:?}: {:?} ({:?})",
			self.phase, self.code, self.state
		)
	}
}

impl std::error::Error for TransactionError {}

/// 同期 callback に通知する実工程です。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionProgress {
	/// 現在の工程。
	pub phase: TransactionPhase,
	/// 0 始まりの item 位置。群の工程は None。
	pub item: Option<usize>,
	/// 変更予定 item 総数。
	pub item_count: usize,
	/// この工程で cancel を受け付けるか。
	pub cancellable: bool,
}

/// 正常結果です。Applied/Restored は全件検証後にしか返しません。
#[derive(Debug)]
pub struct TransactionOutcome {
	/// 履歴と復元選択に使う ID。
	pub transaction_id: String,
	/// 検証済みの最終状態。
	pub state: TransactionState,
	/// 元 raw byte と証跡が残る directory。
	pub backup_directory: PathBuf,
	/// 実際の対象 path 一覧。
	pub stores: Vec<PathBuf>,
	/// UI が Java の再起動案内を表示する必要があります。
	pub restart_required: bool,
}

/// 実体から判別した item の現在状態です。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemState {
	/// 元の hash と保持 metadata/更新日時に一致します。
	Original,
	/// 記録した適用後 hash と保持 metadata/更新日時に一致します。
	Applied,
	/// path が欠落しています。
	Missing,
	/// 未知の内容/metadata、リンク、取得不能等です。
	Unknown,
}

/// journal と実体の両方を照合した履歴状態です。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryState {
	/// 完了記録と全適用後状態が一致します。
	Applied,
	/// 完了記録と全元状態が一致します。
	Restored,
	/// rollback 記録と全元状態が一致します。
	RolledBack,
	/// 未完了ですが、既知 hash/metadata から元へ一意に戻せます。
	Recoverable,
	/// 欠落/未知/整合性違反があり上書きしません。
	RecoveryRequired,
	/// manifest 保存前です。元 path を推測しません。
	IncompletePreparation,
	/// manifest/journal/保管 directory が不正です。
	Invalid,
}

/// 履歴選択前に得られる、秘密を持たない完全な検査結果です。
#[derive(Debug)]
pub struct TransactionInspection {
	/// directory と一致する ID。
	pub transaction_id: String,
	/// この検査を実行した元の backup directory。復元先設定を明示拘束します。
	pub backup_directory: PathBuf,
	/// 全群の判定。
	pub state: HistoryState,
	/// manifest の順の現在状態。
	pub items: Vec<ItemState>,
	/// password を再入力する対象 path の順序。
	pub stores: Vec<PathBuf>,
	/// 選択し直す Java root。
	pub java_root: PathBuf,
	/// journal 末尾に破断がありました。
	pub torn_journal: bool,
	/// 保存した release/java/keytool の現在 snapshot も一致するか。
	pub java_unchanged: bool,
}

/// 不正な一件があっても他の履歴を隠さない列挙結果です。
#[derive(Debug)]
pub struct HistoryEntry {
	/// 選択できる directory 名。
	pub transaction_id: String,
	/// 正常な検査結果または型付き拒否理由。
	pub inspection: Result<TransactionInspection, TransactionError>,
}

/// I/O 失敗の契約を隔離試験する境界です。GUI の操作には使いません。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureBoundary {
	/// 元 backup 保存直後。
	Backup,
	/// stage 検証直後。
	Stage,
	/// immutable manifest 保存直後。
	Manifest,
	/// journal の各追記直前。
	Journal,
	/// target の置換直前。
	BeforeCommit,
	/// target の置換・検証直後。
	AfterCommit,
	/// 逆順 rollback 直前。
	BeforeRollback,
	/// 復元置換直前。
	BeforeRestore,
	/// 復元置換・検証直後。
	AfterRestore,
}

/// 一つの明示的な失敗注入指定です。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailurePoint {
	/// 注入する境界。
	pub boundary: FailureBoundary,
	/// item の位置。群の境界は None。
	pub item: Option<usize>,
}

/// 保管場所と試験注入だけを持つ設定です。password は含みません。
#[derive(Debug, Clone)]
pub struct TransactionOptions {
	/// 新規GUI操作では選択Java内の emudhra-backup。
	backup_root: PathBuf,
	/// Java内rootを選択した場合にだけ要求する保存時Java。
	java_root: Option<PathBuf>,
	/// 隔離検証のため明示した失敗境界。
	failures: Vec<FailurePoint>,
}

impl TransactionOptions {
	//------------------------------------------------------------------------------
	/** 選択済みJava内の固定backup rootへ拘束します。読み取りやdirectory作成は行いません。 */
	//------------------------------------------------------------------------------
	pub fn for_java(environment: &JavaEnvironment) -> Result<Self, TransactionError> {
		let mut options = Self::with_backup_root(environment.root().join("emudhra-backup"))?;
		options.java_root = Some(environment.root().to_path_buf());
		Ok(options)
	}

	//------------------------------------------------------------------------------
	/** 従来版の本人用backup rootを参照します。互換履歴用で、directoryを作りません。 */
	//------------------------------------------------------------------------------
	pub fn local_app_data() -> Result<Self, TransactionError> {
		let base = std::env::var_os("LOCALAPPDATA")
			.ok_or_else(|| TransactionError::new(TransactionCode::Io, TransactionPhase::Backup))?;
		Self::with_backup_root(PathBuf::from(base).join("EnterSystem/JavaTrustRepair/backups"))
	}

	//------------------------------------------------------------------------------
	/** 明示した専用 root を使います。隔離試験に利用でき、既存 ACL を広げることはありません。 */
	//------------------------------------------------------------------------------
	pub fn with_backup_root(backup_root: PathBuf) -> Result<Self, TransactionError> {
		if !crate::transaction_data::valid_path(&backup_root) {
			return Err(TransactionError::new(
				TransactionCode::InvalidManifest,
				TransactionPhase::Backup,
			));
		}
		Ok(Self {
			backup_root,
			java_root: None,
			failures: Vec::new(),
		})
	}

	//------------------------------------------------------------------------------
	/** 適用前の UI に表示できる保管 root を返します。 */
	//------------------------------------------------------------------------------
	pub fn backup_root(&self) -> &Path {
		&self.backup_root
	}

	//------------------------------------------------------------------------------
	/** 隔離試験の境界を追加します。通常の GUI はこの設定を行いません。 */
	//------------------------------------------------------------------------------
	pub fn with_failure(mut self, point: FailurePoint) -> Self {
		self.failures.push(point);
		self
	}

	//------------------------------------------------------------------------------
	/** 明示された境界だけを失敗させます。設定がなければ副作用を持ちません。 */
	//------------------------------------------------------------------------------
	fn check(
		&self,
		boundary: FailureBoundary,
		item: Option<usize>,
		phase: TransactionPhase,
	) -> Result<(), TransactionError> {
		if self.failures.contains(&FailurePoint { boundary, item }) {
			let mut error = TransactionError::new(TransactionCode::InjectedFailure, phase);
			error.item = item;
			return Err(error);
		}
		Ok(())
	}
}

//------------------------------------------------------------------------------
/**
 * 検証済み ScanGroup と同じ ChangePlan だけを適用します。password は group の順です。
 * 全群/Java/元 snapshot を再検査し、全 stage を検証後に順次確定します。
 * 失敗時は変更済みを逆順で戻し、失敗が重なっても元の原因を保持します。
 * progress は同じ worker で呼び出します。確定開始後の cancel は受け付けません。
 * backup/stage/recovery/journal は失敗後も削除せず、実運用の同時更新停止が必要です。
 */
//------------------------------------------------------------------------------
pub fn apply_transaction(
	environment: &JavaEnvironment,
	group: &ScanGroup,
	plan: &ChangePlan,
	passwords: &[&StorePassword],
	options: &TransactionOptions,
	cancellation: &Cancellation,
	mut progress: impl FnMut(TransactionProgress),
) -> Result<TransactionOutcome, TransactionError> {
	let count = plan.stores().len();
	if options
		.java_root
		.as_deref()
		.is_some_and(|root| root != environment.root())
	{
		return Err(TransactionError::new(
			TransactionCode::BackupLocationMismatch,
			TransactionPhase::Validate,
		));
	}
	notify(&mut progress, TransactionPhase::Validate, None, count, true);
	check_cancel(cancellation)?;
	let policy = embedded_policy().map_err(|_| {
		TransactionError::new(TransactionCode::InvalidPlan, TransactionPhase::Validate)
	})?;
	let rebuilt = group.plan(&policy).map_err(|error| {
		let mut value =
			TransactionError::new(TransactionCode::InvalidPlan, TransactionPhase::Validate);
		value.plan_error = Some(error);
		value
	})?;
	if rebuilt != *plan
		|| passwords.len() != group.stores().len()
		|| group.stores().len() > MAX_STORES
		|| environment.snapshots() != group.java_snapshots()
		|| !environment.issues().is_empty()
		|| group.stores().iter().any(|store| {
			store.failure().is_some() || !store.warnings().is_empty() || store.snapshot().is_none()
		}) {
		return Err(TransactionError::new(
			TransactionCode::InvalidPlan,
			TransactionPhase::Validate,
		));
	}
	validate_group(environment, group, &BTreeSet::new())?;
	notify(&mut progress, TransactionPhase::Lock, None, count, true);
	let mut lock_paths: Vec<_> = group
		.stores()
		.iter()
		.filter_map(|store| store.snapshot().map(|snapshot| snapshot.canonical_path()))
		.collect();
	lock_paths.sort();
	let mut locks = Vec::new();
	// 全群を lock し、同一アプリ内と別 instance の重複操作を抑止する
	for path in lock_paths {
		locks.push(
			native::target_lock(path)
				.map_err(|error| native_error(TransactionPhase::Lock, path, error))?,
		);
	}
	let mut guards = Vec::new();
	// 元 file に一切書かず、必要な write/delete 権限と metadata 対応を確認する
	for planned in plan.stores() {
		let original = group.stores()[planned.report_index()]
			.snapshot()
			.ok_or_else(|| {
				TransactionError::new(TransactionCode::InvalidPlan, TransactionPhase::Validate)
			})?;
		let path = original.canonical_path();
		guards.push(
			native::write_guard(path)
				.map_err(|error| native_error(TransactionPhase::Lock, path, error))?,
		);
		native::check_supported_metadata(path)
			.map_err(|error| native_error(TransactionPhase::Validate, path, error))?;
	}
	validate_group(environment, group, &BTreeSet::new())?;
	// Java内の既存rootに未知fileや別Javaの記録があれば、新しい処理を混在させない
	if options.java_root.is_some() {
		for entry in list_history(options)? {
			let inspection = entry.inspection?;
			if inspection.state == HistoryState::IncompletePreparation {
				let mut error = TransactionError::new(
					TransactionCode::RecoveryRequired,
					TransactionPhase::Backup,
				);
				error.path = Some(inspection.backup_directory);
				return Err(error);
			}
		}
	}
	let root = native::prepare_root(&options.backup_root)
		.map_err(|error| native_error(TransactionPhase::Backup, &options.backup_root, error))?;
	let id = new_id()?;
	let directory = root.join(&id);
	native::create_private_directory(&directory)
		.map_err(|error| native_error(TransactionPhase::Backup, &directory, error))?;
	let mut journal = None;
	let mut manifest = Manifest {
		schema_version: 1,
		transaction_id: id.clone(),
		app_version: env!("CARGO_PKG_VERSION").to_owned(),
		policy_id: policy.id().to_owned(),
		policy_hashes: policy
			.roots()
			.iter()
			.map(|root| root.sha256().to_owned())
			.collect(),
		java_root: environment.root().to_path_buf(),
		java: environment.snapshots().clone(),
		items: Vec::new(),
	};
	let mut attempted = Vec::new();
	let result = (|| {
		let preparation = serde_json::json!({
			"schema_version": 1, "transaction_id": id, "policy_id": policy.id(),
			"java": environment.snapshots(),
			"stores": plan.stores().iter().map(|planned| Ok(serde_json::json!({
				"original": group.stores()[planned.report_index()].snapshot(),
				"inventory": SavedInventory::from_inventory(planned.original())?,
				"deletions": planned.deletions().iter().map(|deletion| (deletion.alias(), deletion.sha256(), deletion.policy_root_id())).collect::<Vec<_>>()
			}))).collect::<Result<Vec<_>, TransactionError>>()?
		});
		let preparation = serde_json::to_vec_pretty(&preparation).map_err(|_| {
			TransactionError::new(TransactionCode::InvalidManifest, TransactionPhase::Backup)
		})?;
		if preparation.len() > crate::transaction_data::MAX_DOCUMENT_BYTES {
			return Err(TransactionError::new(
				TransactionCode::InvalidManifest,
				TransactionPhase::Backup,
			));
		}
		let preparation_path = directory.join("preparation.json");
		write_new(&preparation_path, &preparation, TransactionPhase::Backup)?;
		let (_, read_back) = read_snapshot(
			&preparation_path,
			crate::transaction_data::MAX_DOCUMENT_BYTES,
		)
		.map_err(|error| {
			TransactionError::file(TransactionPhase::Backup, &preparation_path, error)
		})?;
		if read_back != preparation {
			return Err(TransactionError::new(
				TransactionCode::VerificationFailed,
				TransactionPhase::Backup,
			));
		}
		// 全件の raw backup と stage を準備し、元 target を keytool-delete に渡さない
		for (index, planned) in plan.stores().iter().enumerate() {
			check_cancel(cancellation)?;
			let source = group.stores()[planned.report_index()]
				.snapshot()
				.ok_or_else(|| {
					TransactionError::new(TransactionCode::InvalidPlan, TransactionPhase::Validate)
				})?;
			let target = source.canonical_path();
			if target.starts_with(&root) {
				return Err(TransactionError::new(
					TransactionCode::InvalidPlan,
					TransactionPhase::Validate,
				));
			}
			notify(
				&mut progress,
				TransactionPhase::Backup,
				Some(index),
				count,
				true,
			);
			let (original, bytes) = snapshot(target, TransactionPhase::Backup)?;
			if original != *source {
				return Err(TransactionError::new(
					TransactionCode::StaleScan,
					TransactionPhase::Backup,
				));
			}
			let backup = directory.join(backup_name(index));
			write_new(&backup, &bytes, TransactionPhase::Backup)?;
			verify_raw_backup(&backup, source)?;
			let before = SavedInventory::from_inventory(planned.original())?;
			verify_inventory(
				environment,
				&backup,
				passwords[planned.report_index()],
				cancellation,
				&before,
				TransactionPhase::Backup,
			)?;
			options.check(
				FailureBoundary::Backup,
				Some(index),
				TransactionPhase::Backup,
			)?;
			notify(
				&mut progress,
				TransactionPhase::Stage,
				Some(index),
				count,
				true,
			);
			let work = work_directory(target, &id, index)?;
			native::create_private_directory(&work)
				.map_err(|error| native_error(TransactionPhase::Stage, &work, error))?;
			let stage = work.join("apply.stage");
			native::create_stage(&stage, &bytes, source, true)
				.map_err(|error| native_error(TransactionPhase::Stage, &stage, error))?;
			let (copied, _) = snapshot(&stage, TransactionPhase::Stage)?;
			if !same_content_metadata(&copied.clone().at_path(target.to_path_buf()), source) {
				return Err(TransactionError::new(
					TransactionCode::VerificationFailed,
					TransactionPhase::Stage,
				));
			}
			// 各別名は完全 inventory/DER 定義で確定済みで、同じ証明書の重複もすべて削除する
			for deletion in planned.deletions() {
				validate_java(environment)?;
				let output = run_readonly(
					environment.keytool(),
					&delete_arguments(&stage, deletion.alias()),
					Some(passwords[planned.report_index()]),
					cancellation,
				)
				.map_err(|error| process_error(TransactionPhase::Stage, &stage, error))?;
				if !output.stdout.trim().is_empty() || !output.stderr.trim().is_empty() {
					return Err(TransactionError::new(
						TransactionCode::Keytool,
						TransactionPhase::Stage,
					));
				}
			}
			native::finish_stage(&stage, source)
				.map_err(|error| native_error(TransactionPhase::Stage, &stage, error))?;
			let after = before.without_targets(&policy);
			if before.entries.len().checked_sub(planned.deletions().len())
				!= Some(after.entries.len())
			{
				return Err(TransactionError::new(
					TransactionCode::VerificationFailed,
					TransactionPhase::Stage,
				));
			}
			verify_inventory(
				environment,
				&stage,
				passwords[planned.report_index()],
				cancellation,
				&after,
				TransactionPhase::Stage,
			)?;
			native::check_supported_metadata(&stage)
				.map_err(|error| native_error(TransactionPhase::Stage, &stage, error))?;
			let (prepared, _) = snapshot(&stage, TransactionPhase::Stage)?;
			if !same_preserved_metadata(&prepared, source)
				|| prepared.identity().volume_serial != source.identity().volume_serial
			{
				return Err(TransactionError::new(
					TransactionCode::VerificationFailed,
					TransactionPhase::Stage,
				));
			}
			let deletions = before
				.entries
				.iter()
				.filter(|entry| !after.entries.contains(entry))
				.cloned()
				.collect();
			manifest.items.push(ManifestItem {
				original: source.clone(),
				applied: prepared.at_path(target.to_path_buf()),
				before,
				after,
				deletions,
				backup_name: backup_name(index),
				work_name: format!(".jtr-{id}-{index:04}"),
				stage_name: "apply.stage".to_owned(),
				recovery_name: "apply.recovery".to_owned(),
			});
			options.check(FailureBoundary::Stage, Some(index), TransactionPhase::Stage)?;
			#[cfg(feature = "internal-qa")]
			crate::qa_checkpoint("stage-verified", Some(index));
		}
		check_cancel(cancellation)?;
		manifest.validate(&id, &root)?;
		notify(&mut progress, TransactionPhase::Prepare, None, count, true);
		write_manifest(&directory.join("manifest.json"), &manifest)?;
		options.check(FailureBoundary::Manifest, None, TransactionPhase::Prepare)?;
		journal = Some(Journal::create(&directory.join("journal.jsonl"))?);
		append(journal.as_mut(), options, JournalEvent::Prepared, None)?;
		validate_group(environment, group, &BTreeSet::new())?;
		check_cancel(cancellation)?;
		append(journal.as_mut(), options, JournalEvent::Committing, None)?;
		let committed_cancel = Cancellation::default();
		let mut changed_reports = BTreeSet::new();
		// 全件準備後だけ順次確定する。ここからは cancel による部分中止を行わない
		for (index, item) in manifest.items.iter().enumerate() {
			notify(
				&mut progress,
				TransactionPhase::Commit,
				Some(index),
				count,
				false,
			);
			validate_group(environment, group, &changed_reports)?;
			options.check(
				FailureBoundary::BeforeCommit,
				Some(index),
				TransactionPhase::Commit,
			)?;
			append(
				journal.as_mut(),
				options,
				JournalEvent::ReplaceStarted,
				Some(index),
			)?;
			let target = item.original.canonical_path();
			let work = work_directory(target, &id, index)?;
			let stage = work.join("apply.stage");
			let recovery = work.join("apply.recovery");
			native::check_supported_metadata(target)
				.map_err(|error| native_error(TransactionPhase::Commit, target, error))?;
			attempted.push(index);
			if let Err(failure) = native::replace(target, &stage, &recovery) {
				let mut error = native_error(TransactionPhase::Commit, target, failure);
				error.evidence = inspect_artifacts(&[target, &stage, &recovery]);
				return Err(error);
			}
			finish_replacement(target, &item.applied, &item.original)?;
			verify_recovery_copy(&recovery, &item.original)?;
			guards[index] = native::write_guard(target)
				.map_err(|error| native_error(TransactionPhase::Verify, target, error))?;
			notify(
				&mut progress,
				TransactionPhase::Verify,
				Some(index),
				count,
				false,
			);
			verify_target(
				environment,
				item,
				passwords[plan.stores()[index].report_index()],
				&committed_cancel,
				false,
				true,
			)?;
			append(
				journal.as_mut(),
				options,
				JournalEvent::ReplaceVerified,
				Some(index),
			)?;
			changed_reports.insert(plan.stores()[index].report_index());
			options.check(
				FailureBoundary::AfterCommit,
				Some(index),
				TransactionPhase::Verify,
			)?;
		}
		validate_group(environment, group, &changed_reports)?;
		// 最初の置換後の細かな同時更新も、全群終了時の開き直しで検査する
		for item in &manifest.items {
			verify_snapshot(
				item.original.canonical_path(),
				&item.applied,
				true,
				TransactionPhase::Verify,
			)?;
		}
		append(journal.as_mut(), options, JournalEvent::Applied, None)?;
		Ok(())
	})();
	if let Err(mut error) = result {
		error.transaction_id = Some(id.clone());
		if !attempted.is_empty() {
			error.rollback_errors = rollback_apply(
				ApplyRollback {
					environment,
					manifest: &manifest,
					directory: &directory,
					plan,
					passwords,
					options,
					journal: journal.as_mut(),
					attempted: &attempted,
				},
				&mut progress,
			);
			error.state = if error.rollback_errors.is_empty() {
				TransactionState::RolledBack
			} else {
				TransactionState::RecoveryRequired
			};
		}
		return Err(error);
	}
	notify(
		&mut progress,
		TransactionPhase::Complete,
		None,
		count,
		false,
	);
	Ok(outcome(&manifest, &directory, TransactionState::Applied))
}

/// 適用の逆順復旧で同じ寿命を持つ借用をまとめます。
struct ApplyRollback<'a, 'password> {
	/// 同じ Java。
	environment: &'a JavaEnvironment,
	/// 固定済み計画。
	manifest: &'a Manifest,
	/// raw backup の保管場所。
	directory: &'a Path,
	/// 元の群との対応。
	plan: &'a ChangePlan,
	/// 操作時だけ供給する password。
	passwords: &'a [&'password StorePassword],
	/// 失敗注入条件。
	options: &'a TransactionOptions,
	/// 同じ永続 writer。
	journal: Option<&'a mut Journal>,
	/// 置換を試行した順序。
	attempted: &'a [usize],
}

//------------------------------------------------------------------------------
/** 変更済み/置換試行済みの対象だけを逆順で戻します。未知内容は上書きしません。 */
//------------------------------------------------------------------------------
fn rollback_apply(
	context: ApplyRollback<'_, '_>,
	progress: &mut impl FnMut(TransactionProgress),
) -> Vec<TransactionError> {
	let ApplyRollback {
		environment,
		manifest,
		directory,
		plan,
		passwords,
		options,
		mut journal,
		attempted,
	} = context;
	let mut errors = Vec::new();
	if let Err(error) = append(
		journal.as_deref_mut(),
		options,
		JournalEvent::RollingBack,
		None,
	) {
		errors.push(error);
	}
	let cancellation = Cancellation::default();
	// 一つの復旧失敗で他の変更済み対象の復旧を放棄しない
	for &index in attempted.iter().rev() {
		notify(
			progress,
			TransactionPhase::Rollback,
			Some(index),
			manifest.items.len(),
			false,
		);
		let result = (|| {
			options.check(
				FailureBoundary::BeforeRollback,
				Some(index),
				TransactionPhase::Rollback,
			)?;
			let item = &manifest.items[index];
			let target = item.original.canonical_path();
			let state = classify(item);
			if conflicting_artifacts(&manifest.transaction_id, index, item, None) {
				return Err(TransactionError::new(
					TransactionCode::ExternalChange,
					TransactionPhase::Rollback,
				));
			}
			if state == ItemState::Original {
				return verify_target(
					environment,
					item,
					passwords[plan.stores()[index].report_index()],
					&cancellation,
					true,
					false,
				);
			}
			let work = work_directory(target, &manifest.transaction_id, index)?;
			let missing = state == ItemState::Missing;
			if state != ItemState::Applied
				&& !(missing
					&& verify_recovery_copy(&work.join("apply.recovery"), &item.original).is_ok())
			{
				return Err(TransactionError::new(
					TransactionCode::ExternalChange,
					TransactionPhase::Rollback,
				));
			}
			append(
				journal.as_deref_mut(),
				options,
				JournalEvent::RollbackStarted,
				Some(index),
			)?;
			let bytes = verify_raw_backup(&directory.join(&item.backup_name), &item.original)?;
			let stage = work.join("rollback.stage");
			native::create_stage(&stage, &bytes, &item.original, true)
				.map_err(|error| native_error(TransactionPhase::Rollback, &stage, error))?;
			verify_inventory(
				environment,
				&stage,
				passwords[plan.stores()[index].report_index()],
				&cancellation,
				&item.before,
				TransactionPhase::Rollback,
			)?;
			let (prepared, _) = snapshot(&stage, TransactionPhase::Rollback)?;
			if missing {
				native::move_to_missing(&stage, target)
					.map_err(|error| native_error(TransactionPhase::Rollback, target, error))?;
			} else {
				verify_snapshot(target, &item.applied, false, TransactionPhase::Rollback)?;
				let recovery = work.join("rollback.recovery");
				if let Err(failure) = native::replace(target, &stage, &recovery) {
					let mut error = native_error(TransactionPhase::Rollback, target, failure);
					error.evidence = inspect_artifacts(&[target, &stage, &recovery]);
					return Err(error);
				}
				verify_displaced_copy(&recovery, &item.applied)?;
			}
			finish_replacement(target, &prepared, &item.original)?;
			verify_target(
				environment,
				item,
				passwords[plan.stores()[index].report_index()],
				&cancellation,
				true,
				false,
			)?;
			append(
				journal.as_deref_mut(),
				options,
				JournalEvent::RollbackVerified,
				Some(index),
			)
		})();
		if let Err(mut error) = result {
			error.item = Some(index);
			errors.push(error);
		}
	}
	let final_event = if errors.is_empty() {
		JournalEvent::RolledBack
	} else {
		JournalEvent::RecoveryRequired
	};
	if let Err(error) = append(journal, options, final_event, None) {
		errors.push(error);
	}
	errors
}

//------------------------------------------------------------------------------
/** Java の既存の実体/hash/metadata を検査し、UI 向け分類を保持します。 */
//------------------------------------------------------------------------------
fn validate_java(environment: &JavaEnvironment) -> Result<(), TransactionError> {
	environment.revalidate().map_err(|error| {
		let mut value =
			TransactionError::new(TransactionCode::StaleJava, TransactionPhase::Validate);
		value.java_error = Some(error);
		value
	})
}

//------------------------------------------------------------------------------
/** 変更済み以外の全群と Java を再検査します。対象ゼロのストアも省略しません。 */
//------------------------------------------------------------------------------
fn validate_group(
	environment: &JavaEnvironment,
	group: &ScanGroup,
	changed: &BTreeSet<usize>,
) -> Result<(), TransactionError> {
	validate_java(environment)?;
	for (index, store) in group.stores().iter().enumerate() {
		if changed.contains(&index) {
			continue;
		}
		let snapshot = store.snapshot().ok_or_else(|| {
			TransactionError::new(TransactionCode::InvalidPlan, TransactionPhase::Validate)
		})?;
		snapshot.revalidate(MAX_INPUT_BYTES).map_err(|error| {
			let mut value = TransactionError::file(
				TransactionPhase::Validate,
				snapshot.canonical_path(),
				error,
			);
			if value.code != TransactionCode::PermissionDenied {
				value.code = TransactionCode::StaleScan;
			}
			value.item = Some(index);
			value
		})?;
	}
	Ok(())
}

//------------------------------------------------------------------------------
/** 全 inventory と通常の metadata を実 path から再取得し、期待状態と照合します。 */
//------------------------------------------------------------------------------
fn verify_target(
	environment: &JavaEnvironment,
	item: &ManifestItem,
	password: &StorePassword,
	cancellation: &Cancellation,
	original: bool,
	identity: bool,
) -> Result<(), TransactionError> {
	let expected = if original {
		&item.original
	} else {
		&item.applied
	};
	let inventory = if original { &item.before } else { &item.after };
	let path = item.original.canonical_path();
	verify_snapshot(path, expected, identity, TransactionPhase::Verify)?;
	verify_inventory(
		environment,
		path,
		password,
		cancellation,
		inventory,
		TransactionPhase::Verify,
	)?;
	native::check_supported_metadata(path)
		.map_err(|error| native_error(TransactionPhase::Verify, path, error))?;
	verify_snapshot(path, expected, identity, TransactionPhase::Verify)
}

//------------------------------------------------------------------------------
/** 同じ厳密 list を stage/実 path/backup に使用し、全別名・種別・DER hash・形式を照合します。 */
//------------------------------------------------------------------------------
fn verify_inventory(
	environment: &JavaEnvironment,
	path: &Path,
	password: &StorePassword,
	cancellation: &Cancellation,
	expected: &SavedInventory,
	phase: TransactionPhase,
) -> Result<(), TransactionError> {
	validate_java(environment)?;
	let (before, _) = snapshot(path, phase)?;
	let listed = list(environment, &before, password, cancellation).map_err(|error| {
		let code = if matches!(error, ScanFailure::Process(ProcessError::Cancelled)) {
			TransactionCode::Cancelled
		} else {
			TransactionCode::Keytool
		};
		let mut value = TransactionError::new(code, phase);
		value.path = Some(path.to_path_buf());
		value.scan_error = Some(error);
		value
	})?;
	if !listed.warnings.is_empty()
		|| SavedInventory::from_inventory(&listed.inventory)? != *expected
	{
		return Err(TransactionError::new(
			TransactionCode::VerificationFailed,
			phase,
		));
	}
	before
		.revalidate(MAX_INPUT_BYTES)
		.map_err(|error| TransactionError::file(phase, path, error))
}

//------------------------------------------------------------------------------
/** 元 backup を読戻し、内容と上限を照合します。backup の ACL は対象へコピーしません。 */
//------------------------------------------------------------------------------
fn verify_raw_backup(path: &Path, original: &FileSnapshot) -> Result<Vec<u8>, TransactionError> {
	let (actual, bytes) = snapshot(path, TransactionPhase::Backup)?;
	if actual.sha256() != original.sha256() || actual.length() != original.length() {
		let mut error =
			TransactionError::new(TransactionCode::BackupCorrupt, TransactionPhase::Backup);
		error.path = Some(path.to_path_buf());
		return Err(error);
	}
	Ok(bytes)
}

//------------------------------------------------------------------------------
/** 同 volume recovery copy が本当に元実体であるか、hash/ID/metadata を照合します。 */
//------------------------------------------------------------------------------
fn verify_recovery_copy(path: &Path, expected: &FileSnapshot) -> Result<(), TransactionError> {
	native::check_supported_metadata(path)
		.map_err(|error| native_error(TransactionPhase::Verify, path, error))?;
	let (actual, _) = snapshot(path, TransactionPhase::Verify)?;
	if actual.identity() != expected.identity()
		|| !same_content_metadata(
			&actual.at_path(expected.canonical_path().to_path_buf()),
			expected,
		) {
		let mut error =
			TransactionError::new(TransactionCode::ExternalChange, TransactionPhase::Verify);
		error.path = Some(path.to_path_buf());
		error.evidence = inspect_artifacts(&[path]);
		return Err(error);
	}
	Ok(())
}

//------------------------------------------------------------------------------
/** 置換で実際に退避された file を照合し、競合した未知内容の場所をエラー証拠へ残します。 */
//------------------------------------------------------------------------------
fn verify_displaced_copy(path: &Path, expected: &FileSnapshot) -> Result<(), TransactionError> {
	native::check_supported_metadata(path)
		.map_err(|error| native_error(TransactionPhase::Verify, path, error))?;
	verify_snapshot(
		path,
		&expected.clone().at_path(path.to_path_buf()),
		false,
		TransactionPhase::Verify,
	)
	.map_err(|mut error| {
		error.evidence = inspect_artifacts(&[path]);
		error
	})
}

//------------------------------------------------------------------------------
/** 既存の退避物が期待内容と矛盾したら自動上書きを禁止します。未知の証拠は削除しません。 */
//------------------------------------------------------------------------------
fn conflicting_artifacts(
	id: &str,
	index: usize,
	item: &ManifestItem,
	operation: Option<&str>,
) -> bool {
	let Ok(work) = work_directory(item.original.canonical_path(), id, index) else {
		return true;
	};
	let mut copies = vec![
		(work.join("apply.recovery"), &item.original),
		(work.join("rollback.recovery"), &item.applied),
	];
	if let Some(operation) = operation {
		copies.push((
			work.join(format!("{operation}.restore.recovery")),
			&item.applied,
		));
		copies.push((
			work.join(format!("{operation}.undo.recovery")),
			&item.original,
		));
	}
	copies.into_iter().any(|(path, expected)| {
		// NotFound 以外の取得失敗や link も、存在しない証拠として無視しない
		match fs::symlink_metadata(&path) {
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
			Err(_) => true,
			Ok(_) => verify_displaced_copy(&path, expected).is_err(),
		}
	})
}

//------------------------------------------------------------------------------
/** file ID を要求するかを明示し、hash/metadata の一致しない path は拒否します。 */
//------------------------------------------------------------------------------
fn verify_snapshot(
	path: &Path,
	expected: &FileSnapshot,
	identity: bool,
	phase: TransactionPhase,
) -> Result<(), TransactionError> {
	let (actual, _) = snapshot(path, phase)?;
	if !same_content_metadata(&actual, expected)
		|| identity && actual.identity() != expected.identity()
	{
		let mut error = TransactionError::new(TransactionCode::ExternalChange, phase);
		error.path = Some(path.to_path_buf());
		return Err(error);
	}
	Ok(())
}

//------------------------------------------------------------------------------
/** 置換した stage 本体と確認してから、元の DACL を保持します。未知実体へ権限を設定しません。 */
//------------------------------------------------------------------------------
fn finish_replacement(
	path: &Path,
	prepared: &FileSnapshot,
	original: &FileSnapshot,
) -> Result<(), TransactionError> {
	let (actual, _) = snapshot(path, TransactionPhase::Verify)?;
	if actual.identity() != prepared.identity() || actual.sha256() != prepared.sha256() {
		return Err(TransactionError::new(
			TransactionCode::ExternalChange,
			TransactionPhase::Verify,
		));
	}
	if !native::same_security(actual.security_descriptor(), original.security_descriptor()) {
		native::preserve_dacl(path, original)
			.map_err(|error| native_error(TransactionPhase::Verify, path, error))?;
	}
	#[cfg(feature = "internal-qa")]
	crate::qa_checkpoint("dacl-preserved", None);
	Ok(())
}

//------------------------------------------------------------------------------
/** 型付き file 検査を容量上限付きで実行します。 */
//------------------------------------------------------------------------------
fn snapshot(
	path: &Path,
	phase: TransactionPhase,
) -> Result<(FileSnapshot, Vec<u8>), TransactionError> {
	read_snapshot(path, MAX_INPUT_BYTES).map_err(|error| TransactionError::file(phase, path, error))
}

//------------------------------------------------------------------------------
/** 実体と metadata が既知のどちらにも一致しない場合は Unknown とし上書きを許しません。 */
//------------------------------------------------------------------------------
fn classify(item: &ManifestItem) -> ItemState {
	match read_snapshot(item.original.canonical_path(), MAX_INPUT_BYTES) {
		Ok((actual, _))
			if native::check_supported_metadata(item.original.canonical_path()).is_ok()
				&& same_content_metadata(&actual, &item.original) =>
		{
			ItemState::Original
		}
		Ok((actual, _))
			if native::check_supported_metadata(item.original.canonical_path()).is_ok()
				&& same_content_metadata(&actual, &item.applied) =>
		{
			ItemState::Applied
		}
		Err(FileSafetyError::Io {
			os_code: Some(2 | 3),
			..
		}) => ItemState::Missing,
		_ => ItemState::Unknown,
	}
}

//------------------------------------------------------------------------------
/** 置換失敗でも三つの実体を調べ、欠落/未知を成功扱いしない証拠を所有します。 */
//------------------------------------------------------------------------------
fn inspect_artifacts(paths: &[&Path]) -> Vec<ArtifactEvidence> {
	paths
		.iter()
		.map(|path| match read_snapshot(path, MAX_INPUT_BYTES) {
			Ok((value, _)) => ArtifactEvidence {
				path: path.to_path_buf(),
				sha256: Some(value.sha256().to_owned()),
				failure: None,
			},
			Err(error) => ArtifactEvidence {
				path: path.to_path_buf(),
				sha256: None,
				failure: Some(error),
			},
		})
		.collect()
}

//------------------------------------------------------------------------------
/** 注入と永続追記を一箇所で実行します。journal がない場合は確定できません。 */
//------------------------------------------------------------------------------
fn append(
	journal: Option<&mut Journal>,
	options: &TransactionOptions,
	event: JournalEvent,
	item: Option<usize>,
) -> Result<(), TransactionError> {
	options.check(FailureBoundary::Journal, item, TransactionPhase::Journal)?;
	journal
		.ok_or_else(|| {
			TransactionError::new(TransactionCode::InvalidJournal, TransactionPhase::Journal)
		})?
		.append(event, item)
}

//------------------------------------------------------------------------------
/** 本人用の一意 ID を生成します。時刻異常でも既存 directory は上書きしません。 */
//------------------------------------------------------------------------------
fn new_id() -> Result<String, TransactionError> {
	let nanos = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map_err(|_| TransactionError::new(TransactionCode::Io, TransactionPhase::Prepare))?
		.as_nanos();
	Ok(format!(
		"tx-{nanos:032x}-{:08x}-{:08x}",
		std::process::id(),
		NEXT_ID.fetch_add(1, Ordering::Relaxed)
	))
}

//------------------------------------------------------------------------------
/** 確定前だけ利用者の cancel を受理します。 */
//------------------------------------------------------------------------------
fn check_cancel(cancellation: &Cancellation) -> Result<(), TransactionError> {
	if cancellation.is_cancelled() {
		Err(TransactionError::new(
			TransactionCode::Cancelled,
			TransactionPhase::Validate,
		))
	} else {
		Ok(())
	}
}

//------------------------------------------------------------------------------
/** 時間から百分率を捏造せず、実際の工程を callback へ渡します。 */
//------------------------------------------------------------------------------
fn notify(
	progress: &mut impl FnMut(TransactionProgress),
	phase: TransactionPhase,
	item: Option<usize>,
	item_count: usize,
	cancellable: bool,
) {
	progress(TransactionProgress {
		phase,
		item,
		item_count,
		cancellable,
	});
}

//------------------------------------------------------------------------------
/** native 分類を UI 用 code へ写し、OS code を保持します。 */
//------------------------------------------------------------------------------
fn native_error(phase: TransactionPhase, path: &Path, failure: IoFailure) -> TransactionError {
	let code = if failure.busy {
		TransactionCode::Busy
	} else if failure.unsupported_metadata {
		TransactionCode::UnsupportedMetadata
	} else if matches!(failure.os_code, Some(5 | 1300 | 1314)) {
		TransactionCode::PermissionDenied
	} else {
		TransactionCode::Io
	};
	let mut error = TransactionError::new(code, phase);
	error.path = Some(path.to_path_buf());
	error.os_code = failure.os_code;
	error
}

//------------------------------------------------------------------------------
/** child の分類と path を保持します。秘密や出力本文を複製しません。 */
//------------------------------------------------------------------------------
fn process_error(phase: TransactionPhase, path: &Path, failure: ProcessError) -> TransactionError {
	let mut error = TransactionError::new(
		if failure == ProcessError::Cancelled {
			TransactionCode::Cancelled
		} else {
			TransactionCode::Keytool
		},
		phase,
	);
	error.path = Some(path.to_path_buf());
	error.process_error = Some(failure);
	error
}

//------------------------------------------------------------------------------
/** 全件確認後だけ、復元入口と再起動案内を持つ正常結果を生成します。 */
//------------------------------------------------------------------------------
fn outcome(manifest: &Manifest, directory: &Path, state: TransactionState) -> TransactionOutcome {
	TransactionOutcome {
		transaction_id: manifest.transaction_id.clone(),
		state,
		backup_directory: directory.to_path_buf(),
		stores: manifest
			.items
			.iter()
			.map(|item| item.original.canonical_path().to_path_buf())
			.collect(),
		restart_required: true,
	}
}

/// 再読込み済み manifest と現在の実体分類を一緒に保持する内部所有者です。
struct LoadedTransaction {
	/// 検証済みの private directory。
	directory: PathBuf,
	/// immutable 計画。
	manifest: Manifest,
	/// 最新 journal の安全に読めた部分。
	journal: JournalStatus,
	/// 追記する最新 journal の path。
	journal_path: PathBuf,
	/// 破断 journal の次に作る分岐番号。
	next_branch: usize,
	/// 実 path の現在分類。
	states: Vec<ItemState>,
}

//------------------------------------------------------------------------------
/**
 * 限定 backup root 内の履歴を列挙します。一つの不正記録でも他の履歴を隠しません。
 * manifest 保存前の directory も IncompletePreparation として残します。
 * password や keytool の実行は不要です。未知の物を削除しません。
 */
//------------------------------------------------------------------------------
pub fn list_history(options: &TransactionOptions) -> Result<Vec<HistoryEntry>, TransactionError> {
	match fs::symlink_metadata(&options.backup_root) {
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
		Err(error) => {
			return Err(TransactionError::io(
				TransactionPhase::History,
				&options.backup_root,
				error,
			));
		}
		Ok(_) => {}
	}
	let root = existing_root(options)?;
	let mut entries = Vec::new();
	// 保管上限を設け、無制限な directory 列挙による停止を防ぐ
	for entry in fs::read_dir(&root)
		.map_err(|error| TransactionError::io(TransactionPhase::History, &root, error))?
		.take(10_001)
	{
		if entries.len() >= 10_000 {
			return Err(TransactionError::new(
				TransactionCode::InvalidManifest,
				TransactionPhase::History,
			));
		}
		let entry =
			entry.map_err(|error| TransactionError::io(TransactionPhase::History, &root, error))?;
		let id = entry.file_name().to_string_lossy().into_owned();
		let inspection = inspect_transaction(options, &id).map_err(|mut error| {
			if error.path.is_none() {
				error.path = Some(root.join(&id));
			}
			error
		});
		entries.push(HistoryEntry {
			transaction_id: id,
			inspection,
		});
	}
	entries.sort_by(|left, right| right.transaction_id.cmp(&left.transaction_id));
	Ok(entries)
}

//------------------------------------------------------------------------------
/**
 * 選択した ID の schema/backup/journal と全実体を照合します。
 * 原/適用後/欠落/未知を区別し、末尾破断を Applied/Restored と判定しません。
 * この読み取り結果は復元許可の代わりではなく、復元関数が lock 後に再検査します。
 */
//------------------------------------------------------------------------------
pub fn inspect_transaction(
	options: &TransactionOptions,
	id: &str,
) -> Result<TransactionInspection, TransactionError> {
	let root = existing_root(options)?;
	if !valid_id(id) {
		return Err(TransactionError::new(
			TransactionCode::InvalidManifest,
			TransactionPhase::History,
		));
	}
	let directory = root.join(id);
	native::verify_private_directory(&directory)
		.map_err(|error| native_error(TransactionPhase::History, &directory, error))?;
	if !directory.join("manifest.json").exists() {
		return Ok(TransactionInspection {
			transaction_id: id.to_owned(),
			backup_directory: directory,
			state: HistoryState::IncompletePreparation,
			items: Vec::new(),
			stores: Vec::new(),
			java_root: PathBuf::new(),
			torn_journal: false,
			java_unchanged: false,
		});
	}
	let loaded = load_transaction(options, id)?;
	let all_original = loaded
		.states
		.iter()
		.all(|state| *state == ItemState::Original);
	let all_applied = loaded
		.states
		.iter()
		.all(|state| *state == ItemState::Applied);
	let safely_known = loaded.states.iter().enumerate().all(|(index, state)| {
		*state == ItemState::Original
			|| *state == ItemState::Applied
			|| *state == ItemState::Missing && missing_recoverable(&loaded, index)
	});
	let java_unchanged = loaded
		.manifest
		.java
		.iter()
		.all(|snapshot| snapshot.revalidate(MAX_INPUT_BYTES).is_ok());
	let state = if !safely_known || !java_unchanged {
		HistoryState::RecoveryRequired
	} else if !loaded.journal.torn_tail
		&& all_applied
		&& loaded.journal.state == TransactionState::Applied
	{
		HistoryState::Applied
	} else if !loaded.journal.torn_tail
		&& all_original
		&& loaded.journal.state == TransactionState::Restored
	{
		HistoryState::Restored
	} else if !loaded.journal.torn_tail
		&& all_original
		&& loaded.journal.state == TransactionState::RolledBack
	{
		HistoryState::RolledBack
	} else {
		HistoryState::Recoverable
	};
	Ok(TransactionInspection {
		transaction_id: id.to_owned(),
		backup_directory: loaded.directory,
		state,
		items: loaded.states,
		stores: loaded
			.manifest
			.items
			.iter()
			.map(|item| item.original.canonical_path().to_path_buf())
			.collect(),
		java_root: loaded.manifest.java_root,
		torn_journal: loaded.journal.torn_tail,
		java_unchanged,
	})
}

//------------------------------------------------------------------------------
/**
 * 適用履歴を元へ戻します。password は inspect_transaction の stores 順で再供給します。
 * backup 整合性、同じ Java、記録した適用後 hash/metadata の全一致が必要です。
 * 外部変更・不正 manifest・破損 backup は上書きしません。二重復元は AlreadyRestored。
 * 全 stage を検証後に復元を確定し、失敗時の部分状態を隠しません。
 */
//------------------------------------------------------------------------------
pub fn restore_transaction(
	environment: &JavaEnvironment,
	options: &TransactionOptions,
	id: &str,
	passwords: &[&StorePassword],
	cancellation: &Cancellation,
	progress: impl FnMut(TransactionProgress),
) -> Result<TransactionOutcome, TransactionError> {
	restore_or_recover(
		environment,
		options,
		id,
		passwords,
		cancellation,
		progress,
		false,
	)
}

//------------------------------------------------------------------------------
/**
 * 未完了 transaction の既知状態だけを元へ戻します。未知 file は強制上書きしません。
 * 末尾破断 journal は変更せず、新規 recovery journal へ分岐して証跡を残します。
 * 欠落は永続化済み未検証の item と一致する元 recovery copy がある場合だけ許可します。
 */
//------------------------------------------------------------------------------
pub fn recover_transaction(
	environment: &JavaEnvironment,
	options: &TransactionOptions,
	id: &str,
	passwords: &[&StorePassword],
	cancellation: &Cancellation,
	progress: impl FnMut(TransactionProgress),
) -> Result<TransactionOutcome, TransactionError> {
	restore_or_recover(
		environment,
		options,
		id,
		passwords,
		cancellation,
		progress,
		true,
	)
}

//------------------------------------------------------------------------------
/** 限定 root 内の一件を再読込みし、各 backup と現在の path を完全に検証します。 */
//------------------------------------------------------------------------------
fn load_transaction(
	options: &TransactionOptions,
	id: &str,
) -> Result<LoadedTransaction, TransactionError> {
	let root = existing_root(options)?;
	if !valid_id(id) {
		return Err(TransactionError::new(
			TransactionCode::InvalidManifest,
			TransactionPhase::History,
		));
	}
	let directory = root.join(id);
	native::verify_private_directory(&directory)
		.map_err(|error| native_error(TransactionPhase::History, &directory, error))?;
	let manifest = load_manifest(&directory.join("manifest.json"))?;
	if options
		.java_root
		.as_ref()
		.is_some_and(|root| root != &manifest.java_root)
	{
		let mut error = TransactionError::new(
			TransactionCode::BackupLocationMismatch,
			TransactionPhase::History,
		);
		error.path = Some(directory);
		return Err(error);
	}
	manifest.validate(id, &root)?;
	let mut journal_path = directory.join("journal.jsonl");
	let mut next_branch = 1;
	let mut allowed = BTreeSet::from([
		"manifest.json".to_owned(),
		"journal.jsonl".to_owned(),
		"preparation.json".to_owned(),
	]);
	allowed.extend(manifest.items.iter().map(|item| item.backup_name.clone()));
	// recovery journal は連番だけを受理し、元の破断記録も保存する
	while directory
		.join(format!("recovery-{next_branch:04}.jsonl"))
		.exists()
	{
		if next_branch > 128 {
			return Err(TransactionError::new(
				TransactionCode::InvalidJournal,
				TransactionPhase::History,
			));
		}
		let name = format!("recovery-{next_branch:04}.jsonl");
		allowed.insert(name.clone());
		read_journal(&journal_path, manifest.items.len())?;
		journal_path = directory.join(name);
		next_branch += 1;
	}
	for entry in fs::read_dir(&directory)
		.map_err(|error| TransactionError::io(TransactionPhase::History, &directory, error))?
		.take(MAX_STORES + 132)
	{
		let entry = entry
			.map_err(|error| TransactionError::io(TransactionPhase::History, &directory, error))?;
		if !entry
			.file_name()
			.to_str()
			.is_some_and(|name| allowed.contains(name))
		{
			return Err(TransactionError::new(
				TransactionCode::InvalidManifest,
				TransactionPhase::History,
			));
		}
	}
	// manifest 保存直後の強制終了も、対象未変更の Prepared として分類できる
	let journal = if journal_path.exists() {
		read_journal(&journal_path, manifest.items.len())?
	} else {
		JournalStatus {
			state: TransactionState::Prepared,
			next: 1,
			torn_tail: true,
			valid_bytes: 0,
			started: vec![false; manifest.items.len()],
			pending: None,
			operation_id: None,
		}
	};
	for item in &manifest.items {
		verify_raw_backup(&directory.join(&item.backup_name), &item.original)?;
	}
	let states = manifest
		.items
		.iter()
		.enumerate()
		.map(|(index, item)| {
			if conflicting_artifacts(id, index, item, journal.operation_id.as_deref()) {
				ItemState::Unknown
			} else {
				classify(item)
			}
		})
		.collect();
	Ok(LoadedTransaction {
		directory,
		manifest,
		journal,
		journal_path,
		next_branch,
		states,
	})
}

//------------------------------------------------------------------------------
/** 変更前に同じ Java を再選択したことと、適用時からの executable/release 不変を要求します。 */
//------------------------------------------------------------------------------
fn verify_saved_java(
	environment: &JavaEnvironment,
	manifest: &Manifest,
) -> Result<(), TransactionError> {
	validate_java(environment)?;
	if environment.root() != manifest.java_root
		|| environment.snapshots() != &manifest.java
		|| !environment.issues().is_empty()
	{
		return Err(TransactionError::new(
			TransactionCode::StaleJava,
			TransactionPhase::Restore,
		));
	}
	Ok(())
}

//------------------------------------------------------------------------------
/** 欠落先は直前に置換開始が永続化され、元実体の recovery copy が一致する場合だけ許可。 */
//------------------------------------------------------------------------------
fn missing_recoverable(loaded: &LoadedTransaction, index: usize) -> bool {
	loaded.journal.pending == Some(index)
		&& work_directory(
			loaded.manifest.items[index].original.canonical_path(),
			&loaded.manifest.transaction_id,
			index,
		)
		.is_ok_and(|work| {
			let item = &loaded.manifest.items[index];
			verify_recovery_copy(&work.join("apply.recovery"), &item.original).is_ok()
				|| loaded
					.journal
					.operation_id
					.as_ref()
					.is_some_and(|operation| {
						let copy = work.join(format!("{operation}.restore.recovery"));
						verify_snapshot(
							&copy,
							&item.applied.clone().at_path(copy.clone()),
							false,
							TransactionPhase::Recovery,
						)
						.is_ok()
					})
		})
}

//------------------------------------------------------------------------------
/** 同 volume に全復元 stage を準備し、既知状態以外を一切上書きせず順次確定します。 */
//------------------------------------------------------------------------------
fn restore_or_recover(
	environment: &JavaEnvironment,
	options: &TransactionOptions,
	id: &str,
	passwords: &[&StorePassword],
	cancellation: &Cancellation,
	mut progress: impl FnMut(TransactionProgress),
	recovery: bool,
) -> Result<TransactionOutcome, TransactionError> {
	check_cancel(cancellation)?;
	let initial = load_transaction(options, id)?;
	let count = initial.manifest.items.len();
	if passwords.len() != count {
		return Err(TransactionError::new(
			TransactionCode::InvalidPlan,
			TransactionPhase::Restore,
		));
	}
	verify_saved_java(environment, &initial.manifest)?;
	let mut lock_paths: Vec<_> = initial
		.manifest
		.items
		.iter()
		.map(|item| item.original.canonical_path())
		.collect();
	lock_paths.sort();
	let mut locks = Vec::new();
	for path in lock_paths {
		locks.push(
			native::target_lock(path)
				.map_err(|error| native_error(TransactionPhase::Lock, path, error))?,
		);
	}
	let loaded = load_transaction(options, id)?;
	let all_original = loaded
		.states
		.iter()
		.all(|state| *state == ItemState::Original);
	let phase = if recovery {
		TransactionPhase::Recovery
	} else {
		TransactionPhase::Restore
	};
	if !recovery
		&& (!all_original
			&& (loaded.journal.torn_tail
				|| loaded.journal.state != TransactionState::Applied
				|| loaded
					.states
					.iter()
					.any(|state| *state != ItemState::Applied)))
	{
		return Err(TransactionError::new(
			TransactionCode::ExternalChange,
			phase,
		));
	}
	for (index, state) in loaded.states.iter().enumerate() {
		if *state == ItemState::Unknown
			|| *state == ItemState::Missing && !missing_recoverable(&loaded, index)
		{
			let mut error = TransactionError::new(TransactionCode::RecoveryRequired, phase);
			error.item = Some(index);
			error.state = TransactionState::RecoveryRequired;
			return Err(error);
		}
	}
	let mut guards = Vec::new();
	let operation = new_id()?;
	let mut stages = Vec::new();
	let mut previous = Vec::new();
	// 全 backup と全 current state を確認するまで、対象を一件も置換しない
	for (index, item) in loaded.manifest.items.iter().enumerate() {
		check_cancel(cancellation)?;
		notify(&mut progress, phase, Some(index), count, true);
		let target = item.original.canonical_path();
		if loaded.states[index] != ItemState::Missing {
			guards.push(Some(native::write_guard(target).map_err(|error| {
				native_error(TransactionPhase::Lock, target, error)
			})?));
			native::check_supported_metadata(target)
				.map_err(|error| native_error(phase, target, error))?;
			verify_target(
				environment,
				item,
				passwords[index],
				cancellation,
				loaded.states[index] == ItemState::Original,
				false,
			)?;
			previous.push(Some(snapshot(target, phase)?.0));
		} else {
			guards.push(None);
			previous.push(None);
		}
		let backup = loaded.directory.join(&item.backup_name);
		let bytes = verify_raw_backup(&backup, &item.original)?;
		verify_inventory(
			environment,
			&backup,
			passwords[index],
			cancellation,
			&item.before,
			phase,
		)?;
		if loaded.states[index] == ItemState::Original {
			stages.push(None);
			continue;
		}
		let work = work_directory(target, id, index)?;
		// 正常適用では既存 private work を使い、存在しなければ新規作成する
		if !work.exists() {
			native::create_private_directory(&work)
				.map_err(|error| native_error(phase, &work, error))?;
		}
		native::verify_private_directory(&work)
			.map_err(|error| native_error(phase, &work, error))?;
		let stage = work.join(format!("{operation}.restore.stage"));
		native::create_stage(&stage, &bytes, &item.original, true)
			.map_err(|error| native_error(phase, &stage, error))?;
		verify_inventory(
			environment,
			&stage,
			passwords[index],
			cancellation,
			&item.before,
			phase,
		)?;
		let (prepared, _) = snapshot(&stage, phase)?;
		if !same_content_metadata(&prepared.at_path(target.to_path_buf()), &item.original) {
			return Err(TransactionError::new(
				TransactionCode::VerificationFailed,
				phase,
			));
		}
		stages.push(Some(stage));
	}
	check_cancel(cancellation)?;
	verify_saved_java(environment, &loaded.manifest)?;
	let mut journal = if loaded.journal.torn_tail {
		let path = loaded
			.directory
			.join(format!("recovery-{:04}.jsonl", loaded.next_branch));
		let mut journal = Journal::create(&path)?;
		journal.append(JournalEvent::Prepared, None)?;
		journal
	} else {
		Journal::resume(&loaded.journal_path, &loaded.journal)?
	};
	options.check(FailureBoundary::Journal, None, TransactionPhase::Journal)?;
	journal.start_restore(&operation)?;
	if all_original {
		append(Some(&mut journal), options, JournalEvent::Restored, None)?;
		notify(
			&mut progress,
			TransactionPhase::Complete,
			None,
			count,
			false,
		);
		return Ok(outcome(
			&loaded.manifest,
			&loaded.directory,
			TransactionState::AlreadyRestored,
		));
	}
	let committed_cancel = Cancellation::default();
	let mut restored = Vec::new();
	let result = (|| {
		// 確定以降は cancel を無視し、実 path の既知状態を再検査してから置換する
		for (index, item) in loaded.manifest.items.iter().enumerate() {
			let Some(stage) = &stages[index] else {
				continue;
			};
			notify(&mut progress, phase, Some(index), count, false);
			verify_saved_java(environment, &loaded.manifest)?;
			if classify(item) != loaded.states[index] {
				return Err(TransactionError::new(
					TransactionCode::ExternalChange,
					phase,
				));
			}
			options.check(FailureBoundary::BeforeRestore, Some(index), phase)?;
			append(
				Some(&mut journal),
				options,
				JournalEvent::RestoreStarted,
				Some(index),
			)?;
			let target = item.original.canonical_path();
			if loaded.states[index] != ItemState::Missing {
				native::check_supported_metadata(target)
					.map_err(|error| native_error(phase, target, error))?;
			}
			let copy = stage.with_extension("recovery");
			let (prepared, _) = snapshot(stage, phase)?;
			restored.push((index, copy.clone()));
			let replacement = if loaded.states[index] == ItemState::Missing {
				native::move_to_missing(stage, target)
			} else {
				native::replace(target, stage, &copy)
			};
			if let Err(failure) = replacement {
				let mut error = native_error(phase, target, failure);
				error.evidence = inspect_artifacts(&[target, stage, &copy]);
				return Err(error);
			}
			finish_replacement(target, &prepared, &item.original)?;
			if let Some(previous) = &previous[index] {
				verify_displaced_copy(&copy, previous)?;
			}
			guards[index] = Some(
				native::write_guard(target).map_err(|error| native_error(phase, target, error))?,
			);
			verify_target(
				environment,
				item,
				passwords[index],
				&committed_cancel,
				true,
				false,
			)?;
			append(
				Some(&mut journal),
				options,
				JournalEvent::RestoreVerified,
				Some(index),
			)?;
			options.check(FailureBoundary::AfterRestore, Some(index), phase)?;
		}
		for (index, item) in loaded.manifest.items.iter().enumerate() {
			verify_target(
				environment,
				item,
				passwords[index],
				&committed_cancel,
				true,
				false,
			)?;
		}
		append(Some(&mut journal), options, JournalEvent::Restored, None)
	})();
	if let Err(mut error) = result {
		error.transaction_id = Some(id.to_owned());
		error.rollback_errors = rollback_restore(
			RestoreRollback {
				environment,
				loaded: &loaded,
				passwords,
				options,
				journal: &mut journal,
				restored: &restored,
				previous: &previous,
				operation: &operation,
			},
			&mut progress,
		);
		let all_applied = loaded
			.manifest
			.items
			.iter()
			.all(|item| classify(item) == ItemState::Applied);
		error.state = if error.rollback_errors.is_empty() && all_applied {
			TransactionState::Applied
		} else {
			TransactionState::RecoveryRequired
		};
		return Err(error);
	}
	notify(
		&mut progress,
		TransactionPhase::Complete,
		None,
		count,
		false,
	);
	Ok(outcome(
		&loaded.manifest,
		&loaded.directory,
		TransactionState::Restored,
	))
}

/// 復元の逆順 rollback にだけ必要な一組の借用です。
struct RestoreRollback<'a, 'password> {
	/// 同じ Java。
	environment: &'a JavaEnvironment,
	/// 読込み/検証済み transaction。
	loaded: &'a LoadedTransaction,
	/// 操作時だけの password。
	passwords: &'a [&'password StorePassword],
	/// 失敗注入条件。
	options: &'a TransactionOptions,
	/// 同じ永続 writer。
	journal: &'a mut Journal,
	/// 復元を試行した位置と回収 file。
	restored: &'a [(usize, PathBuf)],
	/// 復元直前の実体。
	previous: &'a [Option<FileSnapshot>],
	/// 既存を上書きしない作業 ID。
	operation: &'a str,
}

//------------------------------------------------------------------------------
/** 復元失敗でも変更済みを逆順で直前状態へ戻し、元失敗と各 rollback 失敗を別々に保持します。 */
//------------------------------------------------------------------------------
fn rollback_restore(
	context: RestoreRollback<'_, '_>,
	progress: &mut impl FnMut(TransactionProgress),
) -> Vec<TransactionError> {
	let RestoreRollback {
		environment,
		loaded,
		passwords,
		options,
		journal,
		restored,
		previous,
		operation,
	} = context;
	let mut errors = Vec::new();
	if let Err(error) = append(Some(journal), options, JournalEvent::RollingBack, None) {
		errors.push(error);
	}
	let cancellation = Cancellation::default();
	for (index, recovery) in restored.iter().rev() {
		let index = *index;
		notify(
			progress,
			TransactionPhase::Rollback,
			Some(index),
			loaded.manifest.items.len(),
			false,
		);
		let result = (|| {
			options.check(
				FailureBoundary::BeforeRollback,
				Some(index),
				TransactionPhase::Rollback,
			)?;
			let item = &loaded.manifest.items[index];
			let target = item.original.canonical_path();
			let Some(before) = &previous[index] else {
				return Err(TransactionError::new(
					TransactionCode::RecoveryRequired,
					TransactionPhase::Rollback,
				));
			};
			if verify_snapshot(target, before, false, TransactionPhase::Rollback).is_ok() {
				return Ok(());
			}
			if classify(item) != ItemState::Original {
				return Err(TransactionError::new(
					TransactionCode::ExternalChange,
					TransactionPhase::Rollback,
				));
			}
			verify_recovery_copy(recovery, before)?;
			let (_, bytes) = snapshot(recovery, TransactionPhase::Rollback)?;
			let work = work_directory(target, &loaded.manifest.transaction_id, index)?;
			let stage = work.join(format!("{operation}.undo.stage"));
			native::create_stage(&stage, &bytes, before, true)
				.map_err(|error| native_error(TransactionPhase::Rollback, &stage, error))?;
			verify_inventory(
				environment,
				&stage,
				passwords[index],
				&cancellation,
				&item.after,
				TransactionPhase::Rollback,
			)?;
			let (prepared, _) = snapshot(&stage, TransactionPhase::Rollback)?;
			append(
				Some(journal),
				options,
				JournalEvent::RollbackStarted,
				Some(index),
			)?;
			verify_snapshot(target, &item.original, false, TransactionPhase::Rollback)?;
			let undo_copy = work.join(format!("{operation}.undo.recovery"));
			if let Err(failure) = native::replace(target, &stage, &undo_copy) {
				let mut error = native_error(TransactionPhase::Rollback, target, failure);
				error.evidence = inspect_artifacts(&[target, &stage, &undo_copy]);
				return Err(error);
			}
			verify_displaced_copy(&undo_copy, &item.original)?;
			finish_replacement(target, &prepared, before)?;
			verify_snapshot(target, before, false, TransactionPhase::Rollback)?;
			verify_inventory(
				environment,
				target,
				passwords[index],
				&cancellation,
				&item.after,
				TransactionPhase::Rollback,
			)?;
			append(
				Some(journal),
				options,
				JournalEvent::RollbackVerified,
				Some(index),
			)
		})();
		if let Err(mut error) = result {
			error.item = Some(index);
			errors.push(error);
		}
	}
	let all_applied = loaded
		.manifest
		.items
		.iter()
		.all(|item| classify(item) == ItemState::Applied);
	let event = if errors.is_empty() && all_applied {
		JournalEvent::RestoreRolledBack
	} else {
		JournalEvent::RecoveryRequired
	};
	if let Err(error) = append(Some(journal), options, event, None) {
		errors.push(error);
	}
	errors
}

//------------------------------------------------------------------------------
/** 履歴を読む既存 root の本人/管理者限定 ACL と canonical path を検査します。 */
//------------------------------------------------------------------------------
fn existing_root(options: &TransactionOptions) -> Result<PathBuf, TransactionError> {
	native::verify_private_directory(&options.backup_root)
		.map_err(|error| native_error(TransactionPhase::History, &options.backup_root, error))?;
	fs::canonicalize(&options.backup_root).map_err(|error| {
		TransactionError::io(TransactionPhase::History, &options.backup_root, error)
	})
}
