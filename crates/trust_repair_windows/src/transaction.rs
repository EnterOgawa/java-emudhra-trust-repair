//------------------------------------------------------------------------------
/*!
 * - ファイル: transaction.rs
 * - 概要: 検証済み診断から backup・順次適用・rollback・復元を実行します。
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
	/// 主原因とは別に所有する、対象位置・下位原因・復旧証拠の参照先です。
	type Target = TransactionContext;

	//------------------------------------------------------------------------------
	/**
	 * code/phase と同じ読みやすさで所有 context の field を参照します。
	 */
	//------------------------------------------------------------------------------
	fn deref(&self) -> &Self::Target {
		&self.context
	}
}

impl std::ops::DerefMut for TransactionError {
	//------------------------------------------------------------------------------
	/**
	 * 内部処理が最初の原因を失わず context を補足できる可変参照を返します。
	 */
	//------------------------------------------------------------------------------
	fn deref_mut(&mut self) -> &mut Self::Target {
		&mut self.context
	}
}

impl TransactionError {
	//------------------------------------------------------------------------------
	/**
	 * 秘密を含まない型付き失敗を、元対象を未変更の既定状態で生成します。
	 */
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
	/**
	 * OS code と context を保持し、外部エラーの自由文を保存しません。
	 */
	//------------------------------------------------------------------------------
	pub(crate) fn io(phase: TransactionPhase, path: &Path, error: std::io::Error) -> Self {
		let mut value = Self::new(
			// 実際の権限拒否だけを専用分類へ保ち、他の I/O 失敗と混同しない
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
	/**
	 * 元 snapshot の失敗分類を失わずに返します。
	 */
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
			// file の実権限不足は保持し、仕様非対応を管理者権限不足へ言い換えない
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
	/**
	 * 開発向けに固定 code/工程だけを表示します。UI は公開 field から翻訳します。
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
	/// 最新の実在 journal に末尾破断があります。初回 journal の未作成は含めません。
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
	/**
	 * 選択済みJava内の固定backup rootへ拘束します。読み取りやdirectory作成は行いません。
	 *
	 * # Arguments
	 *
	 * - `environment`: 選択済み Java。保存先と保存時 Java の両方をこの root に拘束します。
	 *
	 * # Returns
	 *
	 * 選択 Java 内の `emudhra-backup` を使う設定。
	 *
	 * # Errors
	 *
	 * 構成した保存先が許可する絶対 DOS パスの形式でない場合。
	 */
	//------------------------------------------------------------------------------
	pub fn for_java(environment: &JavaEnvironment) -> Result<Self, TransactionError> {
		let mut options = Self::with_backup_root(environment.root().join("emudhra-backup"))?;
		options.java_root = Some(environment.root().to_path_buf());
		Ok(options)
	}

	//------------------------------------------------------------------------------
	/**
	 * 従来版の本人用backup rootを参照します。互換履歴用で、directoryを作りません。
	 *
	 * # Returns
	 *
	 * LOCALAPPDATA 配下の従来保存先を使う、Java を未拘束の設定。
	 *
	 * # Errors
	 *
	 * LOCALAPPDATA が未設定、または構成したパスが許可形式でない場合。
	 */
	//------------------------------------------------------------------------------
	pub fn local_app_data() -> Result<Self, TransactionError> {
		let base = std::env::var_os("LOCALAPPDATA")
			.ok_or_else(|| TransactionError::new(TransactionCode::Io, TransactionPhase::Backup))?;
		Self::with_backup_root(PathBuf::from(base).join("EnterSystem/JavaTrustRepair/backups"))
	}

	//------------------------------------------------------------------------------
	/**
	 * 明示した専用 root を使います。隔離試験に利用でき、既存 ACL を広げることはありません。
	 *
	 * # Arguments
	 *
	 * - `backup_root`: 設定が所有する専用保存先の絶対 DOS パス。
	 *
	 * # Errors
	 *
	 * パスの字句検証に失敗した場合。ここでは存在・ACL・書込み可能性を保証しません。
	 */
	//------------------------------------------------------------------------------
	pub fn with_backup_root(backup_root: PathBuf) -> Result<Self, TransactionError> {
		// 保存先の字句形式を先に限定し、任意の device・相対パスを設定へ保持しない
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
	/**
	 * 適用前の UI に表示できる保管 root を返します。
	 */
	//------------------------------------------------------------------------------
	pub fn backup_root(&self) -> &Path {
		&self.backup_root
	}

	//------------------------------------------------------------------------------
	/**
	 * 隔離試験の境界を追加します。通常の GUI はこの設定を行いません。
	 *
	 * # Arguments
	 *
	 * - `point`: 失敗を注入する工程境界と、必要な場合は 0 始まりの item 位置。
	 *
	 * # Returns
	 *
	 * 境界を一件追加した設定。元の設定の所有権を引き継ぎます。
	 */
	//------------------------------------------------------------------------------
	pub fn with_failure(mut self, point: FailurePoint) -> Self {
		self.failures.push(point);
		self
	}

	//------------------------------------------------------------------------------
	/**
	 * 明示された境界だけを失敗させます。設定がなければ副作用を持ちません。
	 *
	 * # Arguments
	 *
	 * - `boundary`: 現在到達した工程の境界。
	 * - `item`: ストア別の境界なら 0 始まりの位置、群全体なら `None`。
	 * - `phase`: 注入失敗へ付ける実工程。
	 *
	 * # Errors
	 *
	 * 境界と item の組が明示設定に一致した場合だけ `InjectedFailure` を返します。
	 */
	//------------------------------------------------------------------------------
	fn check(
		&self,
		boundary: FailureBoundary,
		item: Option<usize>,
		phase: TransactionPhase,
	) -> Result<(), TransactionError> {
		// 明示した境界と位置が一致した場合だけ、隔離試験の失敗を注入する
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
 *
 * # Arguments
 *
 * - `environment`: 診断に使った検証済み Java。
 * - `group`: 対象ゼロのストアも含む、入力範囲全体の診断。
 * - `plan`: 同じ群と埋込み定義から再構築できる変更計画。
 * - `passwords`: 対象ゼロを含む `group.stores()` 順の秘密の借用。
 * - `options`: 保存先、必要なら保存時 Java の拘束、隔離試験の失敗境界。
 * - `cancellation`: 確定開始前まで受け付ける中断要求。
 * - `progress`: 呼出し元と同じ worker 上で行う工程通知。
 *
 * # Returns
 *
 * 全対象の適用と検証を完了した結果。バックアップへの入口を所有します。
 *
 * # Errors
 *
 * 計画・Java・全実体の変化、排他・権限・保存・stage・置換・検証の失敗。
 * 確定を試みた項目は逆順に rollback し、元の原因・rollback 失敗・残存状態を返します。
 *
 * # Notes
 *
 * 対象の lock と write guard は本呼出しが所有し、戻るときに解放します。
 * 複数ファイル全体の原子的変更を保証せず、確定途中は利用者の中断を受け付けません。
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
	// 保存先を拘束した Java と別の環境へ、新しい適用を流用しない
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
	// 計画・認証順・全診断・Java の一致を再確認し、古い部分成功から適用しない
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
		// 選択 Java の全履歴を確認し、未完了の準備を残したまま新規処理を混在させない
		for entry in list_history(options)? {
			let inspection = entry.inspection?;
			// manifest 保存前の未完了準備がある場合は、先にその証拠の確認を要求する
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
			"schema_version": 1,
			"transaction_id": id,
			"policy_id": policy.id(),
			"java": environment.snapshots(),
			"stores": plan.stores().iter().map(|planned| Ok(serde_json::json!({
				"original": group.stores()[planned.report_index()].snapshot(),
				"inventory": SavedInventory::from_inventory(planned.original())?,
				"deletions": planned
					.deletions()
					.iter()
					.map(|deletion| (deletion.alias(), deletion.sha256(), deletion.policy_root_id()))
					.collect::<Vec<_>>()
			}))).collect::<Result<Vec<_>, TransactionError>>()?
		});
		let preparation = serde_json::to_vec_pretty(&preparation).map_err(|_| {
			TransactionError::new(TransactionCode::InvalidManifest, TransactionPhase::Backup)
		})?;
		// 準備記録を保存前に容量制限し、巨大な復旧材料を作らない
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
		// 準備記録の読戻しが元 byte と異なれば、対象の変更前に止める
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
			// backup root 自体を変更対象に含めず、保存物と元対象の責務を分ける
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
			// backup 取得時点でも診断済み実体を再確認し、途中更新を保存して適用しない
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
			// stage の内容と保持 metadata を照合し、完全な元コピーからだけ削除を始める
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
				// 削除コマンドに未知の出力がある場合、成功コードだけで stage を採用しない
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
			// 削除前後の件数差も確認し、計画外の削除や欠落を見逃さない
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
			// stage の metadata と同 volume を確認し、元の保持条件を満たす置換だけを準備する
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
			// 置換 API の失敗時も実体を調べ、主原因と残存する証拠を保持する
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
	// 準備・確定の失敗は、試行済み範囲に応じた終了状態と証拠を付けて返す
	if let Err(mut error) = result {
		error.transaction_id = Some(id.clone());
		// 確定を試みた対象がある場合だけ、逆順 rollback で元状態への復旧を試みる
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
			// 全 rollback の検証に合格した場合だけ復旧済みとし、失敗が残れば要復旧にする
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
/**
 * 変更済み/置換試行済みの対象だけを逆順で戻します。未知内容は上書きしません。
 *
 * # Arguments
 *
 * - `context`: 適用済み・試行済みの位置、元 snapshot、journal と設定の借用。
 * - `progress`: 同じ worker 上で行う、中断不可の rollback 工程通知。
 *
 * # Returns
 *
 * 逆順の復旧で発生した全失敗。空なら試行した項目の復旧と検証に合格しています。
 */
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
	// rollback 開始記録の失敗も収集し、可能な元対象の復旧は続ける
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
			// 期待と矛盾する退避物がある対象を、自動 rollback で上書きしない
			if conflicting_artifacts(&manifest.transaction_id, index, item, None) {
				return Err(TransactionError::new(
					TransactionCode::ExternalChange,
					TransactionPhase::Rollback,
				));
			}
			// 既に元状態なら再置換せず、元 inventory の検証で復旧を確認する
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
			// 適用後状態でも根拠付きの欠落でもない対象は、未知内容として保全する
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
			// 根拠付きの欠落には移動、既存対象には退避付き置換を使い分ける
			if missing {
				native::move_to_missing(&stage, target)
					.map_err(|error| native_error(TransactionPhase::Rollback, target, error))?;
			} else {
				verify_snapshot(target, &item.applied, false, TransactionPhase::Rollback)?;
				let recovery = work.join("rollback.recovery");
				// rollback の置換失敗にも残存実体を付け、後の復旧判断に必要な証拠を残す
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
		// 一対象の rollback 失敗で残りを省かず、位置付きの失敗を収集する
		if let Err(mut error) = result {
			error.item = Some(index);
			errors.push(error);
		}
	}
	// 全対象の復旧と検証に成功した場合だけ、完了状態の記録を選ぶ
	let final_event = if errors.is_empty() {
		JournalEvent::RolledBack
	} else {
		JournalEvent::RecoveryRequired
	};
	// 最終 journal の失敗も失敗一覧に加え、記録欠落を成功にしない
	if let Err(error) = append(journal, options, final_event, None) {
		errors.push(error);
	}
	errors
}

//------------------------------------------------------------------------------
/**
 * Java の既存の実体/hash/metadata を検査し、UI 向け分類を保持します。
 *
 * # Errors
 *
 * 選択済み Java の snapshot を再照合できない場合。元の file 検査理由を保持します。
 */
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
/**
 * 変更済み以外の全群と Java を再検査します。対象ゼロのストアも省略しません。
 *
 * # Arguments
 *
 * - `environment`: 三ファイルを再照合する選択済み Java。
 * - `group`: 変更対象外を含む元の全診断群。
 * - `changed`: 既に変更したため元 snapshot との比較から除外する、群内の 0 始まりの位置。
 *
 * # Errors
 *
 * Java または未変更のストアが、元 snapshot と一致しないか再取得できない場合。
 */
//------------------------------------------------------------------------------
fn validate_group(
	environment: &JavaEnvironment,
	group: &ScanGroup,
	changed: &BTreeSet<usize>,
) -> Result<(), TransactionError> {
	validate_java(environment)?;
	// 変更対象外を含む群全体を、元 snapshot と診断順に再照合する
	for (index, store) in group.stores().iter().enumerate() {
		// 既に変更済みの位置だけを元状態との比較から外し、他のストアは検査する
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
			// 実権限不足は保持し、それ以外の再照合失敗を競合として案内する
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
/**
 * 全 inventory と通常の metadata を実 path から再取得し、期待状態と照合します。
 *
 * # Arguments
 *
 * - `environment`: 一覧を取得する Java。
 * - `item`: 元状態と適用後状態の両方を記録した manifest 項目。
 * - `password`: この対象の全 inventory を再取得する秘密。
 * - `cancellation`: 一覧取得中に監視する中断要求。
 * - `original`: `true` は元状態、`false` は適用後状態を期待します。
 * - `identity`: `true` は byte・metadata に加えて file ID も要求します。
 *
 * # Errors
 *
 * 期待する snapshot または全 inventory と一致しないか、再取得に失敗した場合。
 */
//------------------------------------------------------------------------------
fn verify_target(
	environment: &JavaEnvironment,
	item: &ManifestItem,
	password: &StorePassword,
	cancellation: &Cancellation,
	original: bool,
	identity: bool,
) -> Result<(), TransactionError> {
	// 今回要求する元状態または適用後状態の snapshot を選んで照合する
	let expected = if original {
		&item.original
	} else {
		&item.applied
	};
	// snapshot と同じ側の全 inventory を選び、内容と一覧の期待を揃える
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
/**
 * 同じ厳密 list を stage/実 path/backup に使用し、全別名・種別・DER hash・形式を照合します。
 *
 * # Arguments
 *
 * - `environment`: keytool を提供する選択済み Java。
 * - `path`: 今回全 inventory を取り直す実ファイル。
 * - `password`: 指定ファイルの認証だけに借用する秘密。
 * - `cancellation`: 一覧取得で監視する中断要求。
 * - `expected`: 全別名・種別・DER ハッシュ・形式の期待値。
 * - `phase`: 下位エラーへ結び付ける現在工程。
 *
 * # Errors
 *
 * ファイル・一覧を取得できない、警告がある、または保存済みの期待一覧と一致しない場合。
 */
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
		// 利用者の中断を検証不一致へ変換せず、専用の分類で上位へ伝える
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
	// 警告のない全 inventory の完全一致だけを、期待状態の根拠にする
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
/**
 * 元 backup を読戻し、内容と上限を照合します。backup の ACL は対象へコピーしません。
 *
 * # Returns
 *
 * 元 snapshot と内容が一致した backup の全 byte 列。
 *
 * # Errors
 *
 * backup の取得失敗、容量超過、長さまたはハッシュの不一致。
 */
//------------------------------------------------------------------------------
fn verify_raw_backup(path: &Path, original: &FileSnapshot) -> Result<Vec<u8>, TransactionError> {
	let (actual, bytes) = snapshot(path, TransactionPhase::Backup)?;
	// backup の内容を元 snapshot と照合し、壊れた復元材料を利用しない
	if actual.sha256() != original.sha256() || actual.length() != original.length() {
		let mut error =
			TransactionError::new(TransactionCode::BackupCorrupt, TransactionPhase::Backup);
		error.path = Some(path.to_path_buf());
		return Err(error);
	}
	Ok(bytes)
}

//------------------------------------------------------------------------------
/**
 * 同 volume recovery copy が本当に元実体であるか、hash/ID/metadata を照合します。
 *
 * # Errors
 *
 * 元実体の ID・内容・保持 metadata が期待と一致しないか、退避物を取得できない場合。
 */
//------------------------------------------------------------------------------
fn verify_recovery_copy(path: &Path, expected: &FileSnapshot) -> Result<(), TransactionError> {
	native::check_supported_metadata(path)
		.map_err(|error| native_error(TransactionPhase::Verify, path, error))?;
	let (actual, _) = snapshot(path, TransactionPhase::Verify)?;
	// 回復用コピーは元実体の ID と内容・metadata の両方を満たす場合だけ採用する
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
/**
 * 置換で実際に退避された file を照合し、競合した未知内容の場所をエラー証拠へ残します。
 *
 * # Errors
 *
 * 退避された実体が期待と異なるか取得できない場合。
 * 失敗した実パスを証拠として保持し、未知内容を上書きしません。
 */
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
/**
 * 既存の退避物が期待内容と矛盾したら自動上書きを禁止します。未知の証拠は削除しません。
 *
 * # Arguments
 *
 * - `id`: 元の transaction ID。
 * - `index`: manifest 内の 0 始まりの項目位置。
 * - `item`: 照合する元状態・適用後状態・work directory。
 * - `operation`: 復元操作の ID。`None` は適用時の退避物だけを調べます。
 *
 * # Returns
 *
 * 既存の退避物に期待と矛盾するものがあれば `true`。不在だけでは競合にしません。
 */
//------------------------------------------------------------------------------
fn conflicting_artifacts(
	id: &str,
	index: usize,
	item: &ManifestItem,
	operation: Option<&str>,
) -> bool {
	// work directory を安全に導けない場合も、競合なしとして自動上書きしない
	let Ok(work) = work_directory(item.original.canonical_path(), id, index) else {
		return true;
	};
	let mut copies = vec![
		(work.join("apply.recovery"), &item.original),
		(work.join("rollback.recovery"), &item.applied),
	];
	// 復元操作が記録されている場合は、その操作の退避物も競合検査へ含める
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
/**
 * file ID を要求するかを明示し、hash/metadata の一致しない path は拒否します。
 *
 * # Arguments
 *
 * - `path`: 再取得して照合する実パス。
 * - `expected`: 内容・保持 metadata の期待値。
 * - `identity`: `true` は file ID の一致も要求します。
 * - `phase`: 取得・不一致エラーへ付ける工程。
 *
 * # Errors
 *
 * snapshot の取得失敗、または要求した内容・metadata・実体の不一致。
 */
//------------------------------------------------------------------------------
fn verify_snapshot(
	path: &Path,
	expected: &FileSnapshot,
	identity: bool,
	phase: TransactionPhase,
) -> Result<(), TransactionError> {
	let (actual, _) = snapshot(path, phase)?;
	// 内容と保持 metadata を必須とし、要求された場合は file ID の一致も確認する
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
/**
 * 置換した stage 本体と確認してから、元の DACL を保持します。未知実体へ権限を設定しません。
 *
 * # Arguments
 *
 * - `path`: 置換後の実パス。
 * - `prepared`: 実パスへ移ったはずの検証済み stage。
 * - `original`: 戻す DACL と保護状態を持つ元 snapshot。
 *
 * # Errors
 *
 * 置換後の実体が stage と一致しない、または元 DACL の設定に失敗した場合。
 */
//------------------------------------------------------------------------------
fn finish_replacement(
	path: &Path,
	prepared: &FileSnapshot,
	original: &FileSnapshot,
) -> Result<(), TransactionError> {
	let (actual, _) = snapshot(path, TransactionPhase::Verify)?;
	// 実パスが準備した stage であることを確認してから、元 DACL を戻す
	if actual.identity() != prepared.identity() || actual.sha256() != prepared.sha256() {
		return Err(TransactionError::new(
			TransactionCode::ExternalChange,
			TransactionPhase::Verify,
		));
	}
	// 置換時の継承再計算で DACL が変わった場合だけ、保存した元値へ戻す
	if !native::same_security(actual.security_descriptor(), original.security_descriptor()) {
		native::preserve_dacl(path, original)
			.map_err(|error| native_error(TransactionPhase::Verify, path, error))?;
	}
	#[cfg(feature = "internal-qa")]
	crate::qa_checkpoint("dacl-preserved", None);
	Ok(())
}

//------------------------------------------------------------------------------
/**
 * 型付き file 検査を容量上限付きで実行します。
 *
 * # Arguments
 *
 * - `path`: 全 byte と metadata を取得する実ファイル。
 * - `phase`: file 検査失敗へ付ける現在工程。
 *
 * # Returns
 *
 * 最大 `MAX_INPUT_BYTES` の snapshot と全 byte 列。
 *
 * # Errors
 *
 * read_snapshot の安全性検査・I/O 失敗を transaction の分類へ保持して返します。
 */
//------------------------------------------------------------------------------
fn snapshot(
	path: &Path,
	phase: TransactionPhase,
) -> Result<(FileSnapshot, Vec<u8>), TransactionError> {
	read_snapshot(path, MAX_INPUT_BYTES).map_err(|error| TransactionError::file(phase, path, error))
}

//------------------------------------------------------------------------------
/**
 * 実体と metadata が既知のどちらにも一致しない場合は Unknown とし上書きを許しません。
 */
//------------------------------------------------------------------------------
fn classify(item: &ManifestItem) -> ItemState {
	// 元・適用後・欠落・未知を現物から区別し、不明な内容を復旧可能と推測しない
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
/**
 * 置換失敗でも三つの実体を調べ、欠落/未知を成功扱いしない証拠を所有します。
 */
//------------------------------------------------------------------------------
fn inspect_artifacts(paths: &[&Path]) -> Vec<ArtifactEvidence> {
	paths
		.iter()
		// 各残存パスの内容または失敗理由を保持し、置換失敗後の判断材料を失わない
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
/**
 * 注入と永続追記を一箇所で実行します。journal がない場合は確定できません。
 *
 * # Arguments
 *
 * - `journal`: 追記先。`None` では確定記録を作れません。
 * - `options`: journal 追記前に検査する明示失敗境界。
 * - `event`: 永続化する状態遷移。
 * - `item`: 個別項目の記録なら 0 始まりの位置。
 *
 * # Errors
 *
 * journal 不在、明示境界の失敗、または追記・flush・sync の失敗。
 * 書込み途中に失敗しても、書込み済みの記録は取り消しません。
 */
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
/**
 * 本人用の一意 ID を生成します。時刻異常でも既存 directory は上書きしません。
 *
 * # Returns
 *
 * 現在時刻・process ID・process 内の連番を含む ID。新規作成の排他は呼出し側でも行います。
 *
 * # Errors
 *
 * システム時刻が UNIX_EPOCH より前の場合。
 */
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
/**
 * 確定前だけ利用者の cancel を受理します。
 *
 * # Errors
 *
 * 中断が要求済みなら `Cancelled`。確定中の呼出し経路では使用しません。
 */
//------------------------------------------------------------------------------
fn check_cancel(cancellation: &Cancellation) -> Result<(), TransactionError> {
	// 確定前の中断要求だけを受理し、元対象を変更する前に戻る
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
/**
 * 時間から百分率を捏造せず、実際の工程を callback へ渡します。
 *
 * # Arguments
 *
 * - `progress`: 同じ呼出し thread で実行する通知先。
 * - `phase`: 実際に到達した工程。
 * - `item`: 個別工程なら 0 始まりの位置、全体工程なら `None`。
 * - `item_count`: 変更計画の全項目数。
 * - `cancellable`: この工程で安全な中断を受け付けられるか。
 */
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
/**
 * native 分類を UI 用 code へ写し、OS code を保持します。
 */
//------------------------------------------------------------------------------
fn native_error(phase: TransactionPhase, path: &Path, failure: IoFailure) -> TransactionError {
	// 排他・metadata 非対応・実権限不足の順で native の失敗理由を保持する
	let code = if failure.busy {
		TransactionCode::Busy
	}
	// 保全未対応の metadata は、権限不足と区別して拒否理由を保つ
	else if failure.unsupported_metadata {
		TransactionCode::UnsupportedMetadata
	}
	// 実際の権限不足 code だけを管理者起動の案内へ結び付ける
	else if matches!(failure.os_code, Some(5 | 1300 | 1314)) {
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
/**
 * child の分類と path を保持します。秘密や出力本文を複製しません。
 */
//------------------------------------------------------------------------------
fn process_error(phase: TransactionPhase, path: &Path, failure: ProcessError) -> TransactionError {
	let mut error = TransactionError::new(
		// 子プロセスの中断は専用分類に保ち、他の実行失敗と区別する
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
/**
 * 全件確認後だけ、復元入口と再起動案内を持つ正常結果を生成します。
 */
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
	/// 初回 journal が未作成で、復旧 journal もまだ存在しない状態。
	journal_missing: bool,
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
 *
 * # Arguments
 *
 * - `options`: 読み取る限定 backup root。新規 directory は作成しません。
 *
 * # Returns
 *
 * ID の降順の履歴。root 不在は空、個々の検査失敗は該当要素へ保持します。
 *
 * # Errors
 *
 * root の実体・限定 ACL の検査、directory 列挙の失敗、または 10,000 件の上限超過。
 */
//------------------------------------------------------------------------------
pub fn list_history(options: &TransactionOptions) -> Result<Vec<HistoryEntry>, TransactionError> {
	// root の不在だけを空履歴とし、読取り失敗を履歴なしへ変換しない
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
		// 履歴件数の上限で列挙を打ち切り、無制限な読込みを避ける
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
			// 下位失敗がパスを持たない場合だけ、該当履歴の実保存先を補足する
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
 * 初回 journal の未作成は Recoverable とし、実在 journal の末尾破断とは区別します。
 * この読み取り結果は復元許可の代わりではなく、復元関数が lock 後に再検査します。
 *
 * # Arguments
 *
 * - `options`: 履歴を拘束する限定 root と保存時 Java の設定。
 * - `id`: 一件を指定する、パス区切りを含まない transaction ID。
 *
 * # Returns
 *
 * 現物に基づく履歴状態と、全対象・保管場所。manifest 不在は準備未完了として返します。
 *
 * # Errors
 *
 * ID・root・記録・backup の検査に失敗した場合。読み取りだけを行い、証拠を修復しません。
 */
//------------------------------------------------------------------------------
pub fn inspect_transaction(
	options: &TransactionOptions,
	id: &str,
) -> Result<TransactionInspection, TransactionError> {
	let root = existing_root(options)?;
	// ID の字句形式を確認し、限定 root 外の記録を参照させない
	if !valid_id(id) {
		return Err(TransactionError::new(
			TransactionCode::InvalidManifest,
			TransactionPhase::History,
		));
	}
	let directory = root.join(id);
	native::verify_private_directory(&directory)
		.map_err(|error| native_error(TransactionPhase::History, &directory, error))?;
	// manifest 前の保存物は準備未完了として案内し、削除や成功の推測をしない
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
	// 未知実体・Java の変化を最優先し、正常 journal と現物が揃う場合だけ完了状態を認める
	let state = if !safely_known || !java_unchanged {
		HistoryState::RecoveryRequired
	}
	// 破断のない適用完了記録と全件の適用後実体が揃う場合だけ、適用済みと判定する
	else if !loaded.journal.torn_tail
		&& all_applied
		&& loaded.journal.state == TransactionState::Applied
	{
		HistoryState::Applied
	}
	// 破断のない復元完了記録と全件の元実体が揃う場合だけ、復元済みと判定する
	else if !loaded.journal.torn_tail
		&& all_original
		&& loaded.journal.state == TransactionState::Restored
	{
		HistoryState::Restored
	}
	// 破断のない rollback 完了記録と全件の元実体が揃う場合だけ、復旧済みと判定する
	else if !loaded.journal.torn_tail
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
 *
 * # Arguments
 *
 * - `environment`: 保存時と同じ Java。実体・内容・metadata を再照合します。
 * - `options`: 対象履歴を読み取る限定 root。
 * - `id`: 復元または復旧する transaction ID。
 * - `passwords`: inspect_transaction が返した stores 順の認証入力。
 * - `cancellation`: 確定開始前まで監視する中断要求。
 * - `progress`: 同じ worker 上で実行する工程通知。
 *
 * # Returns
 *
 * 全件を元状態へ戻して検証した結果。既に元の完全状態なら `AlreadyRestored`。
 *
 * # Errors
 *
 * 保存時 Java・記録・backup・現在実体の不一致、排他・権限・stage・置換・検証の失敗。
 * 確定後の失敗は直前状態への rollback を試み、主原因と復旧失敗を共に返します。
 *
 * # Notes
 *
 * 確定開始後は中断不可です。lock と guard を所有し、戻るときに解放します。
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
 * 初回 journal の未作成も、元の不在を保つ新規 recovery journal へ記録します。
 * 欠落は永続化済み未検証の item と一致する元 recovery copy がある場合だけ許可します。
 *
 * # Arguments
 *
 * - `environment`: 保存時と同じ Java。実体・内容・metadata を再照合します。
 * - `options`: 対象履歴を読み取る限定 root。
 * - `id`: 復元または復旧する transaction ID。
 * - `passwords`: inspect_transaction が返した stores 順の認証入力。
 * - `cancellation`: 確定開始前まで監視する中断要求。
 * - `progress`: 同じ worker 上で実行する工程通知。
 *
 * # Returns
 *
 * 全件が元状態であることを確認した復旧結果と、保持した履歴への入口。
 *
 * # Errors
 *
 * 未知実体・不正記録・backup 不一致・根拠のない欠落、または準備・確定・検証の失敗。
 * 部分状態と rollback の失敗を隠さず、残存する証拠を保持して返します。
 *
 * # Notes
 *
 * 正常な復元と同じ排他・検証を行い、確定開始後は中断を受け付けません。
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
/**
 * 限定 root 内の一件を再読込みし、各 backup と現在の path を完全に検証します。
 * 初回 journal だけは未作成を Prepared として保持し、復旧分岐の存在後も同じ規則を使います。
 * 存在する全 journal の内容と復旧分岐の連番を検証し、欠落以外の I/O 失敗は返します。
 *
 * # Arguments
 *
 * - `options`: 保存先と必要な保存時 Java の拘束。
 * - `id`: 限定 root 内で検査する transaction ID。
 *
 * # Returns
 *
 * manifest、検証済み journal、現在の全項目状態。
 * 初回 journal の不在は独立したフラグへ保持し、実在する末尾破断と区別します。
 *
 * # Errors
 *
 * manifest・backup・全 journal の内容、復旧分岐の連番、または実体検査の失敗。
 * 初回 journal の NotFound 以外の I/O 失敗を未作成として受理しません。
 */
//------------------------------------------------------------------------------
fn load_transaction(
	options: &TransactionOptions,
	id: &str,
) -> Result<LoadedTransaction, TransactionError> {
	let root = existing_root(options)?;
	// 限定 root の下へ連結する前に ID を検証する
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
	// Java 内 root では、保存時 Java と異なる manifest の流用を拒否する
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
	// manifest 保存後・初回 journal 作成前の中断だけを、未変更の Prepared として扱う
	let (mut journal, initial_journal_missing) = match fs::symlink_metadata(&journal_path) {
		Ok(_) => (read_journal(&journal_path, manifest.items.len())?, false),
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => (
			JournalStatus {
				state: TransactionState::Prepared,
				next: 1,
				torn_tail: false,
				valid_bytes: 0,
				started: vec![false; manifest.items.len()],
				pending: None,
				operation_id: None,
			},
			true,
		),
		Err(error) => {
			return Err(TransactionError::io(
				TransactionPhase::History,
				&journal_path,
				error,
			));
		}
	};
	let mut next_branch = 1;
	let mut allowed = BTreeSet::from([
		"manifest.json".to_owned(),
		"journal.jsonl".to_owned(),
		"preparation.json".to_owned(),
	]);
	allowed.extend(manifest.items.iter().map(|item| item.backup_name.clone()));
	// recovery journal は連番だけを受理し、元の破断記録も保存する
	loop {
		let name = format!("recovery-{next_branch:04}.jsonl");
		let path = directory.join(&name);
		// 復旧 journal の読込不能を不存在に変えず、連番の欠落は後続の許可名検査でも拒否する
		match fs::symlink_metadata(&path) {
			Ok(_) => {}
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
			Err(error) => {
				return Err(TransactionError::io(
					TransactionPhase::History,
					&path,
					error,
				));
			}
		}
		// 復旧分岐の数を制限し、無制限の探索や新規分岐生成を防ぐ
		if next_branch > 128 {
			return Err(TransactionError::new(
				TransactionCode::InvalidJournal,
				TransactionPhase::History,
			));
		}
		allowed.insert(name);
		journal = read_journal(&path, manifest.items.len())?;
		journal_path = path;
		next_branch += 1;
	}
	// 許可済みの記録名だけを列挙し、欠けた連番や未知の分岐を見逃さない
	for entry in fs::read_dir(&directory)
		.map_err(|error| TransactionError::io(TransactionPhase::History, &directory, error))?
		.take(MAX_STORES + 132)
	{
		let entry = entry
			.map_err(|error| TransactionError::io(TransactionPhase::History, &directory, error))?;
		// 未知ファイルが混在する履歴は、都合のよい記録だけを選んで復旧しない
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
	// 各 backup を全件照合し、一部の正常な材料だけで復旧可能と判定しない
	for item in &manifest.items {
		verify_raw_backup(&directory.join(&item.backup_name), &item.original)?;
	}
	let states = manifest
		.items
		.iter()
		.enumerate()
		.map(|(index, item)| {
			// 現在分類に加え既存退避物も確認し、未知の証拠がある対象を抑止する
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
		journal_missing: initial_journal_missing && next_branch == 1,
		journal_path,
		next_branch,
		states,
	})
}

//------------------------------------------------------------------------------
/**
 * 変更前に同じ Java を再選択したことと、適用時からの executable/release 不変を要求します。
 *
 * # Errors
 *
 * Java root または三ファイルの保存時 snapshot が、現在の選択済み Java と異なる場合。
 */
//------------------------------------------------------------------------------
fn verify_saved_java(
	environment: &JavaEnvironment,
	manifest: &Manifest,
) -> Result<(), TransactionError> {
	validate_java(environment)?;
	// 保存時と同じ Java の実体を要求し、設定だけ同じ別コピーへの復元を拒否する
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
/**
 * 欠落先は直前に置換開始が永続化され、元実体の recovery copy が一致する場合だけ許可。
 *
 * # Returns
 *
 * 該当項目が置換開始済み・検証未了で、元状態の退避物と一致する場合だけ `true`。
 */
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
/**
 * 同 volume に全復元 stage を準備し、既知状態以外を一切上書きせず順次確定します。
 *
 * # Arguments
 *
 * - `environment`: 保存時と同じ Java。実体・内容・metadata を再照合します。
 * - `options`: 対象履歴を読み取る限定 root。
 * - `id`: 復元または復旧する transaction ID。
 * - `passwords`: inspect_transaction が返した stores 順の認証入力。
 * - `cancellation`: 確定開始前まで監視する中断要求。
 * - `progress`: 同じ worker 上で実行する工程通知。
 * - `recovery`: `true` は未完了の既知状態の復旧、`false` は正常な適用履歴の復元。
 *
 * # Returns
 *
 * 全件を検証した復元・復旧結果。
 *
 * # Errors
 *
 * 履歴と実体の不整合、準備・排他・確定・検証の失敗。
 * 確定を試みた項目は逆順で直前状態へ戻し、元失敗と rollback 失敗を保持します。
 */
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
	// manifest 順の認証数を要求し、位置がずれた秘密を別ストアへ試行しない
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
	// ソート済みの全対象を lock し、他 instance と重なる復元を開始しない
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
	// 復旧と通常復元の工程通知を分け、確定の方針を明示する
	let phase = if recovery {
		TransactionPhase::Recovery
	} else {
		TransactionPhase::Restore
	};
	// 通常復元は完全な適用済み状態を要求し、破断や混在は明示復旧へ分ける
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
	// 全対象の現在状態を先に検査し、未知内容の対象を準備開始前に拒否する
	for (index, state) in loaded.states.iter().enumerate() {
		// 未知実体や復旧根拠のない欠落を、自動上書きの対象にしない
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
		// 存在する実体だけの write guard を保持し、根拠付き欠落は別の復旧経路へ渡す
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
		// 既に元状態の対象は stage を作らず、再置換を省く
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
		// 復元 stage の内容・保持 metadata を元状態と照合し、不完全な材料を確定しない
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
	// 未作成または破断の元 journal は保全し、新規 recovery journal へ分岐する
	let mut journal = if loaded.journal_missing || loaded.journal.torn_tail {
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
	// 全件が元状態なら、再置換せず完了記録と全件検証で終了する
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
			// stage がない元状態の対象を省き、準備済みの復元対象だけを確定する
			let Some(stage) = &stages[index] else {
				continue;
			};
			notify(&mut progress, phase, Some(index), count, false);
			verify_saved_java(environment, &loaded.manifest)?;
			// stage 準備中に対象の分類が変化した場合は、古い前提で置換しない
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
			// 存在する対象は確定直前にも実体を検査し、欠落復旧と区別する
			if loaded.states[index] != ItemState::Missing {
				native::check_supported_metadata(target)
					.map_err(|error| native_error(phase, target, error))?;
			}
			let copy = stage.with_extension("recovery");
			let (prepared, _) = snapshot(stage, phase)?;
			restored.push((index, copy.clone()));
			// 検証済み欠落には移動、既存対象には退避付き置換を適用する
			let replacement = if loaded.states[index] == ItemState::Missing {
				native::move_to_missing(stage, target)
			} else {
				native::replace(target, stage, &copy)
			};
			// 置換の失敗時も三つの残存実体を採取し、部分状態の証拠を保つ
			if let Err(failure) = replacement {
				let mut error = native_error(phase, target, failure);
				error.evidence = inspect_artifacts(&[target, stage, &copy]);
				return Err(error);
			}
			finish_replacement(target, &prepared, &item.original)?;
			// 直前の実体がある場合だけ退避物と照合し、競合を元の失敗に追加する
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
		// 確定後も元 inventory と現物を全件照合し、一部だけの復元成功を返さない
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
	// 復元の失敗には直前状態への rollback と、残存状態の全件検査を付けて返す
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
		// 元が全件適用済みで rollback も完全な場合だけ、適用後へ戻った状態を認める
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
/**
 * 復元失敗でも変更済みを逆順で直前状態へ戻し、元失敗と各 rollback 失敗を別々に保持します。
 *
 * # Arguments
 *
 * - `context`: 復元前の snapshot、試行位置、journal と設定の借用。
 * - `progress`: 同じ worker 上で行う、中断不可の復旧通知。
 *
 * # Returns
 *
 * 直前状態への逆順 rollback で発生した全失敗。
 */
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
	// rollback 開始の永続記録に失敗しても、可能な対象の復旧と失敗収集を続ける
	if let Err(error) = append(Some(journal), options, JournalEvent::RollingBack, None) {
		errors.push(error);
	}
	let cancellation = Cancellation::default();
	// 復元で置換を試みた対象を逆順にたどり、操作直前の状態へ戻す
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
			// 直前実体の snapshot がない対象を、推測した内容で再置換しない
			let Some(before) = &previous[index] else {
				return Err(TransactionError::new(
					TransactionCode::RecoveryRequired,
					TransactionPhase::Rollback,
				));
			};
			// 既に操作直前の状態なら、不要な再置換をせず次の対象へ進む
			if verify_snapshot(target, before, false, TransactionPhase::Rollback).is_ok() {
				return Ok(());
			}
			// 既知の元状態から外れた対象は、自動 rollback の上書きを止める
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
			// 逆置換の失敗にも退避物の証拠を付け、主原因を失わない
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
		// 一対象の rollback 失敗を位置付きで収集し、残りの対象も検査する
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
	// 全件が元の適用後状態へ戻れた場合だけ、その完了記録を選ぶ
	let event = if errors.is_empty() && all_applied {
		JournalEvent::RestoreRolledBack
	} else {
		JournalEvent::RecoveryRequired
	};
	// 最後の journal 追記失敗も返し、復旧の記録不全を隠さない
	if let Err(error) = append(Some(journal), options, event, None) {
		errors.push(error);
	}
	errors
}

//------------------------------------------------------------------------------
/**
 * 履歴を読む既存 root の本人/管理者限定 ACL と canonical path を検査します。
 *
 * # Returns
 *
 * 限定 ACL と実体を確認した既存 backup root の canonical path。
 *
 * # Errors
 *
 * root 不在、パス・ACL・directory の検査、または canonicalize の失敗。
 */
//------------------------------------------------------------------------------
fn existing_root(options: &TransactionOptions) -> Result<PathBuf, TransactionError> {
	native::verify_private_directory(&options.backup_root)
		.map_err(|error| native_error(TransactionPhase::History, &options.backup_root, error))?;
	fs::canonicalize(&options.backup_root).map_err(|error| {
		TransactionError::io(TransactionPhase::History, &options.backup_root, error)
	})
}
