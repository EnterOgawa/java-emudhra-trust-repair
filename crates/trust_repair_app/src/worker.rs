//------------------------------------------------------------------------------
/*!
 * - ファイル: worker.rs
 * - 概要: GUI の一操作を単一所有 thread で実行し、型付き channel で結果を返します
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
 * UI は join 完了まで次の worker を作りません。password の Debug・保存は行いません
 */
//------------------------------------------------------------------------------

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};

use trust_repair_core::{ChangePlan, PlanError, embedded_policy};
use trust_repair_windows::{
	BuiltinPasswords, Cancellation, CustomStore, HistoryEntry, HistoryState, JavaEnvironment,
	JavaError, ScanGroup, ScanProgress, StorePassword, TransactionError, TransactionInspection,
	TransactionOptions, TransactionOutcome, TransactionProgress, apply_transaction,
	inspect_transaction, list_history, recover_transaction, restore_transaction, scan_java,
	select_java,
};

/// 診断から計画まで同じ実体を所有する、未適用の読み取り結果です
pub struct Diagnosis {
	/// 検証済みの選択 Java
	pub environment: JavaEnvironment,
	/// 全群の診断
	pub group: ScanGroup,
	/// 部分成功を許さない変更計画
	pub plan: Result<ChangePlan, PlanError>,
	/// 選択Java内と同Javaの従来backupだけを照合した履歴
	pub history: Vec<HistoryEntry>,
}

impl Diagnosis {
	//------------------------------------------------------------------------------
	/**
	 * 診断群内の実OS権限不足だけを調べます。鍵・形式・SACL実在等を管理者不足へ変換しません
	 */
	//------------------------------------------------------------------------------
	pub fn needs_administrator(&self) -> bool {
		self.group
			.stores()
			.iter()
			.filter_map(|store| store.failure())
			.any(scan_permission)
	}
}

/// 一操作だけに移動する認証入力です。診断後も同じ操作中だけ保持し、終了時に消去します
pub struct Credentials {
	/// cacerts と、存在時に必要な jssecacerts の明示入力
	pub builtin: (StorePassword, Option<StorePassword>),
	/// 明示追加したストアとその入力
	pub custom: Vec<CustomStore>,
}

/// worker に渡す一操作。秘密を含むので Debug を実装しません
pub enum Command {
	/// 内部 QA だけの、完了通知を送らず終了する worker です
	#[cfg(feature = "gui-qa")]
	QaDisconnect,
	/// 一回の確認後に診断・計画・自動backup・無効化を連続実行します
	Deactivate {
		/// 利用者が選択した Java root
		root: PathBuf,
		/// 一操作中だけ所有する認証入力
		credentials: Credentials,
	},
	/// 詳細設定からだけ読み取り診断します
	Scan {
		/// 利用者が選んだ Java root
		root: PathBuf,
		/// 一操作中だけ所有する認証入力
		credentials: Credentials,
	},
	/// 選択 Java の直近履歴を現物照合して、復元前の一回の確認へ渡します
	PrepareRestore {
		/// 利用者が選択した Java root
		root: PathBuf,
	},
	/// 履歴から元へ戻します
	Restore {
		/// inspect で得た同じ Java root
		root: PathBuf,
		/// 検証済み履歴 ID
		id: String,
		/// 復元確認に表示した実backup root。別rootの同名IDへ流用しません
		backup_root: PathBuf,
		/// 一操作中だけ所有する認証入力
		credentials: Credentials,
		/// 未完了の復旧を選択したか
		recovery: bool,
	},
	/// 安全な保管 root だけから列挙します
	History {
		/// 現在選択しているJavaのroot
		root: PathBuf,
	},
	/// 秘密を含まない画面結果を新規 file だけへ保存します
	Save {
		/// 利用者が指定した出力先
		path: PathBuf,
		/// UI が対象範囲を限定して作った表示用 text
		text: String,
	},
}

/// UI へ戻す完了結果です
pub enum Completed {
	/// 読み取り診断を終えました
	Scan(
		/// 完全な診断群と、その群に対応する変更計画
		Box<Diagnosis>,
	),
	/// 無効化の診断と、変更した場合だけの検証済み結果です
	Deactivated {
		/// 診断の詳細。秘密は含みません
		diagnosis: Box<Diagnosis>,
		/// 対象未検出または変更不可なら None
		outcome: Option<TransactionOutcome>,
	},
	/// 復元候補。対象 Java に履歴がない、または既に元状態なら None
	RestoreReady(
		/// 現物照合済みの復元候補。候補がない場合は None
		Option<Box<TransactionInspection>>,
	),
	/// 適用・復元・復旧の検証済み結果です
	Transaction(
		/// 適用・復元後に backend が検証した全件の状態
		TransactionOutcome,
	),
	/// 現物照合済みの履歴です
	History(
		/// 選択 Java に対応する履歴。個別の失敗も保持します
		Vec<HistoryEntry>,
	),
	/// 新規結果 file を保存しました
	Saved(
		/// 結果を保存したパス。保存本文や秘密は保持しません
		PathBuf,
	),
}

/// worker 失敗は翻訳可能な分類とし、外部出力全文を渡しません
pub enum Failure {
	/// Java を選択できませんでした
	Java(
		/// 選択 Java の型付き失敗
		JavaError,
	),
	/// 必要な password が未入力です
	Process(
		/// 秘密入力または子プロセスの型付き失敗
		trust_repair_windows::ProcessError,
	),
	/// transaction または履歴の検証失敗です
	Transaction(
		/// 全群の変更を開始できなかった計画理由
		TransactionError,
	),
	/// 結果の新規保存失敗です
	Save(
		/// 元の失敗と rollback の失敗を保持する変更結果
		std::io::ErrorKind,
	),
	/// 定義を検証できませんでした
	Policy,
	/// worker の panic または予期しない切断です
	Interrupted,
}

impl Failure {
	//------------------------------------------------------------------------------
	/**
	 * 型付きの実権限不足を、下位原因とrollback原因も含めて主画面の案内へ伝えます
	 */
	//------------------------------------------------------------------------------
	pub fn needs_administrator(&self) -> bool {
		// 命令の下位原因から実権限不足だけを取り出し、他の失敗を管理者不足と誤認しない
		match self {
			Self::Java(value) => java_permission(value),
			Self::Process(value) => process_permission(value),
			Self::Transaction(value) => transaction_permission(value),
			Self::Save(kind) => *kind == std::io::ErrorKind::PermissionDenied,
			_ => false,
		}
	}
}

//------------------------------------------------------------------------------
/**
 * WindowsのAccessDenied・特権未割当て・PrivilegeNotHeldだけを権限不足として扱います
 */
//------------------------------------------------------------------------------
fn permission_code(code: Option<i32>) -> bool {
	matches!(code, Some(5 | 1300 | 1314))
}

//------------------------------------------------------------------------------
/**
 * file安全性の仕様非対応と、OSが返した実権限不足を区別します
 */
//------------------------------------------------------------------------------
fn file_permission(value: &trust_repair_windows::FileSafetyError) -> bool {
	matches!(value, trust_repair_windows::FileSafetyError::Io { os_code, .. } if permission_code(*os_code))
}

//------------------------------------------------------------------------------
/**
 * keytool本文や終了文字列を解析せず、起動時OS codeだけを権限不足へ分類します
 */
//------------------------------------------------------------------------------
fn process_permission(value: &trust_repair_windows::ProcessError) -> bool {
	// process の起動時 OS code だけを調べ、keytool の本文を権限判定へ使わない
	match value {
		trust_repair_windows::ProcessError::Io { os_code, .. } => permission_code(*os_code),
		trust_repair_windows::ProcessError::Cleanup { cause, .. } => process_permission(cause),
		_ => false,
	}
}

//------------------------------------------------------------------------------
/**
 * Java選択の下位file/processの実権限不足を保ちます
 */
//------------------------------------------------------------------------------
fn java_permission(value: &JavaError) -> bool {
	// Java の下位 file/process の分類をたどり、実権限不足を保持する
	match value {
		JavaError::File(value) => file_permission(value),
		JavaError::Process(value) => process_permission(value),
		_ => false,
	}
}

//------------------------------------------------------------------------------
/**
 * 全件診断の型付き原因からだけ、管理者起動案内の必要性を返します
 */
//------------------------------------------------------------------------------
fn scan_permission(value: &trust_repair_windows::ScanFailure) -> bool {
	// 診断の型付き下位原因だけを調べ、解析や内容競合を権限不足へ変換しない
	match value {
		trust_repair_windows::ScanFailure::File(value) => file_permission(value),
		trust_repair_windows::ScanFailure::Java(value) => java_permission(value),
		trust_repair_windows::ScanFailure::Process(value) => process_permission(value),
		_ => false,
	}
}

//------------------------------------------------------------------------------
/**
 * transactionの分類・OS code・各下位原因を調べ、SACL実在や複雑ACLとは区別します
 */
//------------------------------------------------------------------------------
fn transaction_permission(value: &TransactionError) -> bool {
	value.code == trust_repair_windows::TransactionCode::PermissionDenied
		|| permission_code(value.os_code)
		|| value.file_error.as_ref().is_some_and(file_permission)
		|| value.java_error.as_ref().is_some_and(java_permission)
		|| value.process_error.as_ref().is_some_and(process_permission)
		|| value.scan_error.as_ref().is_some_and(scan_permission)
		|| value.rollback_errors.iter().any(transaction_permission)
}

/// 所有 worker からの型付き通知です
pub enum Event {
	/// 実際の診断工程です
	Scan(
		/// 呼出し側の表示言語で案内する工程名
		ScanProgress,
	),
	/// 実際の書換え工程と中断可否です
	Transaction(
		/// この工程中に安全な中断を受け付けるか
		TransactionProgress,
	),
	/// 成功・失敗を混同しない一度だけの完了結果です
	Done(
		/// thread 回収後に一度だけ採用する操作の完了結果
		Result<Completed, Failure>,
	),
}

/// UI が join するまで所有する worker です
pub struct Worker {
	/// UI が停止要求を共有する token
	pub cancellation: Cancellation,
	/// この操作の通知受信先
	pub receiver: Receiver<Event>,
	/// 完了時とアプリ終了時に必ず回収する thread
	pub handle: JoinHandle<()>,
}

//------------------------------------------------------------------------------
/**
 * 一操作の所有権を worker へ移します。thread 起動失敗時は秘密を drop して OS error を返します
 *
 * # Arguments
 *
 * - `command`: 秘密を含む一操作の所有入力。開始した thread が受け取ります
 * - `options`: 従来履歴 root と明示設定。thread の終了まで所有します
 * - `context`: 通知送信後の再描画に使用する複製可能な context
 *
 * # Returns
 *
 * 中断 token、通知 receiver、必ず join する thread の所有者
 *
 * # Errors
 *
 * thread の開始失敗。移動した命令と秘密は破棄され、実行は開始しません
 *
 * # Notes
 *
 * 命令終了後に Done を送ります。受信側の消滅で送信が失敗しても、操作の後始末は継続します
 */
//------------------------------------------------------------------------------
pub fn start(
	command: Command,
	options: TransactionOptions,
	context: eframe::egui::Context,
) -> Result<Worker, std::io::Error> {
	let cancellation = Cancellation::default();
	let token = cancellation.clone();
	let (sender, receiver) = mpsc::channel();
	let handle = thread::Builder::new()
		.name("trust-repair-worker".to_owned())
		.spawn(move || {
			#[cfg(feature = "gui-qa")]
			// 明示 QA の切断命令だけで Done のない thread 終了を再現する
			if matches!(command, Command::QaDisconnect) {
				drop(command);
				context.request_repaint();
				return;
			}
			// panic payload は入力を含み得るため通知へ複写せず、失敗分類だけを返す
			let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
				execute(command, &options, &token, &sender, &context)
			}))
			.unwrap_or(Err(Failure::Interrupted));
			let _receiver_closed = sender.send(Event::Done(result));
			context.request_repaint();
		})?;
	Ok(Worker {
		cancellation,
		receiver,
		handle,
	})
}

//------------------------------------------------------------------------------
/**
 * 同じ worker で全 I/O を実行します。秘密の借用は操作内に限定し、完了前に所有入力を drop します
 *
 * # Arguments
 *
 * - `command`: 今回実行する所有入力。認証は操作中だけ借用します
 * - `options`: 従来 root の参照と、許可した復元元の確認に用いる設定
 * - `cancellation`: 安全な工程で受け付ける共有中断要求
 * - `sender`: 同じ操作の工程通知先
 * - `context`: 工程通知に伴う再描画の要求先
 *
 * # Returns
 *
 * 実際の命令種別に対応する完了結果
 *
 * # Errors
 *
 * Java 選択・認証対応・履歴・診断準備・変更処理・新規保存の失敗。
 * 変更処理の部分状態と rollback 失敗は下位の型付きエラーを保持します
 */
//------------------------------------------------------------------------------
fn execute(
	command: Command,
	options: &TransactionOptions,
	cancellation: &Cancellation,
	sender: &Sender<Event>,
	context: &eframe::egui::Context,
) -> Result<Completed, Failure> {
	// 所有命令の種類ごとに I/O を実行し、認証入力を操作終了時までに破棄する
	match command {
		#[cfg(feature = "gui-qa")]
		Command::QaDisconnect => Err(Failure::Interrupted),
		Command::Deactivate { root, credentials } => {
			let mut diagnosis =
				diagnose(&root, &credentials, options, cancellation, sender, context)?;
			let local_options = TransactionOptions::for_java(&diagnosis.environment)
				.map_err(Failure::Transaction)?;
			// 同じJavaの直近未完了がある場合、新しい変更より復旧確認を優先する
			if let Some(value) = std::mem::take(&mut diagnosis.history)
				.into_iter()
				.filter_map(|entry| entry.inspection.ok())
				.find(|entry| {
					entry.java_root == diagnosis.environment.root()
						|| entry.backup_directory.parent() == Some(local_options.backup_root())
				}) && matches!(
				value.state,
				HistoryState::Recoverable
					| HistoryState::RecoveryRequired
					| HistoryState::IncompletePreparation
					| HistoryState::Invalid
			) {
				return Ok(Completed::RestoreReady(Some(Box::new(value))));
			}
			// 全群の計画が合格した場合だけ適用し、対象ゼロや抑止理由を結果に残す
			let outcome = if let Ok(plan) = &diagnosis.plan {
				let paths: Vec<_> = diagnosis
					.group
					.stores()
					.iter()
					.filter_map(|store| {
						store
							.snapshot()
							.map(|snapshot| snapshot.canonical_path().to_path_buf())
					})
					.collect();
				let passwords = passwords_for(&diagnosis.environment, &paths, &credentials)?;
				Some(
					apply_transaction(
						&diagnosis.environment,
						&diagnosis.group,
						plan,
						&passwords,
						&local_options,
						cancellation,
						|progress| notify(sender, context, Event::Transaction(progress)),
					)
					.map_err(Failure::Transaction)?,
				)
			} else {
				None
			};
			Ok(Completed::Deactivated {
				diagnosis: Box::new(diagnosis),
				outcome,
			})
		}
		Command::Scan { root, credentials } => {
			diagnose(&root, &credentials, options, cancellation, sender, context)
				.map(|value| Completed::Scan(Box::new(value)))
		}
		Command::PrepareRestore { root } => {
			let environment = select_java(&root, cancellation).map_err(Failure::Java)?;
			let local_options =
				TransactionOptions::for_java(&environment).map_err(Failure::Transaction)?;
			let entries = history_for_java(&environment, options)?;
			let candidate = entries
				.into_iter()
				.filter_map(|entry| entry.inspection.ok())
				.find(|entry| {
					entry.java_root == environment.root()
						|| entry.backup_directory.parent() == Some(local_options.backup_root())
				});
			let candidate = candidate.filter(|entry| {
				!matches!(
					entry.state,
					HistoryState::Restored | HistoryState::RolledBack
				)
			});
			Ok(Completed::RestoreReady(candidate.map(Box::new)))
		}
		Command::Restore {
			root,
			id,
			backup_root,
			credentials,
			recovery,
		} => {
			let environment = select_java(&root, cancellation).map_err(Failure::Java)?;
			let local_options =
				TransactionOptions::for_java(&environment).map_err(Failure::Transaction)?;
			// 現選択のJava内rootか、明示した従来rootだけを使う。別Javaのrootへfallbackしない
			let selected_options = if backup_root == local_options.backup_root() {
				&local_options
			}
			// 明示した従来 root の正規実体と一致する場合だけ、互換復元の保存先として採用する
			else if std::fs::canonicalize(options.backup_root()).ok().as_ref()
				== Some(&backup_root)
			{
				options
			} else {
				return Err(Failure::Policy);
			};
			let inspection =
				inspect_transaction(selected_options, &id).map_err(Failure::Transaction)?;
			// 保存時 Java と現在の選択が異なる場合は、同じ履歴を別環境へ復元しない
			if inspection.java_root != environment.root() {
				return Err(Failure::Policy);
			}
			let passwords = passwords_for(&environment, &inspection.stores, &credentials)?;
			let progress = |progress| notify(sender, context, Event::Transaction(progress));
			// 明示復旧と正常復元を分け、それぞれの backend の検証条件を守る
			let outcome = if recovery {
				recover_transaction(
					&environment,
					selected_options,
					&id,
					&passwords,
					cancellation,
					progress,
				)
			} else {
				restore_transaction(
					&environment,
					selected_options,
					&id,
					&passwords,
					cancellation,
					progress,
				)
			};
			outcome
				.map(Completed::Transaction)
				.map_err(Failure::Transaction)
		}
		Command::History { root } => {
			let environment = select_java(&root, cancellation).map_err(Failure::Java)?;
			history_for_java(&environment, options).map(Completed::History)
		}
		Command::Save { path, text } => {
			let mut file = OpenOptions::new()
				.write(true)
				.create_new(true)
				.open(&path)
				.map_err(|error| Failure::Save(error.kind()))?;
			file.write_all(text.as_bytes())
				.and_then(|_| file.flush())
				.and_then(|_| file.sync_all())
				.map_err(|error| Failure::Save(error.kind()))?;
			Ok(Completed::Saved(path))
		}
	}
}

//------------------------------------------------------------------------------
/**
 * 同じ Java と明示入力で群全体を診断します。失敗・警告を含む plan は適用へ進めません
 *
 * # Arguments
 *
 * - `root`: 利用者が選択した Java の元パス
 * - `credentials`: 標準二種と明示 custom の認証入力
 * - `legacy_options`: 同じ Java に属する従来履歴の参照先
 * - `cancellation`: Java と各 keytool 実行で監視する中断要求
 * - `sender`: 診断の工程通知先
 * - `context`: 通知後の再描画先
 *
 * # Returns
 *
 * Java・全診断群・計画の成否・対応履歴を所有する結果。
 * 個々のストアの診断失敗は群内に残し、計画の失敗として保持します
 *
 * # Errors
 *
 * Java・履歴の取得、または実在する jssecacerts の明示入力不足
 */
//------------------------------------------------------------------------------
fn diagnose(
	root: &std::path::Path,
	credentials: &Credentials,
	legacy_options: &TransactionOptions,
	cancellation: &Cancellation,
	sender: &Sender<Event>,
	context: &eframe::egui::Context,
) -> Result<Diagnosis, Failure> {
	let policy = embedded_policy().map_err(|_| Failure::Policy)?;
	let environment = select_java(root, cancellation).map_err(Failure::Java)?;
	let history = history_for_java(&environment, legacy_options)?;
	// jssecacerts が実在する場合は専用入力を要求し、不在時だけ未使用の引数を補う
	let jssecacerts = if environment.candidate_stores().len() > 1 {
		credentials.builtin.1.as_ref().ok_or(Failure::Process(
			trust_repair_windows::ProcessError::InvalidPassword,
		))?
	} else {
		&credentials.builtin.0
	};
	let group = scan_java(
		&environment,
		&policy,
		&BuiltinPasswords {
			cacerts: &credentials.builtin.0,
			jssecacerts,
		},
		&credentials.custom,
		cancellation,
		|progress| notify(sender, context, Event::Scan(progress)),
	);
	let plan = group.plan(&policy);
	Ok(Diagnosis {
		environment,
		group,
		plan,
		history,
	})
}

//------------------------------------------------------------------------------
/**
 * Java内履歴と同じJavaの従来履歴を読み取ります。directoryは作成せず、未知の旧記録は詳細へ残します
 *
 * # Arguments
 *
 * - `environment`: 履歴の保存時 Java と一致すべき選択結果
 * - `legacy_options`: 同じ Java の旧履歴を探す従来 root
 *
 * # Returns
 *
 * 同じ Java の履歴を ID 降順に並べ、その後に未帰属・不正な旧記録を残した一覧
 *
 * # Errors
 *
 * Java 内履歴の読込み・個別照合失敗、または従来 root の実権限不足
 */
//------------------------------------------------------------------------------
fn history_for_java(
	environment: &JavaEnvironment,
	legacy_options: &TransactionOptions,
) -> Result<Vec<HistoryEntry>, Failure> {
	let local_options = TransactionOptions::for_java(environment).map_err(Failure::Transaction)?;
	let mut entries = Vec::new();
	// Java 内履歴は全件照合し、不正な新規記録があれば操作の開始を止める
	for entry in list_history(&local_options).map_err(Failure::Transaction)? {
		let inspection = entry.inspection.map_err(Failure::Transaction)?;
		entries.push(HistoryEntry {
			transaction_id: entry.transaction_id,
			inspection: Ok(inspection),
		});
	}
	let mut unassigned = Vec::new();
	// 従来 root の実権限不足は失敗として返し、他の不正記録は詳細表示用に保持する
	let legacy_entries = match list_history(legacy_options) {
		Ok(entries) => entries,
		Err(error) if transaction_permission(&error) => return Err(Failure::Transaction(error)),
		Err(error) => vec![HistoryEntry {
			transaction_id: "legacy-backups".to_owned(),
			inspection: Err(error),
		}],
	};
	// 全旧履歴を調べ、同じ Java と未帰属・不正の証拠をそれぞれ保持する
	for entry in legacy_entries {
		// 別 Java の履歴を通常候補へ入れず、未帰属の記録は詳細へ残す
		match &entry.inspection {
			Ok(value) if value.java_root == environment.root() => entries.push(entry),
			Ok(value) if value.java_root.as_os_str().is_empty() => unassigned.push(entry),
			Err(_) => unassigned.push(entry),
			_ => {}
		}
	}
	entries.sort_by(|left, right| right.transaction_id.cmp(&left.transaction_id));
	// 保存時Javaを特定できない従来記録は上書きせず、通常の復元候補から分離して表示する
	entries.extend(unassigned);
	Ok(entries)
}

//------------------------------------------------------------------------------
/**
 * 検証済み store 順へ明示入力を対応させます。未知の path で別passwordを自動試行しません
 *
 * # Arguments
 *
 * - `environment`: 標準ストアの canonical path を求める選択済み Java
 * - `paths`: 返す認証の順序を決める、検証済みの対象パス
 * - `credentials`: 返す秘密の参照を所有する一操作分の認証入力
 *
 * # Returns
 *
 * paths と同じ順に並べた秘密の借用。新しい秘密を生成・保存しません
 *
 * # Errors
 *
 * 供給済みパスの正規化失敗、または対象に対応する認証入力がない場合
 */
//------------------------------------------------------------------------------
fn passwords_for<'a>(
	environment: &JavaEnvironment,
	paths: &[PathBuf],
	credentials: &'a Credentials,
) -> Result<Vec<&'a StorePassword>, Failure> {
	let mut supplied = vec![(
		std::fs::canonicalize(environment.root().join("lib/security/cacerts"))
			.map_err(|_| Failure::Policy)?,
		&credentials.builtin.0,
	)];
	// jssecacerts の入力が明示されている場合だけ、その実在パスに対応付ける
	if let Some(password) = &credentials.builtin.1 {
		let path = environment.root().join("lib/security/jssecacerts");
		// 不在の jssecacerts は別ストアへの入力として流用しない
		if path.exists() {
			supplied.push((
				std::fs::canonicalize(path).map_err(|_| Failure::Policy)?,
				password,
			));
		}
	}
	// 全 custom の元パスを正規化し、検証済み対象への認証対応を作る
	for store in &credentials.custom {
		supplied.push((
			std::fs::canonicalize(&store.path).map_err(|_| Failure::Policy)?,
			&store.password,
		));
	}
	paths
		.iter()
		.map(|path| {
			supplied
				.iter()
				.find(|(known, _)| known == path)
				.map(|(_, password)| *password)
				.ok_or(Failure::Process(
					trust_repair_windows::ProcessError::InvalidPassword,
				))
		})
		.collect()
}

//------------------------------------------------------------------------------
/**
 * 型付き工程を送信し再描画を要求します。受信側が消えても backend の後始末は継続します
 */
//------------------------------------------------------------------------------
fn notify(sender: &Sender<Event>, context: &eframe::egui::Context, event: Event) {
	let _receiver_closed = sender.send(event);
	context.request_repaint();
}

/// 実Javaを受け付けない明示fixtureで、旧rootとの互換復元を縦に検証します
#[cfg(test)]
mod tests {
	use super::*;

	//------------------------------------------------------------------------------
	/**
	 * 既存を上書きせず、通常file/directoryだけを所有試験領域へコピーします
	 */
	//------------------------------------------------------------------------------
	fn copy_fixture(source: &std::path::Path, destination: &std::path::Path) {
		std::fs::create_dir(destination).expect("new fixture directory");
		// 所有試験領域の全入力を列挙し、reparse を拒否して新規コピーだけを作る
		for entry in std::fs::read_dir(source).expect("fixture source") {
			let entry = entry.expect("source entry");
			let kind = entry.file_type().expect("fixture type");
			// 通常 directory は再帰コピーし、通常 file は新規作成でコピーする
			if kind.is_dir() {
				copy_fixture(&entry.path(), &destination.join(entry.file_name()));
			} else {
				assert!(kind.is_file());
				std::fs::copy(entry.path(), destination.join(entry.file_name())).expect("new file");
			}
		}
	}

	//------------------------------------------------------------------------------
	/**
	 * fixtureの非秘密passwordだけを、一操作の所有入力へ渡します
	 */
	//------------------------------------------------------------------------------
	fn credentials(root: &std::path::Path) -> Credentials {
		let secret = || StorePassword::new("changeit".to_owned()).expect("test password");
		Credentials {
			builtin: (secret(), Some(secret())),
			custom: ["custom 日本語.jks", "custom 日本語.p12"]
				.into_iter()
				.map(|name| CustomStore {
					path: root.join(name),
					password: secret(),
				})
				.collect(),
		}
	}

	//------------------------------------------------------------------------------
	/**
	 * 専用の旧 LocalAppData 相当 root を同じ Java にだけ対応させます。
	 * 旧 root からの復元後、新規保存先が Java 内に限定されることを確認します
	 */
	//------------------------------------------------------------------------------
	#[test]
	#[ignore = "JTR_LOCAL_BACKUP_FIXTURESで新規隔離領域を明示"]
	fn restores_legacy_history_and_creates_new_backups_only_inside_selected_java() {
		let fixtures = PathBuf::from(
			std::env::var_os("JTR_LOCAL_BACKUP_FIXTURES").expect("explicit fixtures"),
		)
		.canonicalize()
		.expect("fixture root");
		let allowed = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
			.join("../../artifacts/jdk-local-backup")
			.canonicalize()
			.expect("allowed QA root");
		assert!(fixtures.starts_with(allowed));
		let root = fixtures.join(format!("worker-{}", std::process::id()));
		std::fs::create_dir(&root).expect("new worker case");
		let java = root.join("Java");
		copy_fixture(&fixtures.join("Java 21 適用 復元"), &java);
		// 両形式の custom を新規 case へ複写し、以後の適用と復元を元 fixture から隔離する
		for name in ["custom 日本語.jks", "custom 日本語.p12"] {
			std::fs::copy(fixtures.join(name), root.join(name)).expect("new custom store");
		}
		let legacy = TransactionOptions::with_backup_root(
			root.join("LocalAppData/EnterSystem/JavaTrustRepair/backups"),
		)
		.expect("isolated legacy root");
		let context = eframe::egui::Context::default();
		let (sender, _receiver) = mpsc::channel();
		let token = Cancellation::default();
		let diagnosis = diagnose(
			&java,
			&credentials(&root),
			&legacy,
			&token,
			&sender,
			&context,
		)
		.unwrap_or_else(|_| panic!("initial read-only diagnosis"));
		let local = TransactionOptions::for_java(&diagnosis.environment).expect("local root");
		assert!(!local.backup_root().exists() && !legacy.backup_root().exists());
		let original: Vec<_> = diagnosis
			.group
			.stores()
			.iter()
			.map(|store| store.snapshot().expect("original snapshot").clone())
			.collect();
		let secret = StorePassword::new("changeit".to_owned()).expect("fixture password");
		let outcome = apply_transaction(
			&diagnosis.environment,
			&diagnosis.group,
			diagnosis.plan.as_ref().expect("plan"),
			&vec![&secret; diagnosis.group.stores().len()],
			&legacy,
			&token,
			|_| {},
		)
		.expect("previous-version apply fixture");
		let other = root.join("Other Java");
		copy_fixture(&fixtures.join("Java 21 適用 復元"), &other);
		let other_environment = select_java(&other, &token).expect("other Java");
		assert!(
			history_for_java(&other_environment, &legacy)
				.unwrap_or_else(|_| panic!("other history"))
				.is_empty()
		);
		assert!(!other.join("emudhra-backup").exists());
		let ready = execute(
			Command::PrepareRestore { root: java.clone() },
			&legacy,
			&token,
			&sender,
			&context,
		)
		.unwrap_or_else(|_| panic!("legacy prepare restore"));
		// 実際の復元候補が得られた場合だけ、旧 root からの復元を検証する
		let Completed::RestoreReady(Some(inspection)) = ready else {
			panic!("legacy candidate");
		};
		assert_eq!(inspection.backup_directory, outcome.backup_directory);
		assert_eq!(
			inspection.backup_directory.parent(),
			Some(
				legacy
					.backup_root()
					.canonicalize()
					.expect("legacy canonical")
					.as_path()
			)
		);
		let result = execute(
			Command::Restore {
				root: java.clone(),
				id: inspection.transaction_id,
				backup_root: inspection
					.backup_directory
					.parent()
					.expect("bound legacy root")
					.to_path_buf(),
				credentials: credentials(&root),
				recovery: false,
			},
			&legacy,
			&token,
			&sender,
			&context,
		)
		.unwrap_or_else(|_| panic!("legacy restoration"));
		assert!(matches!(
			result,
			Completed::Transaction(value)
				if value.state == trust_repair_windows::TransactionState::Restored
		));
		assert!(!local.backup_root().exists());
		let result = execute(
			Command::Deactivate {
				root: java.clone(),
				credentials: credentials(&root),
			},
			&legacy,
			&token,
			&sender,
			&context,
		)
		.unwrap_or_else(|_| panic!("new Java-local apply"));
		// 検証済みの適用結果を取得し、新規保存先が Java 内に限定されたことを確認する
		let Completed::Deactivated {
			outcome: Some(outcome),
			..
		} = result
		else {
			panic!("new local transaction");
		};
		assert_eq!(outcome.backup_directory.parent(), Some(local.backup_root()));
		let result = execute(
			Command::Restore {
				root: java,
				id: outcome.transaction_id,
				backup_root: local.backup_root().to_path_buf(),
				credentials: credentials(&root),
				recovery: false,
			},
			&legacy,
			&token,
			&sender,
			&context,
		)
		.unwrap_or_else(|_| panic!("new local restore"));
		assert!(matches!(
			result,
			Completed::Transaction(value)
				if value.state == trust_repair_windows::TransactionState::Restored
		));
		// 全元 snapshot を再照合し、復元後の内容と保持 metadata を確認する
		for snapshot in original {
			assert_eq!(
				trust_repair_core::sha256_hex(
					&std::fs::read(snapshot.canonical_path()).expect("restored bytes")
				),
				snapshot.sha256()
			);
		}
	}
}
