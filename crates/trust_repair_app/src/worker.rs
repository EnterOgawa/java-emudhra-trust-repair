//------------------------------------------------------------------------------
/*!
 * - ファイル: worker.rs
 * - 概要: GUI の一操作を単一所有 thread で実行し、型付き channel で結果を返します。
 * - バージョン: 01.02.00
 * - 作成日: 2026/10/26
 * - 制作者: Shunji Ogawa
 * - 著作権: Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * ライセンス: SPDX-License-Identifier: Apache-2.0
 * Apache License, Version 2.0。全文はルートの LICENSE を参照してください。
 *
 * 会社名: EnterSystem
 *
 * 更新履歴:
 * ```text
 * Ver.01.00.00  Shunji Ogawa  2026/10/26  診断・適用・復元・復旧・履歴・結果保存を接続。
 * Ver.01.00.01  Shunji Ogawa  2026/10/26  明示 QA build だけで実 channel 切断を再現可能にした。
 * Ver.01.01.00  Shunji Ogawa  2026/10/26  一操作内の診断・自動backup・無効化と直近復元を接続。
 * Ver.01.02.00  Shunji Ogawa  2026/10/26  Java内backupと従来履歴の読み取り互換、復元rootの拘束を追加。
 * ```
 *
 * 備考: UI は join 完了まで次の worker を作りません。password の Debug・保存は行いません。
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

/// 診断から計画まで同じ実体を所有する、未適用の読み取り結果です。
pub struct Diagnosis {
	/// 検証済みの選択 Java。
	pub environment: JavaEnvironment,
	/// 全群の診断。
	pub group: ScanGroup,
	/// 部分成功を許さない変更計画。
	pub plan: Result<ChangePlan, PlanError>,
	/// 選択Java内と同Javaの従来backupだけを照合した履歴。
	pub history: Vec<HistoryEntry>,
}

impl Diagnosis {
	//------------------------------------------------------------------------------
	/** 診断群内の実OS権限不足だけを調べます。鍵・形式・SACL実在等を管理者不足へ変換しません。 */
	//------------------------------------------------------------------------------
	pub fn needs_administrator(&self) -> bool {
		self.group
			.stores()
			.iter()
			.filter_map(|store| store.failure())
			.any(scan_permission)
	}
}

/// 一操作だけに移動する認証入力です。診断後も同じ操作中だけ保持し、終了時に消去します。
pub struct Credentials {
	/// cacerts と、存在時に必要な jssecacerts の明示入力。
	pub builtin: (StorePassword, Option<StorePassword>),
	/// 明示追加したストアとその入力。
	pub custom: Vec<CustomStore>,
}

/// worker に渡す一操作。秘密を含むので Debug を実装しません。
pub enum Command {
	/// 内部 QA だけの、完了通知を送らず終了する worker です。
	#[cfg(feature = "gui-qa")]
	QaDisconnect,
	/// 一回の確認後に診断・計画・自動backup・無効化を連続実行します。
	Deactivate {
		/// 利用者が選択した Java root。
		root: PathBuf,
		/// 一操作中だけ所有する認証入力。
		credentials: Credentials,
	},
	/// 詳細設定からだけ読み取り診断します。
	Scan {
		/// 利用者が選んだ Java root。
		root: PathBuf,
		/// 一操作中だけ所有する認証入力。
		credentials: Credentials,
	},
	/// 選択 Java の直近履歴を現物照合して、復元前の一回の確認へ渡します。
	PrepareRestore {
		/// 利用者が選択した Java root。
		root: PathBuf,
	},
	/// 履歴から元へ戻します。
	Restore {
		/// inspect で得た同じ Java root。
		root: PathBuf,
		/// 検証済み履歴 ID。
		id: String,
		/// 復元確認に表示した実backup root。別rootの同名IDへ流用しません。
		backup_root: PathBuf,
		/// 一操作中だけ所有する認証入力。
		credentials: Credentials,
		/// 未完了の復旧を選択したか。
		recovery: bool,
	},
	/// 安全な保管 root だけから列挙します。
	History {
		/// 現在選択しているJavaのroot。
		root: PathBuf,
	},
	/// 秘密を含まない画面結果を新規 file だけへ保存します。
	Save {
		/// 利用者が指定した出力先。
		path: PathBuf,
		/// UI が対象範囲を限定して作った表示用 text。
		text: String,
	},
}

/// UI へ戻す完了結果です。
pub enum Completed {
	/// 読み取り診断を終えました。
	Scan(Box<Diagnosis>),
	/// 無効化の診断と、変更した場合だけの検証済み結果です。
	Deactivated {
		/// 診断の詳細。秘密は含みません。
		diagnosis: Box<Diagnosis>,
		/// 対象未検出または変更不可なら None。
		outcome: Option<TransactionOutcome>,
	},
	/// 復元候補。対象 Java に履歴がない、または既に元状態なら None。
	RestoreReady(Option<Box<TransactionInspection>>),
	/// 適用・復元・復旧の検証済み結果です。
	Transaction(TransactionOutcome),
	/// 現物照合済みの履歴です。
	History(Vec<HistoryEntry>),
	/// 新規結果 file を保存しました。
	Saved(PathBuf),
}

/// worker 失敗は翻訳可能な分類とし、外部出力全文を渡しません。
pub enum Failure {
	/// Java を選択できませんでした。
	Java(JavaError),
	/// 必要な password が未入力です。
	Process(trust_repair_windows::ProcessError),
	/// transaction または履歴の検証失敗です。
	Transaction(TransactionError),
	/// 結果の新規保存失敗です。
	Save(std::io::ErrorKind),
	/// 定義を検証できませんでした。
	Policy,
	/// worker の panic または予期しない切断です。
	Interrupted,
}

impl Failure {
	//------------------------------------------------------------------------------
	/** 型付きの実権限不足を、下位原因とrollback原因も含めて主画面の案内へ伝えます。 */
	//------------------------------------------------------------------------------
	pub fn needs_administrator(&self) -> bool {
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
/** WindowsのAccessDenied・特権未割当て・PrivilegeNotHeldだけを権限不足として扱います。 */
//------------------------------------------------------------------------------
fn permission_code(code: Option<i32>) -> bool {
	matches!(code, Some(5 | 1300 | 1314))
}

//------------------------------------------------------------------------------
/** file安全性の仕様非対応と、OSが返した実権限不足を区別します。 */
//------------------------------------------------------------------------------
fn file_permission(value: &trust_repair_windows::FileSafetyError) -> bool {
	matches!(value, trust_repair_windows::FileSafetyError::Io { os_code, .. } if permission_code(*os_code))
}

//------------------------------------------------------------------------------
/** keytool本文や終了文字列を解析せず、起動時OS codeだけを権限不足へ分類します。 */
//------------------------------------------------------------------------------
fn process_permission(value: &trust_repair_windows::ProcessError) -> bool {
	match value {
		trust_repair_windows::ProcessError::Io { os_code, .. } => permission_code(*os_code),
		trust_repair_windows::ProcessError::Cleanup { cause, .. } => process_permission(cause),
		_ => false,
	}
}

//------------------------------------------------------------------------------
/** Java選択の下位file/processの実権限不足を保ちます。 */
//------------------------------------------------------------------------------
fn java_permission(value: &JavaError) -> bool {
	match value {
		JavaError::File(value) => file_permission(value),
		JavaError::Process(value) => process_permission(value),
		_ => false,
	}
}

//------------------------------------------------------------------------------
/** 全件診断の型付き原因からだけ、管理者起動案内の必要性を返します。 */
//------------------------------------------------------------------------------
fn scan_permission(value: &trust_repair_windows::ScanFailure) -> bool {
	match value {
		trust_repair_windows::ScanFailure::File(value) => file_permission(value),
		trust_repair_windows::ScanFailure::Java(value) => java_permission(value),
		trust_repair_windows::ScanFailure::Process(value) => process_permission(value),
		_ => false,
	}
}

//------------------------------------------------------------------------------
/** transactionの分類・OS code・各下位原因を調べ、SACL実在や複雑ACLとは区別します。 */
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

/// 所有 worker からの型付き通知です。
pub enum Event {
	/// 実際の診断工程です。
	Scan(ScanProgress),
	/// 実際の書換え工程と中断可否です。
	Transaction(TransactionProgress),
	/// 成功・失敗を混同しない一度だけの完了結果です。
	Done(Result<Completed, Failure>),
}

/// UI が join するまで所有する worker です。
pub struct Worker {
	/// UI が停止要求を共有する token。
	pub cancellation: Cancellation,
	/// この操作の通知受信先。
	pub receiver: Receiver<Event>,
	/// 完了時とアプリ終了時に必ず回収する thread。
	pub handle: JoinHandle<()>,
}

//------------------------------------------------------------------------------
/** 一操作の所有権を worker へ移します。thread 起動失敗時は秘密を drop して OS error を返します。 */
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
/** 同じ worker で全 I/O を実行します。秘密の借用は操作内に限定し、完了前に所有入力を drop します。 */
//------------------------------------------------------------------------------
fn execute(
	command: Command,
	options: &TransactionOptions,
	cancellation: &Cancellation,
	sender: &Sender<Event>,
	context: &eframe::egui::Context,
) -> Result<Completed, Failure> {
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
			} else if std::fs::canonicalize(options.backup_root()).ok().as_ref()
				== Some(&backup_root)
			{
				options
			} else {
				return Err(Failure::Policy);
			};
			let inspection =
				inspect_transaction(selected_options, &id).map_err(Failure::Transaction)?;
			if inspection.java_root != environment.root() {
				return Err(Failure::Policy);
			}
			let passwords = passwords_for(&environment, &inspection.stores, &credentials)?;
			let progress = |progress| notify(sender, context, Event::Transaction(progress));
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
/** 同じ Java と明示入力で群全体を診断します。失敗・警告を含む plan は適用へ進めません。 */
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
/** Java内履歴と同じJavaの従来履歴を読み取ります。directoryは作成せず、未知の旧記録は詳細へ残します。 */
//------------------------------------------------------------------------------
fn history_for_java(
	environment: &JavaEnvironment,
	legacy_options: &TransactionOptions,
) -> Result<Vec<HistoryEntry>, Failure> {
	let local_options = TransactionOptions::for_java(environment).map_err(Failure::Transaction)?;
	let mut entries = Vec::new();
	for entry in list_history(&local_options).map_err(Failure::Transaction)? {
		let inspection = entry.inspection.map_err(Failure::Transaction)?;
		entries.push(HistoryEntry {
			transaction_id: entry.transaction_id,
			inspection: Ok(inspection),
		});
	}
	let mut unassigned = Vec::new();
	let legacy_entries = match list_history(legacy_options) {
		Ok(entries) => entries,
		Err(error) if transaction_permission(&error) => return Err(Failure::Transaction(error)),
		Err(error) => vec![HistoryEntry {
			transaction_id: "legacy-backups".to_owned(),
			inspection: Err(error),
		}],
	};
	for entry in legacy_entries {
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
/** 検証済み store 順へ明示入力を対応させます。未知の path で別passwordを自動試行しません。 */
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
/** 型付き工程を送信し再描画を要求します。受信側が消えても backend の後始末は継続します。 */
//------------------------------------------------------------------------------
fn notify(sender: &Sender<Event>, context: &eframe::egui::Context, event: Event) {
	let _receiver_closed = sender.send(event);
	context.request_repaint();
}

/// 実Javaを受け付けない明示fixtureで、旧rootとの互換復元を縦に検証します。
#[cfg(test)]
mod tests {
	use super::*;

	//------------------------------------------------------------------------------
	/** 既存を上書きせず、通常file/directoryだけを所有試験領域へコピーします。 */
	//------------------------------------------------------------------------------
	fn copy_fixture(source: &std::path::Path, destination: &std::path::Path) {
		std::fs::create_dir(destination).expect("new fixture directory");
		for entry in std::fs::read_dir(source).expect("fixture source") {
			let entry = entry.expect("source entry");
			let kind = entry.file_type().expect("fixture type");
			if kind.is_dir() {
				copy_fixture(&entry.path(), &destination.join(entry.file_name()));
			} else {
				assert!(kind.is_file());
				std::fs::copy(entry.path(), destination.join(entry.file_name())).expect("new file");
			}
		}
	}

	//------------------------------------------------------------------------------
	/** fixtureの非秘密passwordだけを、一操作の所有入力へ渡します。 */
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
	/** 専用の旧LocalAppData相当rootを同Javaにだけ対応させ、元root復元後の新規保存はJava内へ限定します。 */
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
		assert!(
			matches!(result, Completed::Transaction(value) if value.state == trust_repair_windows::TransactionState::Restored)
		);
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
		assert!(
			matches!(result, Completed::Transaction(value) if value.state == trust_repair_windows::TransactionState::Restored)
		);
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
