//------------------------------------------------------------------------------
/*!
 * - ファイル: internal_qa.rs
 * - 概要: 所有する隔離子の実 kill と次回の現物分類・復旧・実 OS 拒否を検証します。
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
 * internal-qa feature と明示した artifacts/internal-qa だけを使用します。通常は ignore。
 */
//------------------------------------------------------------------------------

#![cfg(all(windows, feature = "internal-qa"))]

use std::fs::{self, File, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use trust_repair_core::{ChangePlan, embedded_policy, sha256_hex};
use trust_repair_windows::{
	BuiltinPasswords, Cancellation, CustomStore, FailureBoundary, FailurePoint, HistoryState,
	JavaEnvironment, ScanGroup, StorePassword, TransactionCode, TransactionOptions,
	TransactionState, apply_transaction, inspect_transaction, list_history, read_snapshot,
	recover_transaction, restore_transaction, scan_java, select_java,
};

// 親だけが新規 case を作り、既存の証拠へ上書きしない
static NEXT_CASE: AtomicUsize = AtomicUsize::new(0);

//------------------------------------------------------------------------------
/**
 * 明示された既存 QA root を、この workspace の新規専用領域内に限定します。
 */
//------------------------------------------------------------------------------
fn root() -> PathBuf {
	let root = PathBuf::from(std::env::var_os("JTR_INTERNAL_QA_ROOT").expect("explicit QA root"))
		.canonicalize()
		.expect("existing QA root");
	let allowed = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
		.join("../../artifacts/internal-qa")
		.canonicalize()
		.expect("QA area");
	assert!(root.starts_with(&allowed) && root != allowed);
	root
}

//------------------------------------------------------------------------------
/**
 * 既知通常 file だけを新規 directory へコピーします。既存 fixture は変更しません。
 */
//------------------------------------------------------------------------------
fn copy_directory(source: &Path, destination: &Path) {
	fs::create_dir(destination).expect("new fixture directory");
	// 所有 fixture の全要素を列挙し、reparse を除いた新規コピーだけを作る
	for entry in fs::read_dir(source).expect("fixture source") {
		let entry = entry.expect("fixture entry");
		let kind = entry.file_type().expect("fixture type");
		assert!(!kind.is_symlink());
		// 通常 directory は再帰複写し、通常 file は既存を上書きせず複写する
		if kind.is_dir() {
			copy_directory(&entry.path(), &destination.join(entry.file_name()));
		} else {
			assert!(kind.is_file());
			fs::copy(entry.path(), destination.join(entry.file_name())).expect("new copy");
		}
	}
}

//------------------------------------------------------------------------------
/**
 * 共通 Java のコピーだけから先に対象を除き、各 case で Java 自体を書換えない状態にします。
 */
//------------------------------------------------------------------------------
fn prepare_shared_java() {
	let root = root();
	// 準備済みの共有 Java は再変更せず、同じ基準から各 case を作る
	if root.join("prepared").exists() {
		return;
	}
	let source =
		PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../artifacts/diagnostics/integration");
	copy_directory(&source.join("Java 21 読取 診断"), &root.join("Java"));
	// 両形式の基準ストアを新規複写し、各試験の元材料を分ける
	for (from, to) in [
		("custom 日本語.jks", "base.jks"),
		("custom 日本語.p12", "base.p12"),
	] {
		fs::copy(source.join(from), root.join(to)).expect("base copy");
	}
	let token = Cancellation::default();
	let environment = select_java(&root.join("Java"), &token).expect("copied Java");
	let secret = fixture_password();
	let group = scan_java(
		&environment,
		&embedded_policy().expect("policy"),
		&BuiltinPasswords {
			cacerts: &secret,
			jssecacerts: &secret,
		},
		&[],
		&token,
		|_| {},
	);
	let plan = group
		.plan(&embedded_policy().expect("policy"))
		.expect("setup plan");
	apply_transaction(
		&environment,
		&group,
		&plan,
		&vec![&secret; group.stores().len()],
		&TransactionOptions::with_backup_root(root.join("setup-backups")).expect("setup root"),
		&token,
		|_| {},
	)
	.expect("setup removes builtin targets only in copy");
	fs::write(
		root.join("prepared"),
		b"shared Java is read-only for subsequent cases",
	)
	.expect("setup marker");
}

//------------------------------------------------------------------------------
/**
 * fixture 専用の公開済み password を、製品と同じ所有型で作ります。
 */
//------------------------------------------------------------------------------
fn fixture_password() -> StorePassword {
	StorePassword::new("changeit".to_owned()).expect("fixture password")
}

/// 一つの case が所有する診断・計画・専用保管先です。
struct Case {
	/// 新規 case directory。
	path: PathBuf,
	/// 共通 Java は読み取り専用で使います。
	java: JavaEnvironment,
	/// 全群の元 snapshot/inventory。
	group: ScanGroup,
	/// 二つの custom だけの変更計画。
	plan: ChangePlan,
	/// 操作時だけ再供給する fixture password。
	secret: StorePassword,
	/// case 内の専用 backup root。
	options: TransactionOptions,
}

impl Case {
	//------------------------------------------------------------------------------
	/**
	 * 既存の case を再診断します。対象原本や他の case を変更しません。
	 */
	//------------------------------------------------------------------------------
	fn load(path: PathBuf) -> Self {
		assert!(path.canonicalize().expect("case path").starts_with(root()));
		let token = Cancellation::default();
		let java = select_java(&root().join("Java"), &token).expect("QA Java");
		let secret = fixture_password();
		let custom = [
			CustomStore {
				path: path.join("custom.jks"),
				password: fixture_password(),
			},
			CustomStore {
				path: path.join("custom.p12"),
				password: fixture_password(),
			},
		];
		let policy = embedded_policy().expect("policy");
		let group = scan_java(
			&java,
			&policy,
			&BuiltinPasswords {
				cacerts: &secret,
				jssecacerts: &secret,
			},
			&custom,
			&token,
			|_| {},
		);
		let plan = group.plan(&policy).expect("all-store plan");
		assert_eq!(plan.stores().len(), 2);
		let options =
			TransactionOptions::with_backup_root(path.join("backups")).expect("case backup");
		Self {
			path,
			java,
			group,
			plan,
			secret,
			options,
		}
	}

	//------------------------------------------------------------------------------
	/**
	 * 同じ group 順の password を借用して通常の適用を行います。
	 */
	//------------------------------------------------------------------------------
	fn apply(
		&self,
		options: &TransactionOptions,
	) -> Result<trust_repair_windows::TransactionOutcome, trust_repair_windows::TransactionError> {
		apply_transaction(
			&self.java,
			&self.group,
			&self.plan,
			&vec![&self.secret; self.group.stores().len()],
			options,
			&Cancellation::default(),
			|_| {},
		)
	}

	//------------------------------------------------------------------------------
	/**
	 * 変更対象二つの hash を返し、不明内容の拒否前後を照合できます。
	 */
	//------------------------------------------------------------------------------
	fn hashes(&self) -> Vec<String> {
		["custom.jks", "custom.p12"]
			.iter()
			.map(|name| sha256_hex(&fs::read(self.path.join(name)).expect("target bytes")))
			.collect()
	}

	//------------------------------------------------------------------------------
	/**
	 * 復元の byte/保持 metadata/更新日時/全 inventory を元診断と再照合します。
	 */
	//------------------------------------------------------------------------------
	fn assert_original(&self) {
		let current = Self::load(self.path.clone());
		// 全対象を元診断と照合し、復旧後の byte と全 inventory を両方確認する
		for (before, after) in self.group.stores().iter().zip(current.group.stores()) {
			assert_eq!(before.report().inventory(), after.report().inventory());
			let old = before.snapshot().expect("before snapshot");
			let new = after.snapshot().expect("after snapshot");
			assert_eq!(old.sha256(), new.sha256());
			assert_eq!(old.attributes(), new.attributes());
			assert_eq!(old.creation_time(), new.creation_time());
			assert_eq!(old.last_write_time(), new.last_write_time());
			// OS の AUTO_INHERITED 制御 bit は再計算され得る。owner/group/DACL byte と保護状態を照合する
			assert_eq!(
				&old.security_descriptor()[4..],
				&new.security_descriptor()[4..]
			);
			assert_eq!(
				old.security_descriptor()[3] & 0x90,
				new.security_descriptor()[3] & 0x90
			);
			assert_eq!(
				old.security_descriptor()[2] & 4,
				new.security_descriptor()[2] & 4
			);
		}
	}
}

//------------------------------------------------------------------------------
/**
 * 二つの形式だけを新規 case へコピーします。共通 Java の metadata は変更しません。
 */
//------------------------------------------------------------------------------
fn case(label: &str) -> Case {
	let path = root().join(format!(
		"case-{}-{}-{label}",
		std::process::id(),
		NEXT_CASE.fetch_add(1, Ordering::Relaxed)
	));
	fs::create_dir(&path).expect("new case");
	// 両形式を新規 case へ配置し、共有 Java の metadata は変えずに隔離する
	for extension in ["jks", "p12"] {
		fs::copy(
			root().join(format!("base.{extension}")),
			path.join(format!("custom.{extension}")),
		)
		.expect("isolated custom");
	}
	Case::load(path)
}

/// 明示起動した子だけを所有し、失敗時にも他 process を触らず回収します。
struct OwnedChild(
	/// この親試験が起動し、終了待ちの責任を持つ子だけを保持します。
	Child,
);

impl Drop for OwnedChild {
	//------------------------------------------------------------------------------
	/**
	 * 親試験 panic 時にも所有する子だけを終了し、終了待ちします。
	 */
	//------------------------------------------------------------------------------
	fn drop(&mut self) {
		let _kill = self.0.kill();
		let _wait = self.0.wait();
	}
}

//------------------------------------------------------------------------------
/**
 * 同じ test exe の専用 fixture を起動し、指定境界が sync されるまで待ちます。
 */
//------------------------------------------------------------------------------
fn paused_child(test: &Case, mode: &str, checkpoint: &str, occurrence: usize) -> OwnedChild {
	let log = File::create(test.path.join("child.log")).expect("child log");
	let child = Command::new(std::env::current_exe().expect("self exe"))
		.args([
			"--exact",
			"internal_qa_child",
			"--ignored",
			"--nocapture",
			"--test-threads=1",
		])
		.env("JTR_QA_CASE", &test.path)
		.env("JTR_QA_MODE", mode)
		.env("JTR_QA_CHECKPOINT", checkpoint)
		.env("JTR_QA_OCCURRENCE", occurrence.to_string())
		.env("JTR_QA_MARKER", test.path.join("paused"))
		.stdin(Stdio::null())
		.stdout(log.try_clone().expect("log clone"))
		.stderr(log)
		.creation_flags(0x0800_0000)
		.spawn()
		.expect("owned child");
	let mut child = OwnedChild(child);
	let started = Instant::now();
	// 所有子が指定境界を永続化するまで待ち、期限で同期障害を検出する
	while !test.path.join("paused").exists() {
		assert!(
			child.0.try_wait().expect("child status").is_none(),
			"child ended before {checkpoint}: {}",
			fs::read_to_string(test.path.join("child.log")).expect("log")
		);
		assert!(
			started.elapsed() < Duration::from_secs(90),
			"checkpoint timeout {checkpoint}"
		);
		std::thread::sleep(Duration::from_millis(20));
	}
	child
}

//------------------------------------------------------------------------------
/**
 * 子専用です。親から指定された自 case だけを変更し、通常の一括 test では実行しません。
 */
//------------------------------------------------------------------------------
#[test]
#[ignore = "内部 QA の親が所有して起動する専用子"]
fn internal_qa_child() {
	let path = PathBuf::from(std::env::var_os("JTR_QA_CASE").expect("owned case"));
	let mode = std::env::var("JTR_QA_MODE").expect("explicit mode");
	// 復元系の子は先に適用し、指定境界へ進む前提状態を作る
	if mode.starts_with("restore") {
		let java = select_java(&root().join("Java"), &Cancellation::default()).expect("Java");
		let mut options =
			TransactionOptions::with_backup_root(path.join("backups")).expect("options");
		// 復元 rollback の条件だけに明示失敗を加え、通常復元と分ける
		if mode == "restore-rollback" {
			options = options.with_failure(FailurePoint {
				boundary: FailureBoundary::AfterRestore,
				item: Some(0),
			});
		}
		let entries = list_history(&options).expect("history");
		let secret = fixture_password();
		let result = restore_transaction(
			&java,
			&options,
			&entries[0].transaction_id,
			&[&secret, &secret],
			&Cancellation::default(),
			|_| {},
		);
		// 復元 rollback と正常復元で、期待する返却状態を分けて検証する
		if mode == "restore-rollback" {
			assert_eq!(
				result.expect_err("restore rollback child").state,
				TransactionState::Applied
			);
		} else {
			result.expect("restore child");
		}
	} else {
		let test = Case::load(path);
		// 適用 rollback の条件だけに途中置換の失敗を注入する
		let options = if mode == "rollback" || mode == "recovery-required" {
			test.options.clone().with_failure(FailurePoint {
				boundary: FailureBoundary::AfterCommit,
				item: Some(1),
			})
		} else {
			test.options.clone()
		};
		// 要復旧の条件では rollback 自体にも失敗を加え、部分状態を再現する
		let options = if mode == "recovery-required" {
			options.with_failure(FailurePoint {
				boundary: FailureBoundary::BeforeRollback,
				item: Some(0),
			})
		} else {
			options
		};
		let result = test.apply(&options);
		// 要復旧と通常の適用・rollback を、対応する実行経路で検証する
		if mode == "recovery-required" {
			assert_eq!(
				result.expect_err("failed rollback child").state,
				TransactionState::RecoveryRequired
			);
		// 通常 rollback の条件では元状態へ戻れたことを確認する
		} else if mode == "rollback" {
			assert_eq!(
				result.expect_err("rollback").state,
				TransactionState::RolledBack
			);
		} else {
			result.expect("apply child");
		}
	}
}

//------------------------------------------------------------------------------
/**
 * 実 kill 後の次回照合は既知状態だけを復旧し、未知 metadata では byte と証拠を保全します。
 */
//------------------------------------------------------------------------------
#[test]
#[ignore = "明示 internal-qa 領域と実 Java が必要"]
fn kills_at_persistent_boundaries_and_recovers_from_actual_files() {
	prepare_shared_java();
	let boundaries = [
		("apply", "saved-preparation.json", 1),
		("apply", "saved-0000.original.bin", 1),
		("apply", "stage-created", 1),
		("apply", "stage-verified:0", 1),
		("apply", "manifest-verified", 1),
		("apply", "journal-Prepared", 1),
		("apply", "journal-Committing", 1),
		("apply", "journal-ReplaceStarted:0", 1),
		("apply", "after-replace", 1),
		("apply", "dacl-preserved", 1),
		("apply", "journal-ReplaceVerified:0", 1),
		("apply", "journal-ReplaceStarted:1", 1),
		("apply", "journal-ReplaceVerified:1", 1),
		("apply", "journal-Applied", 1),
		("rollback", "journal-RollingBack", 1),
		("rollback", "journal-RollbackStarted:1", 1),
		("rollback", "after-replace", 3),
		("rollback", "dacl-preserved", 3),
		("rollback", "journal-RollbackVerified:1", 1),
		("rollback", "journal-RolledBack", 1),
		("restore", "stage-created", 1),
		("restore", "journal-Restoring", 1),
		("restore", "journal-RestoreStarted:0", 1),
		("restore", "after-replace", 1),
		("restore", "dacl-preserved", 1),
		("restore", "journal-RestoreVerified:0", 1),
		("restore", "journal-RestoreStarted:1", 1),
		("restore", "journal-RestoreVerified:1", 1),
		("restore", "journal-Restored", 1),
		("restore-rollback", "journal-RollingBack", 1),
		("restore-rollback", "after-replace", 2),
		("restore-rollback", "dacl-preserved", 2),
		("restore-rollback", "journal-RestoreRolledBack", 1),
		("recovery-required", "journal-RecoveryRequired", 1),
	];
	// 各永続化境界で所有子を順に実終了し、次回起動の復旧契約を確認する
	for (index, (mode, boundary, occurrence)) in boundaries.iter().enumerate() {
		verify_killed_boundary(index, mode, boundary, *occurrence);
	}
}

//------------------------------------------------------------------------------
/**
 * 一つの永続化境界で所有子を実終了し、次回読込と復旧後の保全を確認します。
 */
//------------------------------------------------------------------------------
fn verify_killed_boundary(index: usize, mode: &str, boundary: &str, occurrence: usize) {
	let test = case(&format!("kill-{index:02}"));
	// 復元系の kill 試験は、適用済みの独立 case から開始する
	if mode.starts_with("restore") {
		test.apply(&test.options).expect("preapply");
	}
	let mut child = paused_child(&test, mode, boundary, occurrence);
	let pid = child.0.id();
	child.0.kill().expect("kill only owned child");
	assert!(!child.0.wait().expect("reap child").success());
	let entries = list_history(&test.options).expect("next-run history");
	assert_eq!(entries.len(), 1);
	let id = &entries[0].transaction_id;
	let inspected = inspect_transaction(&test.options, id).expect("next-run inspect");
	// 初回 journal 前の境界では、未作成を実在する破断記録と混同しないことを確認する
	if mode == "apply" && boundary == "manifest-verified" {
		assert_eq!(inspected.state, HistoryState::Recoverable);
		assert!(
			!inspected.torn_journal,
			"absent initial journal is not a torn file"
		);
		assert!(
			test.options
				.backup_root()
				.join(id)
				.join("manifest.json")
				.is_file()
		);
		assert_eq!(
			fs::symlink_metadata(test.options.backup_root().join(id).join("journal.jsonl"))
				.expect_err("initial journal has never been created")
				.kind(),
			std::io::ErrorKind::NotFound
		);
	}
	let before = test.hashes();
	// manifest 前の kill は準備未完了として扱い、元対象が変化していないことを確認する
	if inspected.state == HistoryState::IncompletePreparation {
		test.assert_original();
		assert!(
			recover_transaction(
				&test.java,
				&test.options,
				id,
				&[&test.secret, &test.secret],
				&Cancellation::default(),
				|_| {}
			)
			.is_err()
		);
	// 未知 metadata の状態では、元 byte と証拠を保ったまま自動上書きを拒否することを確認する
	} else if inspected.state == HistoryState::RecoveryRequired {
		let error = recover_transaction(
			&test.java,
			&test.options,
			id,
			&[&test.secret, &test.secret],
			&Cancellation::default(),
			|_| {},
		)
		.expect_err("ambiguous metadata cannot be overwritten");
		assert_eq!(error.code, TransactionCode::RecoveryRequired);
		assert_eq!(test.hashes(), before);
		assert!(
			test.options
				.backup_root()
				.join(id)
				.join("manifest.json")
				.is_file()
		);
	} else {
		assert!(
			!matches!(
				inspected.state,
				HistoryState::Applied | HistoryState::Restored | HistoryState::RolledBack
			) || (mode == "restore" && boundary == "stage-created")
				|| matches!(
					boundary,
					"journal-Applied"
						| "journal-Restored"
						| "journal-RolledBack"
						| "journal-RestoreRolledBack"
				)
		);
		let result = recover_transaction(
			&test.java,
			&test.options,
			id,
			&[&test.secret, &test.secret],
			&Cancellation::default(),
			|_| {},
		)
		.expect("known state recovery");
		assert!(matches!(
			result.state,
			TransactionState::Restored | TransactionState::AlreadyRestored
		));
		test.assert_original();
		// 初回 journal 前の実 kill では、復旧後の次適用と復元まで再利用を確認する
		if mode == "apply" && boundary == "manifest-verified" {
			assert_recovered_initial_journal_history(&test, id);
		}
	}
	println!(
		"kill {index:02} {mode} {boundary} occurrence={occurrence}: pid={pid} reaped; {:?}; next-run recovery contract verified",
		inspected.state
	);
}

//------------------------------------------------------------------------------
/**
 * 復旧完了の履歴を再読込し、次の適用・全件検証・復元が元 byte/metadata へ戻ることを確認。
 */
//------------------------------------------------------------------------------
fn assert_recovered_initial_journal_history(test: &Case, id: &str) {
	let directory = test.options.backup_root().join(id);
	assert!(!directory.join("journal.jsonl").exists());
	assert!(directory.join("recovery-0001.jsonl").is_file());
	let history = list_history(&test.options).expect("history after initial-journal recovery");
	assert_eq!(history.len(), 1);
	let inspection = history[0]
		.inspection
		.as_ref()
		.expect("recovered entry readable");
	assert_eq!(inspection.state, HistoryState::Restored);
	assert!(!inspection.torn_journal);
	let applied = test
		.apply(&test.options)
		.expect("next apply accepts recovered history");
	assert_eq!(applied.state, TransactionState::Applied);
	assert_eq!(list_history(&test.options).expect("both records").len(), 2);
	restore_transaction(
		&test.java,
		&test.options,
		&applied.transaction_id,
		&[&test.secret, &test.secret],
		&Cancellation::default(),
		|_| {},
	)
	.expect("restore after next apply");
	test.assert_original();
	assert!(!directory.join("journal.jsonl").exists());
	// 次回の復元後も全履歴を再読込みし、復旧分岐を含め正常状態が残ることを確認する
	for entry in list_history(&test.options).expect("history after next restore") {
		assert_eq!(
			entry.inspection.expect("both records readable").state,
			HistoryState::Restored
		);
	}
	println!(
		"initial journal absent: recovery history readable; next apply/restore preserved original bytes, complete inventory and metadata"
	);
}

//------------------------------------------------------------------------------
/**
 * 34境界と同じ実 kill を初回 journal 作成前だけに実行し、復旧後の再利用まで確認します。
 */
//------------------------------------------------------------------------------
#[test]
#[ignore = "明示 internal-qa 領域と実 Java が必要"]
fn missing_initial_journal_recovers_and_allows_next_apply() {
	prepare_shared_java();
	verify_killed_boundary(4, "apply", "manifest-verified", 1);
}

//------------------------------------------------------------------------------
/**
 * 初回 journal の権限/共有失敗・不正内容と復旧連番の欠落を、未作成として許可しません。
 */
//------------------------------------------------------------------------------
#[test]
#[ignore = "明示 internal-qa 領域・実 Java と現利用者 SID が必要"]
fn journal_read_errors_and_missing_recovery_branch_are_rejected() {
	prepare_shared_java();
	let test = case("journal-errors");
	let applied = test
		.apply(&test.options)
		.expect("apply before negative cases");
	let initial = applied.backup_directory.join("journal.jsonl");
	let initial_bytes = fs::read(&initial).expect("initial evidence");
	let before = test.hashes();
	let exclusive = OpenOptions::new()
		.read(true)
		.share_mode(0)
		.open(&initial)
		.expect("exclusive owned journal");
	let sharing = inspect_transaction(&test.options, &applied.transaction_id)
		.expect_err("sharing failure is not an absent journal");
	drop(exclusive);
	assert!(
		sharing.os_code == Some(32)
			|| matches!(
				sharing.file_error,
				Some(trust_repair_windows::FileSafetyError::Io {
					os_code: Some(32),
					..
				})
			),
		"{sharing:?}"
	);
	let sid = std::env::var("JTR_QA_SID").expect("explicit test principal SID");
	assert!(
		sid.starts_with("S-1-")
			&& sid
				.bytes()
				.all(|byte| byte.is_ascii_digit() || byte == b'S' || byte == b'-')
	);
	let allowed = format!("(A;;FA;;;{sid})(A;;FA;;;BA)");
	set_fixture_dacl(&initial, &format!("(D;;0x1;;;{sid}){allowed}"));
	let denied = inspect_transaction(&test.options, &applied.transaction_id)
		.expect_err("permission failure is not an absent journal");
	set_fixture_dacl(&initial, &allowed);
	assert_eq!(denied.code, TransactionCode::PermissionDenied);
	assert_eq!(
		fs::read(&initial).expect("initial evidence unchanged"),
		initial_bytes
	);
	assert_eq!(test.hashes(), before);
	let mut torn = initial_bytes.clone();
	torn.truncate(torn.len() - 7);
	fs::write(&initial, &torn).expect("simulate initial torn tail");
	assert!(
		inspect_transaction(&test.options, &applied.transaction_id)
			.expect("existing torn initial journal")
			.torn_journal
	);
	recover_transaction(
		&test.java,
		&test.options,
		&applied.transaction_id,
		&[&test.secret, &test.secret],
		&Cancellation::default(),
		|_| {},
	)
	.expect("first torn-tail recovery");
	let branch = applied.backup_directory.join("recovery-0001.jsonl");
	let mut branch_bytes = fs::read(&branch).expect("first recovery evidence");
	branch_bytes.truncate(branch_bytes.len() - 7);
	fs::write(&branch, &branch_bytes).expect("simulate recovery torn tail");
	assert!(
		inspect_transaction(&test.options, &applied.transaction_id)
			.expect("existing torn recovery journal")
			.torn_journal
	);
	recover_transaction(
		&test.java,
		&test.options,
		&applied.transaction_id,
		&[&test.secret, &test.secret],
		&Cancellation::default(),
		|_| {},
	)
	.expect("second torn-tail recovery");
	let second = applied.backup_directory.join("recovery-0002.jsonl");
	let second_bytes = fs::read(&second).expect("second recovery evidence");
	let saved = test.path.join("retained-recovery-0001.jsonl");
	fs::rename(&branch, &saved)
		.expect("preserve missing intermediate evidence outside transaction");
	let gap = inspect_transaction(&test.options, &applied.transaction_id)
		.expect_err("missing intermediate recovery is rejected");
	fs::rename(&saved, &branch).expect("restore intermediate evidence");
	assert_eq!(gap.code, TransactionCode::InvalidManifest);
	fs::write(
		&initial,
		b"{\"sequence\":2,\"event\":\"Prepared\",\"item\":null,\"operation_id\":null}\n",
	)
	.expect("simulate invalid existing initial journal");
	let invalid = inspect_transaction(&test.options, &applied.transaction_id)
		.expect_err("existing invalid initial journal is not ignored after recovery");
	fs::write(&initial, &torn).expect("restore original torn evidence");
	assert_eq!(invalid.code, TransactionCode::InvalidJournal);
	assert_eq!(
		fs::read(&initial).expect("original torn evidence retained"),
		torn
	);
	assert_eq!(
		fs::read(&branch).expect("first torn recovery retained"),
		branch_bytes
	);
	assert_eq!(
		fs::read(&second).expect("latest recovery unchanged"),
		second_bytes
	);
	assert_eq!(
		inspect_transaction(&test.options, &applied.transaction_id)
			.expect("history restored after negative cases")
			.state,
		HistoryState::Restored
	);
	test.assert_original();
	println!(
		"initial journal sharing/permission/invalid content and missing intermediate recovery rejected; torn original/recovery evidence and original target bytes/inventory/metadata preserved"
	);
}

//------------------------------------------------------------------------------
/**
 * OS の sharing failure と外部 rename は主原因を失わず、不明内容を上書きせず保全します。
 */
//------------------------------------------------------------------------------
#[test]
#[ignore = "明示 internal-qa 領域と実 Java が必要"]
fn actual_sharing_failure_and_external_rename_preserve_evidence() {
	prepare_shared_java();
	// sharing 拒否と外部 rename を、適用・復元の各該当条件で検証する
	for (rename, restore) in [(false, false), (true, false), (true, true)] {
		// 変更条件ごとに case 名を分け、異なる残存証拠を混在させない
		let test = case(if rename {
			"external-rename"
		} else {
			"sharing-violation"
		});
		// 復元系は先に正常適用し、同じ元状態から通常復元の失敗を再現する
		if restore {
			test.apply(&test.options)
				.expect("apply before restore race");
		}
		let mut child = paused_child(
			&test,
			// 所有子の実行 mode を適用または復元の条件へ対応させる
			if restore { "restore" } else { "apply" },
			"before-replace",
			1,
		);
		let target = test.path.join("custom.jks");
		let (before, _) = read_snapshot(&target, 32 * 1024 * 1024).expect("current snapshot");
		let mut hold = None;
		// 外部 rename は未知内容を作り、sharing 条件は保持 handle で実拒否を起こす
		if rename {
			fs::rename(&target, test.path.join("external-original.jks"))
				.expect("external atomic rename despite old guard");
			fs::write(&target, b"unknown external content must survive")
				.expect("external replacement");
			// 外部 file の作成/更新日時まで一致しても、退避された byte の違いを見逃さない
			set_fixture_times(&target, &before);
		} else {
			// 書込み共有は許し DELETE 共有だけを拒否して、本物の ReplaceFileW OS 失敗を発生させる
			hold = Some(
				OpenOptions::new()
					.read(true)
					.share_mode(3)
					.open(&target)
					.expect("external no-delete handle"),
			);
		}
		fs::write(test.path.join("paused.release"), b"continue").expect("release");
		let started = Instant::now();
		// 所有子の終了まで確認し、60 秒の上限で回収の失敗を検出する
		while child.0.try_wait().expect("status").is_none() {
			assert!(started.elapsed() < Duration::from_secs(60));
			std::thread::sleep(Duration::from_millis(20));
		}
		drop(hold);
		let log = fs::read_to_string(test.path.join("child.log")).expect("child failure");
		assert!(
			log.contains(if restore {
				"restore child"
			} else {
				"apply child"
			}),
			"{log}"
		);
		let history = list_history(&test.options).expect("failure history");
		let inspection = history[0].inspection.as_ref().expect("inspect failure");
		// 未知の退避内容が残る条件では、次回復旧でも上書きを拒否して証拠を保持することを確認する
		if rename {
			assert_eq!(inspection.state, HistoryState::RecoveryRequired);
			let recovery = fs::read_dir(&test.path)
				.expect("work directory")
				.filter_map(Result::ok)
				.filter(|entry| entry.file_name().to_string_lossy().starts_with(".jtr-"))
				.flat_map(|entry| {
					fs::read_dir(entry.path())
						.expect("work files")
						.filter_map(Result::ok)
				})
				.find(|entry| {
					fs::read(entry.path())
						.is_ok_and(|bytes| bytes == b"unknown external content must survive")
				})
				.expect("actual external bytes preserved in displaced recovery file")
				.path();
			let hashes = test.hashes();
			let error = recover_transaction(
				&test.java,
				&test.options,
				&history[0].transaction_id,
				&[&test.secret, &test.secret],
				&Cancellation::default(),
				|_| {},
			)
			.expect_err("conflicting evidence blocks next-run overwrite");
			assert_eq!(error.code, TransactionCode::RecoveryRequired);
			assert_eq!(test.hashes(), hashes);
			assert_eq!(
				fs::read(recovery).expect("evidence preserved"),
				b"unknown external content must survive"
			);
			assert!(log.contains("rollback_errors: [TransactionError"), "{log}");
		} else {
			assert_eq!(inspection.state, HistoryState::RolledBack);
			assert!(log.contains("os_code: Some(32)"), "{log}");
			test.assert_original();
		}
		println!(
			"actual {} restore={restore}: {:?}; OS failure/evidence retained",
			if rename {
				"external rename"
			} else {
				"sharing violation"
			},
			inspection.state
		);
	}
}

//------------------------------------------------------------------------------
/**
 * 自 fixture の外部更新が既存の時刻を保持する状況を再現します。権限・内容は変更しません。
 */
//------------------------------------------------------------------------------
fn set_fixture_times(path: &Path, snapshot: &trust_repair_windows::FileSnapshot) {
	use windows_sys::Win32::Foundation::FILETIME;
	use windows_sys::Win32::Storage::FileSystem::SetFileTime;
	let time = |value: u64| FILETIME {
		dwLowDateTime: value as u32,
		dwHighDateTime: (value >> 32) as u32,
	};
	let file = OpenOptions::new()
		.access_mode(0x100)
		.share_mode(7)
		.open(path)
		.expect("fixture attributes");
	// SAFETY: 自 case 内の所有 file と初期化済 FILETIME を同期呼出しだけへ借用する
	let result = unsafe {
		SetFileTime(
			file.as_raw_handle(),
			&time(snapshot.creation_time()),
			std::ptr::null(),
			&time(snapshot.last_write_time()),
		)
	};
	assert_ne!(result, 0);
}

//------------------------------------------------------------------------------
/**
 * 不正 backup/manifest は既存試験に加え、保管 root の owner/DACL 範囲も強制緩和せず拒否します。
 */
//------------------------------------------------------------------------------
#[test]
#[ignore = "明示 internal-qa 領域と実 Java が必要"]
fn refuses_widened_backup_directory_without_changing_targets() {
	prepare_shared_java();
	let test = case("wide-backup-root");
	fs::create_dir(test.options.backup_root()).expect("inherited broad ACL fixture");
	let before = test.hashes();
	let error = test
		.apply(&test.options)
		.expect_err("private root required");
	assert_eq!(error.code, TransactionCode::UnsupportedMetadata);
	assert_eq!(test.hashes(), before);
	assert_eq!(
		fs::read_dir(test.options.backup_root())
			.expect("root preserved")
			.count(),
		0
	);
	let (_, bytes) =
		read_snapshot(&test.path.join("custom.jks"), 32 * 1024 * 1024).expect("original readable");
	assert_eq!(sha256_hex(&bytes), before[0]);
}

//------------------------------------------------------------------------------
/**
 * 自 fixture の DACL だけを設定します。通常権限を緩和する製品経路には使いません。
 */
//------------------------------------------------------------------------------
fn set_fixture_dacl(path: &Path, entries: &str) {
	use std::os::windows::ffi::OsStrExt;
	use windows_sys::Win32::Foundation::LocalFree;
	use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
	use windows_sys::Win32::Security::{
		DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, SetFileSecurityW,
	};
	assert!(
		path.canonicalize()
			.expect("own fixture")
			.starts_with(root())
	);
	let sddl: Vec<u16> = format!("D:P{entries}").encode_utf16().chain([0]).collect();
	let path: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
	let mut descriptor = std::ptr::null_mut();
	// SAFETY: 終端 NUL の試験固定 SDDL と OS 所有出力を渡し、成功後に専用解放する
	let converted = unsafe {
		ConvertStringSecurityDescriptorToSecurityDescriptorW(
			sddl.as_ptr(),
			1,
			&mut descriptor,
			std::ptr::null_mut(),
		)
	};
	assert_ne!(converted, 0);
	// SAFETY: OS が生成した descriptor の DACL だけを、検査済み自 fixture に設定する
	let result = unsafe {
		SetFileSecurityW(
			path.as_ptr(),
			DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
			descriptor,
		)
	};
	// SAFETY: 変換に成功した LocalAlloc pointer を一度だけ解放する
	unsafe {
		LocalFree(descriptor);
	}
	assert_ne!(
		result,
		0,
		"fixture DACL: {}",
		std::io::Error::last_os_error()
	);
}

//------------------------------------------------------------------------------
/**
 * 実権限拒否・複雑 ACE 拒否・保護 DACL の置換中断を隔離ファイルで確認します。
 */
//------------------------------------------------------------------------------
#[test]
#[ignore = "明示 QA root と現利用者 SID が必要"]
fn real_permission_complex_acl_and_protected_dacl_contracts() {
	prepare_shared_java();
	let sid = std::env::var("JTR_QA_SID").expect("explicit test principal SID");
	assert!(
		sid.starts_with("S-1-")
			&& sid
				.bytes()
				.all(|byte| byte.is_ascii_digit() || byte == b'S' || byte == b'-')
	);
	// 実書込み拒否・複雑 ACE・保護 DACL を別 case に分けて検証する
	for (label, prefix) in [
		("denied-write", format!("(D;;0x2;;;{sid})")),
		(
			"complex-ace",
			format!("(OA;;FR;00000000-0000-0000-0000-000000000001;;{sid})"),
		),
		("protected-dacl", String::new()),
	] {
		let initial = case(label);
		let entries = format!("{prefix}(A;;FA;;;{sid})(A;;FA;;;BA)");
		// 両形式へ同じ権限条件を設定し、一部の対象だけで合格としない
		for name in ["custom.jks", "custom.p12"] {
			set_fixture_dacl(&initial.path.join(name), &entries);
		}
		let test = Case::load(initial.path);
		let before = test.hashes();
		// 保護 DACL の条件では置換直後に所有子を実終了し、保持と次回復旧の契約を確認する
		if label == "protected-dacl" {
			let mut child = paused_child(&test, "apply", "after-replace", 1);
			child.0.kill().expect("kill protected DACL case child");
			child.0.wait().expect("reap protected DACL child");
			let history = list_history(&test.options).expect("protected history");
			assert_eq!(
				history[0]
					.inspection
					.as_ref()
					.expect("protected inspect")
					.state,
				HistoryState::Recoverable
			);
			recover_transaction(
				&test.java,
				&test.options,
				&history[0].transaction_id,
				&[&test.secret, &test.secret],
				&Cancellation::default(),
				|_| {},
			)
			.expect("protected DACL recovery");
			test.assert_original();
			println!(
				"protected DACL: raw ReplaceFileW kill recovered with original ACL/bytes/inventory"
			);
		} else {
			let error = test
				.apply(&test.options)
				.expect_err("unsupported metadata/permission must refuse");
			assert_eq!(
				error.code,
				if label == "denied-write" {
					TransactionCode::PermissionDenied
				} else {
					TransactionCode::UnsupportedMetadata
				},
				"{error:?}"
			);
			assert_eq!(test.hashes(), before);
			println!("real {label}: {:?}; unchanged target bytes", error.code);
		}
	}
}
