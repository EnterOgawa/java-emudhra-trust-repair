//------------------------------------------------------------------------------
/*!
 * - ファイル: transactions.rs
 * - 概要: 隔離した実 Java で適用・全件検証・復元と失敗時の保全を確認します。
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
 * Ver.01.00.00  Shunji Ogawa  2026/10/26  四 LTS・両形式の実 keytool 適用/復元試験を追加。
 * Ver.01.00.01  Shunji Ogawa  2026/10/26  内部 QA の新規領域も明示された隔離 root として許可。
 * Ver.01.01.00  Shunji Ogawa  2026/10/26  Java内backupの四LTS往復、既存root/権限/移動/未完了拒否を検証。
 * ```
 *
 * 備考:
 *
 * 明示された artifacts/transactions の試験コピーだけを変更します。通常 test では ignore。
 */
//------------------------------------------------------------------------------

#![cfg(windows)]

use std::fs;
use std::io::Write;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use trust_repair_core::{ChangePlan, PlanError, embedded_policy, sha256_hex};
use trust_repair_windows::{
	BuiltinPasswords, Cancellation, CustomStore, FailureBoundary, FailurePoint, HistoryState,
	JavaEnvironment, ScanGroup, StorePassword, TransactionCode, TransactionOptions,
	TransactionPhase, TransactionState, apply_transaction, inspect_transaction, list_history,
	recover_transaction, restore_transaction, scan_java, select_java,
};

// 同一 test process の新規 case 名を一意にする
static NEXT_CASE: AtomicUsize = AtomicUsize::new(0);

//------------------------------------------------------------------------------
/** 明示 root を workspace の transaction 隔離領域に限定します。実 Java は受け付けません。 */
//------------------------------------------------------------------------------
fn fixtures() -> PathBuf {
	let root = PathBuf::from(
		std::env::var_os("JAVA_TRUST_REPAIR_TRANSACTION_FIXTURES")
			.expect("transaction fixtures を明示"),
	);
	let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
	let allowed = workspace
		.join("artifacts/transactions")
		.canonicalize()
		.expect("許可領域");
	let internal = workspace.join("artifacts/internal-qa").canonicalize().ok();
	let local_backup = workspace
		.join("artifacts/jdk-local-backup")
		.canonicalize()
		.ok();
	let root = root.canonicalize().expect("fixture root");
	assert!(
		root.starts_with(allowed)
			|| internal.is_some_and(|path| root.starts_with(path))
			|| local_backup.is_some_and(|path| root.starts_with(path))
	);
	root
}

//------------------------------------------------------------------------------
/** 既知の通常 file だけから新規の隔離 case へコピーします。既存 case を上書きしません。 */
//------------------------------------------------------------------------------
fn copy_directory(source: &Path, destination: &Path) {
	fs::create_dir(destination).expect("新規 directory");
	for entry in fs::read_dir(source).expect("source") {
		let entry = entry.expect("entry");
		let target = destination.join(entry.file_name());
		if entry.file_type().expect("type").is_dir() {
			copy_directory(&entry.path(), &target);
		} else {
			assert!(entry.file_type().expect("type").is_file());
			fs::copy(entry.path(), target).expect("isolated copy");
		}
	}
}

//------------------------------------------------------------------------------
/** 検証専用の非秘密 password を製品と同じ所有型へ渡します。 */
//------------------------------------------------------------------------------
fn password() -> StorePassword {
	StorePassword::new("changeit".to_owned()).expect("test password")
}

//------------------------------------------------------------------------------
/** 後続 case の基準を変えないよう、Java と両 custom を丸ごと新規コピーします。 */
//------------------------------------------------------------------------------
fn case(major: u16, label: &str) -> (PathBuf, PathBuf, TransactionOptions) {
	let fixture = fixtures();
	let root = fixture.join(format!(
		"run-{}-{}-{label}",
		std::process::id(),
		NEXT_CASE.fetch_add(1, Ordering::Relaxed)
	));
	fs::create_dir(&root).expect("new case");
	let java = root.join(format!("Java {major} 適用 復元"));
	copy_directory(&fixture.join(format!("Java {major} 適用 復元")), &java);
	for name in ["custom 日本語.jks", "custom 日本語.p12"] {
		fs::copy(fixture.join(name), root.join(name)).expect("custom copy");
	}
	let options =
		TransactionOptions::with_backup_root(root.join("backups")).expect("dedicated backups");
	(root, java, options)
}

//------------------------------------------------------------------------------
/** 四 LTS/両形式で全非対象保持・再診断未検出・完全復元・二重復元を実測します。 */
//------------------------------------------------------------------------------
#[test]
#[ignore = "明示された新規 transaction fixtures が必要"]
fn applies_rediagnoses_and_restores_four_lts_both_formats() {
	let policy = embedded_policy().expect("policy");
	for major in [11, 17, 21, 25] {
		let (root, java, legacy_options) = case(major, "roundtrip");
		let cancellation = Cancellation::default();
		let environment = select_java(&java, &cancellation).expect("Java");
		let options = TransactionOptions::for_java(&environment).expect("Java-local backup");
		assert_eq!(
			options.backup_root(),
			environment.root().join("emudhra-backup")
		);
		assert!(
			list_history(&options)
				.expect("read-only absent history")
				.is_empty()
		);
		assert!(!options.backup_root().exists());
		let secret = password();
		let builtin = BuiltinPasswords {
			cacerts: &secret,
			jssecacerts: &secret,
		};
		let custom = [
			CustomStore {
				path: root.join("custom 日本語.jks"),
				password: password(),
			},
			CustomStore {
				path: root.join("custom 日本語.p12"),
				password: password(),
			},
		];
		let group = scan_java(
			&environment,
			&policy,
			&builtin,
			&custom,
			&cancellation,
			|_| {},
		);
		let plan = group.plan(&policy).expect("complete plan");
		let original: Vec<_> = group
			.stores()
			.iter()
			.map(|store| store.snapshot().expect("snapshot").clone())
			.collect();
		assert!(
			!options.backup_root().exists(),
			"scan must not create backup directory"
		);
		let passwords = vec![&secret; group.stores().len()];
		let result = apply_transaction(
			&environment,
			&group,
			&plan,
			&passwords,
			&options,
			&cancellation,
			|_| {},
		)
		.expect("apply");
		assert_eq!(result.state, TransactionState::Applied);
		assert_eq!(
			result.backup_directory.parent(),
			Some(options.backup_root())
		);
		assert!(!legacy_options.backup_root().exists());
		assert_eq!(
			inspect_transaction(&options, &result.transaction_id)
				.expect("history")
				.state,
			HistoryState::Applied
		);
		let after = scan_java(
			&environment,
			&policy,
			&builtin,
			&custom,
			&cancellation,
			|_| {},
		);
		assert_eq!(after.plan(&policy), Err(PlanError::NoTargets));
		for (before, after) in group.stores().iter().zip(after.stores()) {
			assert!(after.report().targets().is_empty());
			let old = before.report().inventory().expect("old inventory");
			let new = after.report().inventory().expect("new inventory");
			assert_eq!(new.format(), old.format());
			let non_targets: Vec<_> = old
				.entries()
				.iter()
				.filter(|entry| {
					!before
						.report()
						.targets()
						.iter()
						.any(|target| target.alias() == entry.alias())
				})
				.cloned()
				.collect();
			assert_eq!(new.entries(), non_targets);
		}
		let restore_passwords = vec![&secret; plan.stores().len()];
		let restored = restore_transaction(
			&environment,
			&options,
			&result.transaction_id,
			&restore_passwords,
			&cancellation,
			|_| {},
		)
		.expect("restore");
		assert_eq!(restored.state, TransactionState::Restored);
		for source in &original {
			assert_eq!(
				sha256_hex(&fs::read(source.canonical_path()).expect("restored bytes")),
				source.sha256()
			);
		}
		let rescanned = scan_java(
			&environment,
			&policy,
			&builtin,
			&custom,
			&cancellation,
			|_| {},
		);
		for (old, new) in group.stores().iter().zip(rescanned.stores()) {
			assert_eq!(old.report().inventory(), new.report().inventory());
		}
		assert_eq!(
			restore_transaction(
				&environment,
				&options,
				&result.transaction_id,
				&restore_passwords,
				&cancellation,
				|_| {}
			)
			.expect("idempotent restore")
			.state,
			TransactionState::AlreadyRestored
		);
		assert_eq!(list_history(&options).expect("history list").len(), 1);
		println!(
			"Java {major}: {} stores, JKS/PKCS12 apply → rediagnose → original byte/inventory/metadata restored",
			plan.stores().len()
		);
	}
}

/// 異常系の各 case が所有する、一度診断した隔離環境です。
struct PreparedCase {
	/// 検証済みの選択 Java。
	environment: JavaEnvironment,
	/// 不変の全群診断。
	group: ScanGroup,
	/// 不変の変更計画。
	plan: ChangePlan,
	/// 操作時供給する非秘密の fixture password。
	secret: StorePassword,
	/// 新規 backup 専用 root。
	options: TransactionOptions,
}

impl PreparedCase {
	//------------------------------------------------------------------------------
	/** 一回の操作でだけ借用する、診断群順の password 一覧を作ります。 */
	//------------------------------------------------------------------------------
	fn passwords(&self) -> Vec<&StorePassword> {
		vec![&self.secret; self.group.stores().len()]
	}

	//------------------------------------------------------------------------------
	/** manifest 順の password 一覧を作ります。対象ゼロ store の分を含めません。 */
	//------------------------------------------------------------------------------
	fn restore_passwords(&self) -> Vec<&StorePassword> {
		vec![&self.secret; self.plan.stores().len()]
	}

	//------------------------------------------------------------------------------
	/** 元群の raw byte hash がすべて診断時と同じことを確認します。 */
	//------------------------------------------------------------------------------
	fn assert_original(&self) {
		for store in self.group.stores() {
			let original = store.snapshot().expect("snapshot");
			assert_eq!(
				sha256_hex(&fs::read(original.canonical_path()).expect("bytes")),
				original.sha256()
			);
		}
	}
}

//------------------------------------------------------------------------------
/** 各異常系を完全に別の隔離コピーで準備し、既存 fixture や実 Java を再利用して変更しません。 */
//------------------------------------------------------------------------------
fn prepared(label: &str) -> PreparedCase {
	let (root, java, options) = case(21, label);
	let cancellation = Cancellation::default();
	let environment = select_java(&java, &cancellation).expect("Java");
	let secret = password();
	let policy = embedded_policy().expect("policy");
	let custom = [
		CustomStore {
			path: root.join("custom 日本語.jks"),
			password: password(),
		},
		CustomStore {
			path: root.join("custom 日本語.p12"),
			password: password(),
		},
	];
	let group = scan_java(
		&environment,
		&policy,
		&BuiltinPasswords {
			cacerts: &secret,
			jssecacerts: &secret,
		},
		&custom,
		&cancellation,
		|_| {},
	);
	let plan = group.plan(&policy).expect("plan");
	PreparedCase {
		environment,
		group,
		plan,
		secret,
		options,
	}
}

//------------------------------------------------------------------------------
/** 所有fixtureのdirectory DACLだけを設定します。製品には権限緩和の入口を追加しません。 */
//------------------------------------------------------------------------------
fn fixture_directory_acl(path: &Path, deny_create: bool) {
	assert!(
		path.canonicalize()
			.expect("own fixture")
			.starts_with(fixtures())
	);
	let script = r#"$ErrorActionPreference = 'Stop'
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$prefix = if ($env:JTR_FIXTURE_DENY -eq '1') { "(D;;0x4;;;$sid)" } else { '' }
$security = [Security.AccessControl.DirectorySecurity]::new()
$security.SetSecurityDescriptorSddlForm("O:${sid}G:${sid}D:P${prefix}(A;OICI;FA;;;$sid)(A;OICI;FA;;;BA)")
Set-Acl -LiteralPath $env:JTR_FIXTURE_DIRECTORY -AclObject $security
"#;
	let output = Command::new("powershell.exe")
		.env_remove("PSModulePath")
		.env(
			"JTR_FIXTURE_DIRECTORY",
			path.to_str()
				.expect("Unicode fixture")
				.trim_start_matches("\\\\?\\"),
		)
		.env("JTR_FIXTURE_DENY", if deny_create { "1" } else { "0" })
		.args(["-NoProfile", "-NonInteractive", "-Command", script])
		.creation_flags(0x0800_0000)
		.output()
		.expect("fixture ACL setup");
	assert!(
		output.status.success(),
		"{}",
		String::from_utf8_lossy(&output.stderr)
	);
}

//------------------------------------------------------------------------------
/** Java内rootの広いACL・通常file・link・未知内容と作成権限不足/readonlyを、元を変えず拒否します。 */
//------------------------------------------------------------------------------
#[test]
#[ignore = "新規のJava内backup隔離fixtureが必要"]
fn java_local_backup_refuses_unsafe_roots_and_write_denial() {
	for label in [
		"wide",
		"file",
		"junction",
		"unknown",
		"denied-create",
		"readonly",
	] {
		let mut test = prepared(&format!("local-{label}"));
		let options = TransactionOptions::for_java(&test.environment).expect("local options");
		let root = options.backup_root();
		match label {
			"wide" => fs::create_dir(root).expect("inherited broad ACL"),
			"file" => fs::write(root, b"unknown root file").expect("ordinary file root"),
			"unknown" => {
				let injected = options.clone().with_failure(FailurePoint {
					boundary: FailureBoundary::Backup,
					item: Some(0),
				});
				let preparation = apply_transaction(
					&test.environment,
					&test.group,
					&test.plan,
					&test.passwords(),
					&injected,
					&Cancellation::default(),
					|_| {},
				)
				.expect_err("create exact private root");
				assert_eq!(preparation.code, TransactionCode::InjectedFailure);
				// OSが作った限定ACLを保ち、所有する準備証拠だけを新規の兄弟directoryへ退避する
				let source = root.join(
					preparation
						.transaction_id
						.as_deref()
						.expect("own preparation ID"),
				);
				let destination = root
					.parent()
					.expect("own Java fixture")
					.join("retained-preparation-evidence");
				assert!(source.starts_with(fixtures()) && destination.starts_with(fixtures()));
				fs::rename(source, destination).expect("retain own preparation evidence");
				fs::write(root.join("foreign.txt"), b"preserve unknown data")
					.expect("foreign data");
			}
			"junction" => {
				let target = test
					.environment
					.root()
					.parent()
					.expect("case root")
					.join("junction-target");
				fs::create_dir(&target).expect("own junction target");
				let output = Command::new("powershell.exe").env_remove("PSModulePath")
					.env("JTR_FIXTURE_LINK", root.to_str().expect("fixture").trim_start_matches("\\\\?\\"))
					.env("JTR_FIXTURE_TARGET", target.to_str().expect("fixture").trim_start_matches("\\\\?\\"))
					.args(["-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop'; New-Item -ItemType Junction -Path $env:JTR_FIXTURE_LINK -Target $env:JTR_FIXTURE_TARGET | Out-Null"])
					.creation_flags(0x0800_0000).output().expect("fixture junction");
				assert!(
					output.status.success(),
					"{}",
					String::from_utf8_lossy(&output.stderr)
				);
			}
			"denied-create" => {
				fixture_directory_acl(test.environment.root(), true);
				// fixtureのACL設定に伴う子への継承を診断前状態として取り込み、診断後競合と混同しない
				let java = test.environment.root().to_path_buf();
				let case_root = java.parent().expect("own case root");
				let custom = ["custom 日本語.jks", "custom 日本語.p12"].map(|name| CustomStore {
					path: case_root.join(name),
					password: password(),
				});
				test.environment =
					select_java(&java, &Cancellation::default()).expect("deny fixture Java");
				let policy = embedded_policy().expect("policy");
				test.group = scan_java(
					&test.environment,
					&policy,
					&BuiltinPasswords {
						cacerts: &test.secret,
						jssecacerts: &test.secret,
					},
					&custom,
					&Cancellation::default(),
					|_| {},
				);
				test.plan = test.group.plan(&policy).expect("deny fixture plan");
			}
			"readonly" => {
				let path = test.group.stores()[0]
					.snapshot()
					.expect("snapshot")
					.canonical_path();
				let mut permissions = fs::metadata(path).expect("metadata").permissions();
				permissions.set_readonly(true);
				fs::set_permissions(path, permissions).expect("own readonly fixture");
			}
			_ => unreachable!("fixed labels"),
		}
		let error = apply_transaction(
			&test.environment,
			&test.group,
			&test.plan,
			&test.passwords(),
			&options,
			&Cancellation::default(),
			|_| {},
		)
		.expect_err("unsafe backup must refuse");
		assert_eq!(
			error.code,
			match label {
				"unknown" => TransactionCode::InvalidManifest,
				"denied-create" => TransactionCode::PermissionDenied,
				"readonly" => TransactionCode::StaleScan,
				_ => TransactionCode::UnsupportedMetadata,
			},
			"{label}: {error:?}"
		);
		test.assert_original();
		if label == "unknown" {
			assert_eq!(
				fs::read(root.join("foreign.txt")).expect("preserved"),
				b"preserve unknown data"
			);
		}
		if label == "denied-create" || label == "readonly" {
			assert!(!root.exists());
		}
		assert!(!test.options.backup_root().exists(), "no legacy fallback");
		println!(
			"Java-local {label}: {:?}; original bytes retained; no fallback",
			error.code
		);
	}
}

//------------------------------------------------------------------------------
/** 同じ設定の別Javaへの流用と移動したbackupの復元を拒否し、元の場所へ戻したfixtureだけ復元します。 */
//------------------------------------------------------------------------------
#[test]
#[ignore = "新規のJava内backup隔離fixtureが必要"]
fn java_local_backup_binds_environment_and_rejects_moved_records() {
	let test = prepared("local-moved");
	let other = prepared("local-other-java");
	let options = TransactionOptions::for_java(&test.environment).expect("local options");
	let error = apply_transaction(
		&other.environment,
		&other.group,
		&other.plan,
		&other.passwords(),
		&options,
		&Cancellation::default(),
		|_| {},
	)
	.expect_err("different environment");
	assert_eq!(error.code, TransactionCode::BackupLocationMismatch);
	other.assert_original();
	assert!(!options.backup_root().exists());
	let outcome = apply_transaction(
		&test.environment,
		&test.group,
		&test.plan,
		&test.passwords(),
		&options,
		&Cancellation::default(),
		|_| {},
	)
	.expect("local apply");
	let manifest =
		fs::read(outcome.backup_directory.join("manifest.json")).expect("original manifest");
	let original_root = test.environment.root();
	let moved_root = original_root.parent().expect("own case").join("moved Java");
	fs::rename(original_root, &moved_root).expect("move only own fixture");
	let moved = select_java(&moved_root, &Cancellation::default()).expect("moved Java");
	let moved_options = TransactionOptions::for_java(&moved).expect("moved options");
	let error =
		inspect_transaction(&moved_options, &outcome.transaction_id).expect_err("moved backup");
	assert_eq!(error.code, TransactionCode::BackupLocationMismatch);
	assert_eq!(
		restore_transaction(
			&moved,
			&moved_options,
			&outcome.transaction_id,
			&test.restore_passwords(),
			&Cancellation::default(),
			|_| {}
		)
		.expect_err("moved restore")
		.code,
		TransactionCode::BackupLocationMismatch
	);
	assert_eq!(
		fs::read(
			moved_options
				.backup_root()
				.join(&outcome.transaction_id)
				.join("manifest.json")
		)
		.expect("preserved manifest"),
		manifest
	);
	fs::rename(&moved_root, original_root).expect("return own fixture to original location");
	restore_transaction(
		&test.environment,
		&options,
		&outcome.transaction_id,
		&test.restore_passwords(),
		&Cancellation::default(),
		|_| {},
	)
	.expect("restore at original location");
	test.assert_original();
}

//------------------------------------------------------------------------------
/** Java内rootでも未完了準備は新規適用を止め、既知の部分適用は通常の復旧検証から完全復元します。 */
//------------------------------------------------------------------------------
#[test]
#[ignore = "新規のJava内backup隔離fixtureが必要"]
fn java_local_backup_preserves_incomplete_preparation_and_recovers_known_state() {
	for preparation in [true, false] {
		let test = prepared(if preparation {
			"local-incomplete"
		} else {
			"local-recovery"
		});
		let options = TransactionOptions::for_java(&test.environment).expect("local options");
		let injected = if preparation {
			options.clone().with_failure(FailurePoint {
				boundary: FailureBoundary::Backup,
				item: Some(0),
			})
		} else {
			options
				.clone()
				.with_failure(FailurePoint {
					boundary: FailureBoundary::AfterCommit,
					item: Some(0),
				})
				.with_failure(FailurePoint {
					boundary: FailureBoundary::BeforeRollback,
					item: Some(0),
				})
		};
		apply_transaction(
			&test.environment,
			&test.group,
			&test.plan,
			&test.passwords(),
			&injected,
			&Cancellation::default(),
			|_| {},
		)
		.expect_err("injected incomplete state");
		let entries = list_history(&options).expect("local history");
		assert_eq!(entries.len(), 1);
		let inspection = entries[0]
			.inspection
			.as_ref()
			.expect("incomplete inspection");
		if preparation {
			assert_eq!(inspection.state, HistoryState::IncompletePreparation);
			assert_eq!(
				apply_transaction(
					&test.environment,
					&test.group,
					&test.plan,
					&test.passwords(),
					&options,
					&Cancellation::default(),
					|_| {}
				)
				.expect_err("unresolved preparation")
				.code,
				TransactionCode::RecoveryRequired
			);
			assert_eq!(list_history(&options).expect("no new transaction").len(), 1);
		} else {
			assert_eq!(inspection.state, HistoryState::Recoverable);
			let outcome = recover_transaction(
				&test.environment,
				&options,
				&entries[0].transaction_id,
				&test.restore_passwords(),
				&Cancellation::default(),
				|_| {},
			)
			.expect("known local recovery");
			assert_eq!(outcome.state, TransactionState::Restored);
		}
		test.assert_original();
	}
}

//------------------------------------------------------------------------------
/** backup/stage/journal/途中置換の失敗は元を維持または逆順で完全 rollback します。 */
//------------------------------------------------------------------------------
#[test]
#[ignore = "隔離 transaction fixtures が必要"]
fn injected_boundaries_preserve_or_roll_back_every_store() {
	for (boundary, item) in [
		(FailureBoundary::Backup, Some(0)),
		(FailureBoundary::Stage, Some(0)),
		(FailureBoundary::Journal, Some(1)),
		(FailureBoundary::BeforeCommit, Some(1)),
		(FailureBoundary::AfterCommit, Some(1)),
	] {
		let test = prepared(&format!("failure-{boundary:?}"));
		let options = test
			.options
			.clone()
			.with_failure(FailurePoint { boundary, item });
		let error = apply_transaction(
			&test.environment,
			&test.group,
			&test.plan,
			&test.passwords(),
			&options,
			&Cancellation::default(),
			|_| {},
		)
		.expect_err("injected failure");
		assert_eq!(error.code, TransactionCode::InjectedFailure, "{error:?}");
		test.assert_original();
		if matches!(boundary, FailureBoundary::Backup | FailureBoundary::Stage) {
			assert_eq!(error.state, TransactionState::Aborted);
			assert_eq!(
				inspect_transaction(&test.options, error.transaction_id.as_deref().expect("ID"))
					.expect("incomplete")
					.state,
				HistoryState::IncompletePreparation
			);
		} else {
			assert_eq!(error.state, TransactionState::RolledBack, "{error:?}");
			assert_eq!(
				inspect_transaction(&test.options, error.transaction_id.as_deref().expect("ID"))
					.expect("rollback history")
					.state,
				HistoryState::RolledBack
			);
		}
		println!("{boundary:?}: original stores preserved, {:?}", error.state);
	}
}

//------------------------------------------------------------------------------
/** 元失敗と rollback 失敗を両方保持し、既知の部分状態を明示復旧で元へ戻します。 */
//------------------------------------------------------------------------------
#[test]
#[ignore = "隔離 transaction fixtures が必要"]
fn failed_rollback_retains_both_causes_and_supports_known_recovery() {
	let test = prepared("rollback-fails");
	let options = test
		.options
		.clone()
		.with_failure(FailurePoint {
			boundary: FailureBoundary::AfterCommit,
			item: Some(1),
		})
		.with_failure(FailurePoint {
			boundary: FailureBoundary::BeforeRollback,
			item: Some(0),
		});
	let error = apply_transaction(
		&test.environment,
		&test.group,
		&test.plan,
		&test.passwords(),
		&options,
		&Cancellation::default(),
		|_| {},
	)
	.expect_err("rollback injection");
	assert_eq!(error.code, TransactionCode::InjectedFailure);
	assert_eq!(error.state, TransactionState::RecoveryRequired);
	assert_eq!(error.rollback_errors.len(), 1);
	let id = error.transaction_id.as_deref().expect("ID");
	assert_eq!(
		inspect_transaction(&test.options, id)
			.expect("known states")
			.state,
		HistoryState::Recoverable
	);
	assert_eq!(
		recover_transaction(
			&test.environment,
			&test.options,
			id,
			&test.restore_passwords(),
			&Cancellation::default(),
			|_| {}
		)
		.expect("safe recovery")
		.state,
		TransactionState::Restored
	);
	test.assert_original();
}

//------------------------------------------------------------------------------
/** stale scan/cancel を変更前に拒否し、保持中のアプリ間 lock は同一 thread でも Busy にします。 */
//------------------------------------------------------------------------------
#[test]
#[ignore = "隔離 transaction fixtures が必要"]
fn refuses_stale_scan_cancel_and_reentrant_busy() {
	let test = prepared("preconditions");
	let cancellation = Cancellation::default();
	cancellation.cancel();
	let cancelled = apply_transaction(
		&test.environment,
		&test.group,
		&test.plan,
		&test.passwords(),
		&test.options,
		&cancellation,
		|_| {},
	)
	.expect_err("cancel");
	assert_eq!(cancelled.code, TransactionCode::Cancelled);
	assert!(!test.options.backup_root().exists());
	let wrong = StorePassword::new("bad-password".to_owned()).expect("wrong fixture password");
	let bad_password = apply_transaction(
		&test.environment,
		&test.group,
		&test.plan,
		&vec![&wrong; test.group.stores().len()],
		&test.options,
		&Cancellation::default(),
		|_| {},
	)
	.expect_err("bad apply password");
	assert_eq!(bad_password.code, TransactionCode::Keytool);
	test.assert_original();
	let preparing_cancel = Cancellation::default();
	let cancelled = apply_transaction(
		&test.environment,
		&test.group,
		&test.plan,
		&test.passwords(),
		&test.options,
		&preparing_cancel,
		|event| {
			if event.phase == TransactionPhase::Stage {
				preparing_cancel.cancel();
			}
		},
	)
	.expect_err("cancel preparation");
	assert_eq!(cancelled.code, TransactionCode::Cancelled);
	test.assert_original();
	let mut busy_checked = false;
	let committing_cancel = Cancellation::default();
	let applied = apply_transaction(
		&test.environment,
		&test.group,
		&test.plan,
		&test.passwords(),
		&test.options,
		&committing_cancel,
		|event| {
			if !busy_checked && event.phase == TransactionPhase::Backup {
				let busy = apply_transaction(
					&test.environment,
					&test.group,
					&test.plan,
					&test.passwords(),
					&test.options,
					&Cancellation::default(),
					|_| {},
				)
				.expect_err("busy");
				assert_eq!(busy.code, TransactionCode::Busy);
				busy_checked = true;
			}
			if event.phase == TransactionPhase::Commit {
				assert!(!event.cancellable);
				committing_cancel.cancel();
			}
		},
	)
	.expect("outer apply");
	assert!(busy_checked);
	restore_transaction(
		&test.environment,
		&test.options,
		&applied.transaction_id,
		&test.restore_passwords(),
		&Cancellation::default(),
		|_| {},
	)
	.expect("restore");
	test.assert_original();
	let stale = apply_transaction(
		&test.environment,
		&test.group,
		&test.plan,
		&test.passwords(),
		&test.options,
		&Cancellation::default(),
		|_| {},
	)
	.expect_err("restoration changes original file IDs, so old scan is stale");
	assert_eq!(stale.code, TransactionCode::StaleScan);
}

//------------------------------------------------------------------------------
/** 復元の途中失敗も逆順で適用後へ戻し、その後の通常復元が成功することを確認します。 */
//------------------------------------------------------------------------------
#[test]
#[ignore = "隔離 transaction fixtures が必要"]
fn restoration_failure_rolls_back_to_applied_and_can_be_retried() {
	let test = prepared("restore-rollback");
	let applied = apply_transaction(
		&test.environment,
		&test.group,
		&test.plan,
		&test.passwords(),
		&test.options,
		&Cancellation::default(),
		|_| {},
	)
	.expect("apply");
	let options = test.options.clone().with_failure(FailurePoint {
		boundary: FailureBoundary::AfterRestore,
		item: Some(1),
	});
	let error = restore_transaction(
		&test.environment,
		&options,
		&applied.transaction_id,
		&test.restore_passwords(),
		&Cancellation::default(),
		|_| {},
	)
	.expect_err("restore boundary");
	assert_eq!(error.code, TransactionCode::InjectedFailure);
	assert_eq!(error.state, TransactionState::Applied, "{error:?}");
	assert!(error.rollback_errors.is_empty(), "{error:?}");
	assert_eq!(
		inspect_transaction(&test.options, &applied.transaction_id)
			.expect("history")
			.state,
		HistoryState::Applied
	);
	restore_transaction(
		&test.environment,
		&test.options,
		&applied.transaction_id,
		&test.restore_passwords(),
		&Cancellation::default(),
		|_| {},
	)
	.expect("retry restore");
	test.assert_original();
}

//------------------------------------------------------------------------------
/** 不正 password・外部更新・Java 更新・backup 破損・不正 schema/path/hash/重複を拒否します。 */
//------------------------------------------------------------------------------
#[test]
#[ignore = "隔離 transaction fixtures が必要"]
fn restoration_rejects_untrusted_material_without_overwriting_targets() {
	for scenario in ["password", "external", "java", "backup", "manifest"] {
		let test = prepared(scenario);
		let applied = apply_transaction(
			&test.environment,
			&test.group,
			&test.plan,
			&test.passwords(),
			&test.options,
			&Cancellation::default(),
			|_| {},
		)
		.expect("apply");
		let target = applied.stores.last().expect("target");
		let wrong = StorePassword::new("bad-password".to_owned()).expect("wrong password");
		let passwords = if scenario == "password" {
			vec![&wrong; test.plan.stores().len()]
		} else {
			test.restore_passwords()
		};
		let mut expected = None;
		match scenario {
			"external" => {
				fs::OpenOptions::new()
					.append(true)
					.open(target)
					.expect("external open")
					.write_all(b"outside update")
					.expect("external update");
				expected = Some(TransactionCode::ExternalChange);
			}
			"java" => {
				fs::OpenOptions::new()
					.append(true)
					.open(test.environment.root().join("release"))
					.expect("release")
					.write_all(b"\n")
					.expect("Java update");
				expected = Some(TransactionCode::StaleJava);
			}
			"backup" => {
				let backup = applied.backup_directory.join("0000.original.bin");
				fs::write(backup, b"corrupt backup").expect("corruption");
				expected = Some(TransactionCode::BackupCorrupt);
			}
			"manifest" => {
				let path = applied.backup_directory.join("manifest.json");
				let original = fs::read(&path).expect("manifest");
				let parsed: serde_json::Value = serde_json::from_slice(&original).expect("JSON");
				for kind in 0..5 {
					let mut malformed = parsed.clone();
					match kind {
						0 => malformed["schema_version"] = serde_json::json!(999),
						1 => {
							malformed["items"][0]["backup_name"] =
								serde_json::json!("../escape.bin")
						}
						2 => {
							malformed["items"][0]["original"]["sha256"] =
								serde_json::json!("not-a-hash")
						}
						3 => {
							let duplicate = malformed["items"][0].clone();
							malformed["items"]
								.as_array_mut()
								.expect("array")
								.push(duplicate);
						}
						_ => {
							malformed["items"][0]["original"]["canonical_path"] =
								serde_json::json!("relative-target.jks")
						}
					}
					fs::write(&path, serde_json::to_vec(&malformed).expect("JSON"))
						.expect("test tampering");
					assert_eq!(
						inspect_transaction(&test.options, &applied.transaction_id)
							.expect_err("invalid manifest")
							.code,
						TransactionCode::InvalidManifest
					);
				}
				expected = Some(TransactionCode::InvalidManifest);
			}
			_ => {}
		}
		let before: Vec<_> = applied
			.stores
			.iter()
			.map(|path| sha256_hex(&fs::read(path).expect("before refusal")))
			.collect();
		let error = restore_transaction(
			&test.environment,
			&test.options,
			&applied.transaction_id,
			&passwords,
			&Cancellation::default(),
			|_| {},
		)
		.expect_err("refusal");
		if let Some(code) = expected {
			assert_eq!(error.code, code, "{scenario}: {error:?}");
		} else {
			assert_eq!(error.code, TransactionCode::Keytool, "{error:?}");
		}
		for (path, before) in applied.stores.iter().zip(before) {
			assert_eq!(sha256_hex(&fs::read(path).expect("after refusal")), before);
		}
		println!("restore {scenario}: refused without overwriting targets");
	}
}

//------------------------------------------------------------------------------
/** journal の末尾破断を成功扱いせず、元記録を残した新規分岐から既知状態を復元します。 */
//------------------------------------------------------------------------------
#[test]
#[ignore = "隔離 transaction fixtures が必要"]
fn torn_journal_is_detected_and_recovered_without_rewriting_evidence() {
	let test = prepared("torn-journal");
	let applied = apply_transaction(
		&test.environment,
		&test.group,
		&test.plan,
		&test.passwords(),
		&test.options,
		&Cancellation::default(),
		|_| {},
	)
	.expect("apply");
	let journal = applied.backup_directory.join("journal.jsonl");
	let mut bytes = fs::read(&journal).expect("journal");
	bytes.truncate(bytes.len() - 7);
	fs::write(&journal, &bytes).expect("simulate torn write");
	let inspection =
		inspect_transaction(&test.options, &applied.transaction_id).expect("torn tail");
	assert!(inspection.torn_journal);
	assert_eq!(inspection.state, HistoryState::Recoverable);
	assert!(
		restore_transaction(
			&test.environment,
			&test.options,
			&applied.transaction_id,
			&test.restore_passwords(),
			&Cancellation::default(),
			|_| {}
		)
		.is_err()
	);
	recover_transaction(
		&test.environment,
		&test.options,
		&applied.transaction_id,
		&test.restore_passwords(),
		&Cancellation::default(),
		|_| {},
	)
	.expect("recover known applied states");
	assert_eq!(fs::read(&journal).expect("original evidence"), bytes);
	assert!(
		applied
			.backup_directory
			.join("recovery-0001.jsonl")
			.is_file()
	);
	assert_eq!(
		inspect_transaction(&test.options, &applied.transaction_id)
			.expect("recovery history")
			.state,
		HistoryState::Restored
	);
	test.assert_original();
}

//------------------------------------------------------------------------------
/** 正しい password が PEM の語句と一致しても RFC を壊さず、両形式の適用と復元が成功します。 */
//------------------------------------------------------------------------------
#[test]
#[ignore = "隔離 transaction fixtures が必要"]
fn password_matching_pem_marker_does_not_corrupt_inventory() {
	let (root, java, options) = case(21, "pem-password");
	let cancellation = Cancellation::default();
	let environment = select_java(&java, &cancellation).expect("Java");
	for name in ["custom 日本語.jks", "custom 日本語.p12"] {
		let path = root.join(name);
		let path_text = path.to_str().expect("known Unicode fixture");
		let path_text = path_text.strip_prefix("\\\\?\\").unwrap_or(path_text);
		let mut command = Command::new(environment.keytool());
		command
			.args([
				"-J-Duser.language=en",
				"-J-Duser.country=US",
				"-storepasswd",
				"-keystore",
				path_text,
				"-storepass:env",
				"FIXTURE_OLD",
				"-new:env",
				"FIXTURE_NEW",
			])
			.env_clear()
			.env("FIXTURE_OLD", "changeit")
			.env("FIXTURE_NEW", "CERTIFICATE")
			.creation_flags(0x0800_0000);
		for key in ["SystemRoot", "WINDIR", "TEMP", "TMP"] {
			if let Some(value) = std::env::var_os(key) {
				command.env(key, value);
			}
		}
		let output = command.output().expect("fixture keytool");
		assert!(output.status.success(), "fixture password change");
	}
	let builtin_password = password();
	let pem_password = StorePassword::new("CERTIFICATE".to_owned()).expect("fixture password");
	assert!(!format!("{pem_password:?}").contains("CERTIFICATE"));
	let custom = [
		CustomStore {
			path: root.join("custom 日本語.jks"),
			password: StorePassword::new("CERTIFICATE".to_owned()).expect("password"),
		},
		CustomStore {
			path: root.join("custom 日本語.p12"),
			password: StorePassword::new("CERTIFICATE".to_owned()).expect("password"),
		},
	];
	let policy = embedded_policy().expect("policy");
	let group = scan_java(
		&environment,
		&policy,
		&BuiltinPasswords {
			cacerts: &builtin_password,
			jssecacerts: &builtin_password,
		},
		&custom,
		&cancellation,
		|_| {},
	);
	let plan = group.plan(&policy).expect("PEM remains parseable");
	let passwords = [
		&builtin_password,
		&builtin_password,
		&pem_password,
		&pem_password,
	];
	let applied = apply_transaction(
		&environment,
		&group,
		&plan,
		&passwords,
		&options,
		&cancellation,
		|_| {},
	)
	.expect("apply");
	let restore_passwords: Vec<_> = plan
		.stores()
		.iter()
		.map(|store| passwords[store.report_index()])
		.collect();
	restore_transaction(
		&environment,
		&options,
		&applied.transaction_id,
		&restore_passwords,
		&cancellation,
		|_| {},
	)
	.expect("restore");
	for store in group.stores() {
		let original = store.snapshot().expect("snapshot");
		assert_eq!(
			sha256_hex(&fs::read(original.canonical_path()).expect("original bytes")),
			original.sha256()
		);
	}
}

//------------------------------------------------------------------------------
/** 欠落を通常復元で上書きせず、開始記録と同 volume 元 recovery copy が揃う場合だけ復旧します。 */
//------------------------------------------------------------------------------
#[test]
#[ignore = "隔離 transaction fixtures が必要"]
fn missing_target_requires_pending_record_and_verified_recovery_copy() {
	let test = prepared("missing-target");
	let applied = apply_transaction(
		&test.environment,
		&test.group,
		&test.plan,
		&test.passwords(),
		&test.options,
		&Cancellation::default(),
		|_| {},
	)
	.expect("apply");
	let target = &applied.stores[0];
	let evidence = target
		.parent()
		.expect("parent")
		.join("missing-target-held-evidence.bin");
	fs::rename(target, &evidence).expect("simulate missing target without deleting bytes");
	assert_eq!(
		inspect_transaction(&test.options, &applied.transaction_id)
			.expect("missing")
			.state,
		HistoryState::RecoveryRequired
	);
	assert!(
		recover_transaction(
			&test.environment,
			&test.options,
			&applied.transaction_id,
			&test.restore_passwords(),
			&Cancellation::default(),
			|_| {}
		)
		.is_err()
	);
	assert!(!target.exists());
	let journal = applied.backup_directory.join("journal.jsonl");
	let bytes = fs::read(&journal).expect("journal");
	let pending: Vec<_> = bytes
		.split_inclusive(|byte| *byte == b'\n')
		.take(3)
		.flatten()
		.copied()
		.collect();
	fs::write(&journal, pending).expect("simulate interruption after first ReplaceStarted");
	assert_eq!(
		inspect_transaction(&test.options, &applied.transaction_id)
			.expect("safe missing state")
			.state,
		HistoryState::Recoverable
	);
	recover_transaction(
		&test.environment,
		&test.options,
		&applied.transaction_id,
		&test.restore_passwords(),
		&Cancellation::default(),
		|_| {},
	)
	.expect("unique recovery");
	assert!(evidence.exists(), "unknown evidence is never deleted");
	test.assert_original();
}

//------------------------------------------------------------------------------
/** 監査 SACL を持つ新規 fixture は、内容を書かず UnsupportedMetadata で適用を拒否します。 */
//------------------------------------------------------------------------------
#[test]
#[ignore = "SACL 設定特権と隔離 transaction fixtures が必要"]
fn refuses_sacl_instead_of_losing_audit_metadata() {
	let mut test = prepared("sacl-refusal");
	let root = test.environment.root().parent().expect("case root");
	let target = root.join("custom 日本語.jks");
	let script = root.join("set-fixture-audit.ps1");
	fs::write(&script, br#"param([string]$Target)
$ErrorActionPreference = 'Stop'
$security = Get-Acl -LiteralPath $Target -Audit
$sid = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
$rule = [System.Security.AccessControl.FileSystemAuditRule]::new($sid,[System.Security.AccessControl.FileSystemRights]::ReadData,[System.Security.AccessControl.AuditFlags]::Success)
$security.AddAuditRule($rule)
Set-Acl -LiteralPath $Target -AclObject $security
if ((Get-Acl -LiteralPath $Target -Audit).Audit.Count -ne 1) { throw 'Expected fixture audit entry' }
"#).expect("fixture script");
	let output = Command::new("powershell.exe")
		.env_remove("PSModulePath")
		.args([
			"-NoProfile",
			"-NonInteractive",
			"-ExecutionPolicy",
			"Bypass",
			"-File",
		])
		.arg(
			script
				.to_str()
				.expect("fixture Unicode path")
				.trim_start_matches("\\\\?\\"),
		)
		.arg(
			target
				.to_str()
				.expect("fixture Unicode path")
				.trim_start_matches("\\\\?\\"),
		)
		.creation_flags(0x0800_0000)
		.output()
		.expect("fixture SACL setup");
	assert!(
		output.status.success(),
		"SACL fixture setup requires SeSecurityPrivilege: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	let custom = [
		CustomStore {
			path: target,
			password: password(),
		},
		CustomStore {
			path: root.join("custom 日本語.p12"),
			password: password(),
		},
	];
	let policy = embedded_policy().expect("policy");
	test.group = scan_java(
		&test.environment,
		&policy,
		&BuiltinPasswords {
			cacerts: &test.secret,
			jssecacerts: &test.secret,
		},
		&custom,
		&Cancellation::default(),
		|_| {},
	);
	test.plan = test
		.group
		.plan(&policy)
		.expect("read-only inventory is complete");
	let error = apply_transaction(
		&test.environment,
		&test.group,
		&test.plan,
		&test.passwords(),
		&test.options,
		&Cancellation::default(),
		|_| {},
	)
	.expect_err("SACL must not be lost");
	assert_eq!(
		error.code,
		TransactionCode::UnsupportedMetadata,
		"{error:?}"
	);
	assert_eq!(error.state, TransactionState::Aborted);
	test.assert_original();
	assert!(!test.options.backup_root().exists());
}
