//------------------------------------------------------------------------------
/*!
 * - ファイル: readonly_scan.rs
 * - 概要: 隔離コピーの実 keytool で四つの LTS を読み取り診断します
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
 * 手動準備した試験領域だけを使用し、Java の導入や store の作成は行いません
 */
//------------------------------------------------------------------------------

#![cfg(windows)]

use std::fs;
use std::path::PathBuf;

use trust_repair_core::{IssueCode, PlanError, ScanStatus, embedded_policy, sha256_hex};
use trust_repair_windows::{
	BuiltinPasswords, Cancellation, CustomStore, ScanFailure, ScanPhase, StorePassword, scan_java,
	select_java,
};

//------------------------------------------------------------------------------
/**
 * 明示された隔離 fixture root を返します。未設定または workspace 外なら試験を失敗させます
 */
//------------------------------------------------------------------------------
fn fixtures() -> PathBuf {
	let root = PathBuf::from(
		std::env::var_os("JAVA_TRUST_REPAIR_FIXTURES")
			.expect("隔離 fixture root を明示してください"),
	);
	let allowed = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
		.join("../../artifacts/diagnostics")
		.canonicalize()
		.expect("試験領域");
	let root = root.canonicalize().expect("fixture root");
	assert!(root.starts_with(allowed));
	root
}

//------------------------------------------------------------------------------
/**
 * 非秘密の固定試験用 password を、製品と同じ所有型へ渡します
 */
//------------------------------------------------------------------------------
fn password() -> StorePassword {
	StorePassword::new("changeit".to_owned()).expect("fixture password")
}

//------------------------------------------------------------------------------
/**
 * Java 11/17/21/25 の cacerts/jssecacerts と両 custom 形式を診断し、元 byte 不変を確認します。
 * 対象証明書の二重別名と Unicode を省略せず、重複 file 指定は統合する必要があります
 */
//------------------------------------------------------------------------------
#[test]
#[ignore = "tools/prepare-diagnostics-fixtures.ps1 で用意した隔離 Java が必要"]
fn scans_four_lts_both_formats_without_writing_any_store() {
	let root = fixtures();
	let policy = embedded_policy().expect("policy");
	let secret = password();
	let passwords = BuiltinPasswords {
		cacerts: &secret,
		jssecacerts: &secret,
	};
	// 四つの runtime は別の隔離 root で、すべて同じ製品経路を実行する
	for major in [11, 17, 21, 25] {
		let java_root = root.join(format!("Java {major} 読取 診断"));
		let cancellation = Cancellation::default();
		let environment = select_java(&java_root, &cancellation).expect("選択 Java を検証");
		assert_eq!(environment.major(), major);
		assert!(environment.issues().is_empty());
		let paths = [
			java_root.join("lib/security/cacerts"),
			java_root.join("lib/security/jssecacerts"),
			root.join("custom 日本語.jks"),
			root.join("custom 日本語.p12"),
		];
		let hashes: Vec<_> = paths
			.iter()
			.map(|path| sha256_hex(&fs::read(path).expect("before")))
			.collect();
		let custom = [
			CustomStore {
				path: paths[2].clone(),
				password: password(),
			},
			CustomStore {
				path: paths[3].clone(),
				password: password(),
			},
			CustomStore {
				path: paths[2].clone(),
				password: password(),
			},
		];
		let mut phases = Vec::new();
		let group = scan_java(
			&environment,
			&policy,
			&passwords,
			&custom,
			&cancellation,
			|event| phases.push(event.phase),
		);
		assert_eq!(group.stores().len(), 4, "同一実体の指定は統合する");
		// 全ストアの完全な inventory と snapshot の再照合を要求する
		for (index, store) in group.stores().iter().enumerate() {
			assert!(
				store.failure().is_none(),
				"Java {major}, store {index}: {:?}",
				store.failure()
			);
			assert!(
				store.report().issues().is_empty(),
				"Java {major}, store {index}: {:?}",
				store.report()
			);
			let snapshot = store.snapshot().expect("snapshot");
			assert!(!snapshot.security_descriptor().is_empty());
			snapshot.revalidate(32 * 1024 * 1024).expect("再照合");
			// 明示 custom の範囲では日本語パスと重複指定も保持されたことを確認する
			if index >= 2 {
				assert_eq!(store.report().targets().len(), 5);
				assert_eq!(
					store
						.report()
						.inventory()
						.expect("inventory")
						.entries()
						.len(),
					6
				);
			}
		}
		let plan = group.plan(&policy).expect("群全体の計画");
		assert_eq!(plan.policy_id(), policy.id());
		assert!(plan.stores().len() >= 2);
		assert_eq!(phases.first(), Some(&ScanPhase::ValidateJava));
		assert_eq!(phases.last(), Some(&ScanPhase::Complete));
		// 診断した全実体をもう一度読み、元 byte hash の不変を確認する
		for (path, before) in paths.iter().zip(hashes) {
			assert_eq!(
				sha256_hex(&fs::read(path).expect("after")),
				before,
				"元ストア不変"
			);
		}
		println!(
			"Java {major}: {} stores, {} planned stores; hashes unchanged",
			group.stores().len(),
			plan.stores().len()
		);
	}
}

//------------------------------------------------------------------------------
/**
 * password 不正・破損・同名別 DER・秘密鍵/対称鍵の一つで、他の成功の計画も止めます
 */
//------------------------------------------------------------------------------
#[test]
#[ignore = "隔離 fixtures が必要"]
fn rejects_bad_password_corruption_collision_and_key_material() {
	let root = fixtures();
	let policy = embedded_policy().expect("policy");
	let secret = password();
	let passwords = BuiltinPasswords {
		cacerts: &secret,
		jssecacerts: &secret,
	};
	let cancellation = Cancellation::default();
	let environment = select_java(&root.join("Java 21 読取 診断"), &cancellation).expect("Java");
	// 他の成功した custom を必ず同じ群へ含め、部分適用に進まないことを試す
	for (name, wrong_password, expected) in [
		("custom 日本語.jks", true, None),
		("corrupt.jks", false, None),
		("collision.jks", false, Some(IssueCode::NameCollision)),
		("private.p12", false, Some(IssueCode::KeyMaterial)),
		("private.jks", false, Some(IssueCode::KeyMaterial)),
		("secret.p12", false, Some(IssueCode::KeyMaterial)),
	] {
		let path = root.join(name);
		let before = sha256_hex(&fs::read(&path).expect("before"));
		// 誤 password の条件だけに非秘密の誤入力を使い、各失敗原因を分ける
		let bad = if wrong_password {
			StorePassword::new("wrong-password".to_owned()).expect("test password")
		} else {
			password()
		};
		let custom = [
			CustomStore {
				path: root.join("custom 日本語.p12"),
				password: password(),
			},
			CustomStore {
				path: path.clone(),
				password: bad,
			},
		];
		let group = scan_java(
			&environment,
			&policy,
			&passwords,
			&custom,
			&cancellation,
			|_| {},
		);
		assert!(
			matches!(group.plan(&policy), Err(PlanError::Blocked { .. })),
			"{name}"
		);
		let failed = group.stores().last().expect("custom");
		// 既知の抑止理由がある条件では、その型付き理由まで保持されることを確認する
		if let Some(issue) = expected {
			assert!(
				failed.report().issues().contains(&issue),
				"{name}: {:?}",
				failed
			);
			assert!(
				failed.report().inventory().is_some(),
				"鍵や同名衝突でも inventory を表示する"
			);
			// 秘密鍵と対称鍵で期待する inventory の構造を分け、どちらも変更不可と確認する
			if name == "private.jks" {
				assert!(!failed.warnings().is_empty());
			}
		} else {
			assert_eq!(failed.report().status(), ScanStatus::Failed);
			assert!(matches!(failed.failure(), Some(ScanFailure::Process(_))));
		}
		assert_eq!(sha256_hex(&fs::read(&path).expect("after")), before);
	}
}

//------------------------------------------------------------------------------
/**
 * 利用者の中断は結果に残り、child を起動せず群全体の計画を無効にします
 */
//------------------------------------------------------------------------------
#[test]
#[ignore = "隔離 fixtures が必要"]
fn cancelled_scan_cannot_create_a_plan() {
	let root = fixtures();
	let policy = embedded_policy().expect("policy");
	let cancellation = Cancellation::default();
	let environment = select_java(&root.join("Java 17 読取 診断"), &cancellation).expect("Java");
	let secret = password();
	cancellation.cancel();
	let group = scan_java(
		&environment,
		&policy,
		&BuiltinPasswords {
			cacerts: &secret,
			jssecacerts: &secret,
		},
		&[],
		&cancellation,
		|_| {},
	);
	assert!(
		group
			.stores()
			.iter()
			.all(|store| store.report().issues().contains(&IssueCode::Cancelled))
	);
	assert!(group.plan(&policy).is_err());
}

//------------------------------------------------------------------------------
/**
 * 祖先 junction と診断中の外部書換えを検出し、他ストアの部分計画も作りません
 */
//------------------------------------------------------------------------------
#[test]
#[ignore = "隔離 fixtures が必要"]
fn rejects_ancestor_junction_and_external_update_during_scan() {
	let root = fixtures();
	let linked = root.join("junction/lib/security/cacerts");
	assert_eq!(
		trust_repair_windows::read_snapshot(&linked, 32 * 1024 * 1024).expect_err("junction"),
		trust_repair_windows::FileSafetyError::ReparsePoint
	);
	let policy = embedded_policy().expect("policy");
	let cancellation = Cancellation::default();
	let environment = select_java(&root.join("Java 21 読取 診断"), &cancellation).expect("Java");
	let path = root.join(format!("externally-changing-{}.jks", std::process::id()));
	fs::copy(root.join("custom 日本語.jks"), &path).expect("isolated changing store");
	let secret = password();
	let custom = [CustomStore {
		path: path.clone(),
		password: password(),
	}];
	let mut changed = false;
	let group = scan_java(
		&environment,
		&policy,
		&BuiltinPasswords {
			cacerts: &secret,
			jssecacerts: &secret,
		},
		&custom,
		&cancellation,
		|event| {
			// 指定ストアの一覧取得中に一度だけ外部変更し、診断全体の再照合で検出させる
			if !changed && event.phase == ScanPhase::ListInventory && event.input_index == Some(2) {
				fs::write(&path, b"external update during scan").expect("external fixture update");
				changed = true;
			}
		},
	);
	assert!(changed);
	assert!(
		group
			.stores()
			.last()
			.expect("custom")
			.report()
			.issues()
			.contains(&IssueCode::ChangedDuringScan)
	);
	assert!(group.plan(&policy).is_err());
}

//------------------------------------------------------------------------------
/**
 * 選択後に Java が変化した場合、keytool の工程を一度も開始せず全群を無効にします
 */
//------------------------------------------------------------------------------
#[test]
#[ignore = "隔離 fixtures が必要"]
fn rejects_stale_java_before_starting_keytool() {
	let root = fixtures().join("Java stale selection");
	let policy = embedded_policy().expect("policy");
	let cancellation = Cancellation::default();
	let environment = select_java(&root, &cancellation).expect("Java");
	let release = root.join("release");
	let mut bytes = fs::read(&release).expect("release");
	bytes.push(b'\n');
	fs::write(&release, bytes).expect("external Java metadata update");
	let secret = password();
	let mut phases = Vec::new();
	let group = scan_java(
		&environment,
		&policy,
		&BuiltinPasswords {
			cacerts: &secret,
			jssecacerts: &secret,
		},
		&[],
		&cancellation,
		|event| phases.push(event.phase),
	);
	assert_eq!(phases, [ScanPhase::ValidateJava, ScanPhase::Complete]);
	assert!(group.stores().iter().all(|store| {
		store
			.report()
			.issues()
			.contains(&IssueCode::ChangedDuringScan)
	}));
	assert!(group.plan(&policy).is_err());
}
