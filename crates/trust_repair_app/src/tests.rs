//------------------------------------------------------------------------------
/*!
 * - ファイル: tests.rs
 * - 概要: GUI の言語境界、秘密の非保存、未完了優先とキーボード入力を検証します。
 * - バージョン: 01.03.00
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
 * Ver.01.00.00  Shunji Ogawa  2026/10/26  GUI 固有の失敗/秘密/言語/keyboard 契約を追加。
 * Ver.01.01.00  Shunji Ogawa  2026/10/26  簡素化した確認破棄・未完了案内・秘密非保存へ更新。
 * Ver.01.02.00  Shunji Ogawa  2026/10/26  自動判定の保守的分類・世代拒否・非消費入力を検証。
 * Ver.01.03.00  Shunji Ogawa  2026/10/26  選択Javaの履歴だけを採用し、入力変更で保存先と履歴を分離。
 * ```
 *
 * 備考: ファイル・Java を変更しない試験です。native の実測は別の明示 QA で行います。
 */
//------------------------------------------------------------------------------

use super::*;
use trust_repair_windows::{ItemState, TransactionInspection};

//------------------------------------------------------------------------------
/** ファイル操作を開始しない固定設定で GUI 状態を作ります。失敗なら試験を失敗させます。 */
//------------------------------------------------------------------------------
fn app(language: Language) -> TrustRepairApp {
	TrustRepairApp::new(
		embedded_policy().expect("embedded test policy"),
		language,
		TransactionOptions::with_backup_root(PathBuf::from("D:/isolated-ui-tests/backups"))
			.expect("fixed absolute test path"),
	)
}

//------------------------------------------------------------------------------
/** 言語の主番号と地域差、未知値を検証します。日本語以外は英語を要求します。 */
//------------------------------------------------------------------------------
#[test]
fn selects_display_language_by_primary_langid() {
	assert!(Language::from_langid(0x0411) == Language::Japanese);
	assert!(Language::from_langid(0x0811) == Language::Japanese);
	for id in [0, 0x0409, 0x0809, 0x0407, 0x0804] {
		assert!(Language::from_langid(id) == Language::English);
	}
}

//------------------------------------------------------------------------------
/** 入力秘密を結果保存へ含めず、入力変更で確認・再入力を破棄する契約を検証します。 */
//------------------------------------------------------------------------------
#[test]
fn excludes_passwords_and_invalidates_confirmation() {
	let mut app = app(Language::Japanese);
	*app.builtin[0].value = "sensitive-test-marker".to_owned();
	app.custom.push(StoreInput {
		path: PathBuf::from("D:/isolated-ui-tests/custom"),
		password: PasswordInput::new(),
	});
	*app.custom[0].password.value = "second-secret-marker".to_owned();
	app.confirmation = Some(Confirmation::Deactivate);
	assert!(!app.report().contains("sensitive-test-marker"));
	assert!(!app.report().contains("second-secret-marker"));
	app.invalidate();
	assert!(app.confirmation.is_none());
	assert!(app.current_status == CurrentStatus::Unknown);
}

//------------------------------------------------------------------------------
/** 群全体成功後のNoTargetsだけを無効化済みとし、失敗・警告をその状態へ変換しません。 */
//------------------------------------------------------------------------------
#[test]
fn distinguishes_no_targets_from_blocked_or_failed() {
	assert!(CurrentStatus::from_plan(&Err(PlanError::NoTargets)) == CurrentStatus::Disabled);
	for error in [
		PlanError::EmptySelection,
		PlanError::Blocked { report_index: 0 },
		PlanError::PolicyMismatch,
	] {
		assert!(CurrentStatus::from_plan(&Err(error)) == CurrentStatus::Unavailable);
	}
}

//------------------------------------------------------------------------------
/** 古い入力世代の失敗は新しいfolderの表示を変更せず、空入力には自動jobを予約しません。 */
//------------------------------------------------------------------------------
#[test]
fn discards_old_generation_and_clears_empty_selection() {
	let mut app = app(Language::English);
	app.root_text = "D:/isolated-ui-tests/first".to_owned();
	app.invalidate();
	let old = app.input_generation;
	app.root_text = "D:/isolated-ui-tests/second".to_owned();
	app.invalidate();
	app.accept_auto_check(old, Err(Failure::Interrupted));
	assert!(app.current_status == CurrentStatus::Unknown && app.error_details.is_empty());
	assert!(app.auto_due.is_some());
	app.root_text.clear();
	app.invalidate();
	assert!(app.auto_due.is_none());
}

//------------------------------------------------------------------------------
/** 自動確認のsnapshot後もcustom入力を保持し、続く無効化操作で同じ入力を一度だけ消費できます。 */
//------------------------------------------------------------------------------
#[test]
fn automatic_snapshot_does_not_consume_custom_password() {
	let mut app = app(Language::Japanese);
	app.builtin[0].standard = false;
	*app.builtin[0].value = "test-secret".to_owned();
	app.custom.push(StoreInput {
		path: PathBuf::from("D:/isolated-ui-tests/custom"),
		password: PasswordInput::new(),
	});
	*app.custom[0].password.value = "custom-test-secret".to_owned();
	let snapshot = app.snapshot_credentials().expect("fixed valid test inputs");
	drop(snapshot);
	assert!(app.builtin[0].value.as_str() == "test-secret");
	assert!(app.custom[0].password.value.as_str() == "custom-test-secret");
	assert!(!app.report().contains("test-secret"));
	let operation = app.take_credentials().expect("same input remains usable");
	drop(operation);
	assert!(app.builtin[0].value.is_empty() && app.custom[0].password.value.is_empty());
}

//------------------------------------------------------------------------------
/** 読み取り/特権/保存の実権限不足は、日英の主画面と自動確認で管理者起動案内を維持します。 */
//------------------------------------------------------------------------------
#[test]
fn displays_administrator_advice_without_confusing_unsupported_metadata() {
	for language in [Language::Japanese, Language::English] {
		for code in [5, 1300, 1314] {
			let mut app = app(language);
			app.accept_auto_check(
				0,
				Err(Failure::Java(trust_repair_windows::JavaError::File(
					trust_repair_windows::FileSafetyError::Io {
						operation: "read",
						os_code: Some(code),
					},
				))),
			);
			assert!(app.error && app.current_status == CurrentStatus::Unavailable);
			assert_eq!(app.message, language.administrator_required());
			assert!(app.outcome.is_none());
		}
		let mut app = app(language);
		app.accept(Err(Failure::Save(std::io::ErrorKind::PermissionDenied)));
		assert_eq!(app.message, language.administrator_required());
		app.accept(Err(Failure::Java(trust_repair_windows::JavaError::File(
			trust_repair_windows::FileSafetyError::NamedStreams,
		))));
		assert_ne!(app.message, language.administrator_required());
		assert_ne!(
			language.code(TransactionCode::UnsupportedMetadata),
			language.administrator_required()
		);
	}
}

//------------------------------------------------------------------------------
/** 別Javaを選択した時点で古い履歴/復元確認を捨て、表示・保存先も選択Java内へ切り替えます。 */
//------------------------------------------------------------------------------
#[test]
fn changes_backup_location_and_clears_history_with_selected_java() {
	let mut app = app(Language::English);
	assert!(app.root_text.is_empty() && app.history.is_empty() && app.worker.is_none());
	app.root_text = "D:/isolated-ui-tests/first".to_owned();
	app.confirmation = Some(Confirmation::Deactivate);
	app.history.push(HistoryEntry {
		transaction_id: "unknown".to_owned(),
		inspection: Err(trust_repair_windows::TransactionError {
			code: TransactionCode::InvalidManifest,
			phase: trust_repair_windows::TransactionPhase::History,
			state: TransactionState::Aborted,
			context: Box::new(trust_repair_windows::TransactionContext {
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
		}),
	});
	app.root_text = "D:/isolated-ui-tests/second".to_owned();
	app.invalidate();
	assert!(app.history.is_empty() && app.confirmation.is_none() && !app.needs_recovery);
	assert_eq!(
		app.selected_backup_root(),
		PathBuf::from("D:/isolated-ui-tests/second/emudhra-backup")
	);
	assert!(app.report().contains("second\\emudhra-backup"));
}

//------------------------------------------------------------------------------
/** 未完了履歴を復旧入口へ優先し、worker 切断を成功や outcome にしないことを検証します。 */
//------------------------------------------------------------------------------
#[test]
fn prioritizes_incomplete_history_and_rejects_interrupted_success() {
	let mut app = app(Language::English);
	app.root_text = "D:/isolated-ui-tests/Java".to_owned();
	app.accept(Ok(Completed::History(vec![HistoryEntry {
		transaction_id: "test-id".to_owned(),
		inspection: Ok(TransactionInspection {
			transaction_id: "test-id".to_owned(),
			backup_directory: PathBuf::from("D:/isolated-ui-tests/Java/emudhra-backup/test-id"),
			state: HistoryState::Recoverable,
			items: vec![ItemState::Original],
			stores: vec![PathBuf::from("D:/isolated-ui-tests/cacerts")],
			java_root: PathBuf::from("D:/isolated-ui-tests/Java"),
			torn_journal: true,
			java_unchanged: true,
		}),
	}])));
	assert!(app.needs_recovery);
	assert!(app.root_text.contains("isolated-ui-tests"));
	// 同じJavaの古い履歴が未知状態でも、直近Appliedを未完了と誤表示しない
	let mut older = app.history.remove(0);
	older.inspection.as_mut().expect("fixed inspection").state = HistoryState::RecoveryRequired;
	app.needs_recovery = false;
	app.accept(Ok(Completed::History(vec![
		HistoryEntry {
			transaction_id: "newer-test-id".to_owned(),
			inspection: Ok(TransactionInspection {
				transaction_id: "newer-test-id".to_owned(),
				backup_directory: PathBuf::from(
					"D:/isolated-ui-tests/Java/emudhra-backup/newer-test-id",
				),
				state: HistoryState::Applied,
				items: Vec::new(),
				stores: Vec::new(),
				java_root: PathBuf::from("D:/isolated-ui-tests/Java"),
				torn_journal: false,
				java_unchanged: true,
			}),
		},
		older,
	])));
	assert!(!app.needs_recovery);
	app.accept(Err(Failure::Interrupted));
	assert!(app.error);
	assert!(app.outcome.is_none());
	assert!(app.error_details.contains("Success cannot be confirmed"));
}

//------------------------------------------------------------------------------
/** 実際の egui widget に Tab/Space を渡し、マウスなしで標準値を明示選択できることを確認します。 */
//------------------------------------------------------------------------------
#[test]
fn toggles_explicit_password_choice_with_keyboard() {
	let context = egui::Context::default();
	let mut password = PasswordInput::new();
	*password.value = "erase-on-toggle".to_owned();
	let mut output = context.run_ui(egui::RawInput::default(), |ui| {
		password.draw(ui, Language::English);
	});
	output.textures_delta.clear();
	for key in [egui::Key::Tab, egui::Key::Tab, egui::Key::Space] {
		let events = [true, false]
			.into_iter()
			.map(|pressed| egui::Event::Key {
				key,
				physical_key: None,
				pressed,
				repeat: false,
				modifiers: egui::Modifiers::NONE,
			})
			.collect();
		let mut output = context.run_ui(
			egui::RawInput {
				events,
				..Default::default()
			},
			|ui| {
				password.draw(ui, Language::English);
			},
		);
		output.textures_delta.clear();
	}
	assert!(password.standard);
	assert!(password.value.is_empty());
}
