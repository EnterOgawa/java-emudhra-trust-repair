//------------------------------------------------------------------------------
/*!
 * - ファイル: tests.rs
 * - 概要: GUI の言語境界、秘密の非保存、未完了優先とキーボード入力を検証します。
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
 * ファイル・Java を変更しない試験です。native の実測は別の明示 QA で行います。
 */
//------------------------------------------------------------------------------

use super::*;
use std::sync::mpsc;
use std::thread;
use trust_repair_windows::{ItemState, TransactionInspection};

//------------------------------------------------------------------------------
/**
 * ファイル操作を開始しない固定設定で GUI 状態を作ります。失敗なら試験を失敗させます。
 */
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
/**
 * ファイルを変更せず、pollが保持すべき検証済み結果と再起動要否を作ります。
 */
//------------------------------------------------------------------------------
fn poll_outcome(state: TransactionState, restart_required: bool) -> TransactionOutcome {
	TransactionOutcome {
		transaction_id: "poll-result".to_owned(),
		state,
		backup_directory: PathBuf::from("D:/isolated-ui-tests/backups/poll-result"),
		stores: vec![PathBuf::from("D:/isolated-ui-tests/cacerts")],
		restart_required,
	}
}

//------------------------------------------------------------------------------
/**
 * 制御済みworkerが終了判定へ到達するまで待ちます。sleepを使わず、試験障害は5秒で失敗します。
 *
 * # Arguments
 *
 * - `worker`: この試験が終了を制御する worker。
 *
 * # Panics
 *
 * 5 秒以内に thread が終了判定へ到達しなければ試験を失敗させます。
 */
//------------------------------------------------------------------------------
fn await_worker_finished(worker: &Worker) {
	let deadline = Instant::now() + Duration::from_secs(5);
	// 終了判定まで譲り合って待ち、5 秒の上限で同期障害を検出する
	while !worker.handle.is_finished() {
		assert!(Instant::now() < deadline, "controlled worker must finish");
		thread::yield_now();
	}
}

//------------------------------------------------------------------------------
/**
 * pollの初回受信を必ずEmptyにし、その直後だけ通知送信・thread終了を許可します。
 * 実際のpollを呼ぶ試験専用で、panic指定時も所有threadはpollで回収します。
 *
 * # Arguments
 *
 * - `app`: 初回 drain 後の一回限りの同期点を設定する試験画面。
 * - `events`: 同期点の受理後に送る順序付き通知。
 * - `panics`: `true` は通知後に制御 thread を panic させます。
 *
 * # Notes
 *
 * UI 側の初回 Empty を確認するまで通知を保留し、実際の poll の競合窓を固定します。
 */
//------------------------------------------------------------------------------
fn finish_after_initial_drain(app: &mut TrustRepairApp, events: Vec<Event>, panics: bool) {
	let (release, wait) = mpsc::channel();
	let (sender, receiver) = mpsc::channel();
	let handle = thread::spawn(move || {
		wait.recv().expect("poll releases controlled worker");
		// 初回 Empty の確認後に全通知を指定順で送り、終了判定との競合を固定する
		for event in events {
			assert!(sender.send(event).is_ok(), "poll owns the receiver");
		}
		assert!(!panics, "controlled worker panic");
	});
	app.worker = Some(Worker {
		cancellation: trust_repair_windows::Cancellation::default(),
		receiver,
		handle,
	});
	app.after_worker_drain = Some(Box::new(move |worker| {
		assert!(matches!(
			worker.receiver.try_recv(),
			Err(TryRecvError::Empty)
		));
		assert!(!worker.handle.is_finished());
		release.send(()).expect("controlled worker waits for poll");
		await_worker_finished(worker);
	}));
}

//------------------------------------------------------------------------------
/**
 * 初回Empty→Done送信→thread終了の順でも、検証済み状態・再起動要否を一度だけ採用します。
 */
//------------------------------------------------------------------------------
#[test]
fn poll_accepts_done_sent_between_initial_empty_and_finished_check() {
	// 適用・復元・二重復元の全状態で、遅着 Done の結果と再起動要否を検証する
	for (state, status, restart) in [
		(TransactionState::Applied, CurrentStatus::Disabled, true),
		(
			TransactionState::Restored,
			CurrentStatus::TargetsRemain,
			true,
		),
		(
			TransactionState::AlreadyRestored,
			CurrentStatus::TargetsRemain,
			false,
		),
	] {
		let mut app = app(Language::English);
		finish_after_initial_drain(
			&mut app,
			vec![Event::Done(Ok(Completed::Transaction(poll_outcome(
				state, restart,
			))))],
			false,
		);
		app.poll();
		assert!(app.worker.is_none() && app.pending.is_none());
		assert!(!app.error && app.error_details.is_empty() && app.progress.is_empty());
		assert!(app.current_status == status);
		let outcome = app.outcome.as_ref().expect("late success must be retained");
		assert_eq!(outcome.state, state);
		assert_eq!(outcome.transaction_id, "poll-result");
		assert_eq!(outcome.restart_required, restart);
		assert_eq!(
			outcome.stores,
			[PathBuf::from("D:/isolated-ui-tests/cacerts")]
		);
		app.message = "already accepted".to_owned();
		app.poll();
		assert_eq!(app.message, "already accepted");
		assert!(app.pending.is_none() && app.outcome.is_some());
	}
}

//------------------------------------------------------------------------------
/**
 * Done欠落・実panic・成功通知後の実panicは、古い結果を残さず予期しない終了へ分類します。
 */
//------------------------------------------------------------------------------
#[test]
fn poll_rejects_finished_worker_without_done_or_with_panic() {
	// Done 欠落・実 panic・成功通知後の panic の組合せを、実際の poll で拒否させる
	for (sends_done, panics) in [(false, false), (false, true), (true, true)] {
		let mut app = app(Language::English);
		app.outcome = Some(poll_outcome(TransactionState::Applied, true));
		app.confirmation = Some(Confirmation::Deactivate);
		// Done のある条件だけ通知を用意し、通知欠落の条件と区別する
		let events = if sends_done {
			vec![Event::Done(Ok(Completed::Transaction(poll_outcome(
				TransactionState::Restored,
				true,
			))))]
		} else {
			Vec::new()
		};
		finish_after_initial_drain(&mut app, events, panics);
		app.poll();
		assert!(app.worker.is_none() && app.pending.is_none());
		assert!(app.error && app.outcome.is_none() && app.confirmation.is_none());
		assert!(app.current_status == CurrentStatus::Unavailable);
		assert!(app.error_details.contains("Success cannot be confirmed"));
	}
}

//------------------------------------------------------------------------------
/**
 * 遅着した失敗の分類を維持し、同じ競合窓でも古い自動確認世代だけは採用しません。
 */
//------------------------------------------------------------------------------
#[test]
fn poll_preserves_late_failure_and_rejects_stale_automatic_generation() {
	let mut app = app(Language::English);
	app.outcome = Some(poll_outcome(TransactionState::Applied, true));
	finish_after_initial_drain(
		&mut app,
		vec![Event::Done(Err(Failure::Process(
			trust_repair_windows::ProcessError::Cancelled,
		)))],
		false,
	);
	app.poll();
	assert!(app.worker.is_none() && app.pending.is_none() && app.outcome.is_none());
	assert!(!app.error && app.current_status == CurrentStatus::Unavailable);
	assert_eq!(app.message, "Cancelled. Nothing was changed.");
	assert!(!app.error_details.contains("Success cannot be confirmed"));

	// 同じ競合窓で、現在世代の採用と古い世代の拒否を両方検証する
	for stale in [false, true] {
		let mut app = self::app(Language::English);
		app.input_generation = 2;
		// 古い結果の条件だけ入力世代を進め、通知の到着順は同じに保つ
		app.automatic_generation = Some(if stale { 1 } else { 2 });
		app.current_status = CurrentStatus::TargetsRemain;
		app.message = "current selection".to_owned();
		finish_after_initial_drain(
			&mut app,
			vec![Event::Done(Err(Failure::Save(
				std::io::ErrorKind::PermissionDenied,
			)))],
			false,
		);
		app.poll();
		assert!(
			app.worker.is_none() && app.pending.is_none() && app.automatic_generation.is_none()
		);
		// 入力世代の一致に応じた期待状態を照合し、遅着失敗の混入を検出する
		if stale {
			assert!(!app.error && app.current_status == CurrentStatus::TargetsRemain);
			assert_eq!(app.message, "current selection");
			assert!(app.error_details.is_empty());
		} else {
			assert!(app.error && app.current_status == CurrentStatus::Unavailable);
			assert_eq!(app.message, Language::English.administrator_required());
		}
	}
}

//------------------------------------------------------------------------------
/**
 * Done受信後も生存workerを保持し、最新工程・中断要求・close待機を終了回収まで維持します。
 */
//------------------------------------------------------------------------------
#[test]
fn poll_keeps_live_worker_and_waits_to_close_until_reaped() {
	let mut app = app(Language::English);
	let (finish, wait) = mpsc::channel();
	let (sender, receiver) = mpsc::channel();
	let (ready, started) = mpsc::channel();
	let handle = thread::spawn(move || {
		// 中断可能な準備と確定後の検証で、工程通知と close 待機の契約を確認する
		for phase in [
			trust_repair_windows::TransactionPhase::Prepare,
			trust_repair_windows::TransactionPhase::Verify,
		] {
			assert!(
				sender
					.send(Event::Transaction(
						trust_repair_windows::TransactionProgress {
							phase,
							item: None,
							item_count: 1,
							cancellable: false,
						}
					))
					.is_ok()
			);
		}
		assert!(
			sender
				.send(Event::Done(Ok(Completed::Transaction(poll_outcome(
					TransactionState::Applied,
					true,
				)))))
				.is_ok()
		);
		ready.send(()).expect("test waits for queued notifications");
		wait.recv().expect("test allows worker to exit");
	});
	started.recv().expect("worker queued progress and Done");
	let cancellation = trust_repair_windows::Cancellation::default();
	app.worker = Some(Worker {
		cancellation: cancellation.clone(),
		receiver,
		handle,
	});
	app.closing = true;
	app.poll();
	assert!(app.worker.is_some() && app.pending.is_some() && app.outcome.is_none());
	assert!(!app.cancellable);
	assert_eq!(
		app.progress,
		Language::English.simple_phase(trust_repair_windows::TransactionPhase::Verify)
	);
	app.worker
		.as_ref()
		.expect("live worker retained")
		.cancellation
		.cancel();
	assert!(cancellation.is_cancelled());
	let context = egui::Context::default();
	app.handle_close(&context);
	assert!(!app.close_ready);
	finish.send(()).expect("worker waits for test");
	await_worker_finished(app.worker.as_ref().expect("worker still owned"));
	app.poll();
	app.handle_close(&context);
	assert!(app.worker.is_none() && app.pending.is_none() && app.close_ready);
	assert!(app.current_status == CurrentStatus::Disabled && app.outcome.is_some() && !app.error);
}

//------------------------------------------------------------------------------
/**
 * 言語の主番号と地域差、未知値を検証します。日本語以外は英語を要求します。
 */
//------------------------------------------------------------------------------
#[test]
fn selects_display_language_by_primary_langid() {
	assert!(Language::from_langid(0x0411) == Language::Japanese);
	assert!(Language::from_langid(0x0811) == Language::Japanese);
	// 未知値と日本語以外の地域を一通り確認し、英語 fallback を維持する
	for id in [0, 0x0409, 0x0809, 0x0407, 0x0804] {
		assert!(Language::from_langid(id) == Language::English);
	}
}

//------------------------------------------------------------------------------
/**
 * 入力秘密を結果保存へ含めず、入力変更で確認・再入力を破棄する契約を検証します。
 */
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
/**
 * 群全体成功後のNoTargetsだけを無効化済みとし、失敗・警告をその状態へ変換しません。
 */
//------------------------------------------------------------------------------
#[test]
fn distinguishes_no_targets_from_blocked_or_failed() {
	assert!(CurrentStatus::from_plan(&Err(PlanError::NoTargets)) == CurrentStatus::Disabled);
	// 全群の各失敗理由を、対象ゼロの診断成功と混同しないことを確認する
	for error in [
		PlanError::EmptySelection,
		PlanError::Blocked { report_index: 0 },
		PlanError::PolicyMismatch,
	] {
		assert!(CurrentStatus::from_plan(&Err(error)) == CurrentStatus::Unavailable);
	}
}

//------------------------------------------------------------------------------
/**
 * 古い入力世代の失敗は新しいfolderの表示を変更せず、空入力には自動jobを予約しません。
 */
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
/**
 * 自動確認のsnapshot後もcustom入力を保持し、続く無効化操作で同じ入力を一度だけ消費できます。
 */
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
/**
 * 読み取り/特権/保存の実権限不足は、日英の主画面と自動確認で管理者起動案内を維持します。
 */
//------------------------------------------------------------------------------
#[test]
fn displays_administrator_advice_without_confusing_unsupported_metadata() {
	// 日本語と英語の双方で、実権限不足の案内を検証する
	for language in [Language::Japanese, Language::English] {
		// 三つの実権限 code を同じ分類へ保ち、内容非対応の分類と区別する
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
/**
 * 別Javaを選択した時点で古い履歴/復元確認を捨て、表示・保存先も選択Java内へ切り替えます。
 */
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
/**
 * 未完了履歴を復旧入口へ優先し、worker 切断を成功や outcome にしないことを検証します。
 */
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
/**
 * 実際の egui widget に Tab/Space を渡し、マウスなしで標準値を明示選択できることを確認します。
 */
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
	// 実 widget へ Tab・Tab・Space を順に送り、keyboard だけで標準値を切り替える
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
