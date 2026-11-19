//------------------------------------------------------------------------------
/*!
 * - ファイル: tests.rs
 * - 概要: GUI の言語境界、秘密の非保存、未完了優先とキーボード入力を検証します
 * - バージョン: 01.03.02
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
 * Ver.01.01.00  Shunji Ogawa  2026/11/19  勧告通知の入力世代、診断失敗時の保持、定義更新を検証
 * Ver.01.01.01  Shunji Ogawa  2026/11/19  定義の差し替え前後で公式配布先を照合
 * Ver.01.02.00  Shunji Ogawa  2026/11/19  表の行をクリックしたときの CVE 詳細を検証
 * Ver.01.02.01  Shunji Ogawa  2026/11/19  最小ウィンドウでの詳細の横幅と日本語リンクを検証
 * Ver.01.02.02  Shunji Ogawa  2026/11/19  対応不要の CVE を除いた表と空表示を検証
 * Ver.01.02.03  Shunji Ogawa  2026/11/19  CVSS と修正版の並べ替えと選択行を検証
 * Ver.01.02.04  Shunji Ogawa  2026/11/19  初期表示が CVSS の降順であることを検証
 * Ver.01.03.00  Shunji Ogawa  2026/11/19  取得済み定義で選択中の Java を再照合する処理を検証
 * Ver.01.03.01  Shunji Ogawa  2026/11/19  配布元ごとの確認結果を含む通知形式に対応
 * Ver.01.03.02  Shunji Ogawa  2026/11/19  メモリ内の定義での再照合を検証
 * ```
 *
 * 備考:
 *
 * 明示した隔離試験では試験 EXE の隣に定義を書きます。Java は変更しません
 */
//------------------------------------------------------------------------------

use super::*;
use std::sync::mpsc;
use std::thread;
use trust_repair_windows::{ItemState, TransactionInspection};

//------------------------------------------------------------------------------
/**
 * ファイル操作を開始しない固定設定で GUI 状態を作ります。失敗なら試験を失敗させます
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
 * ファイルを変更せず、pollが保持すべき検証済み結果と再起動要否を作ります
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
 * 制御済みworkerが終了判定へ到達するまで待ちます。sleepを使わず、試験障害は5秒で失敗します
 *
 * # Arguments
 *
 * - `worker`: この試験が終了を制御する worker
 *
 * # Panics
 *
 * 5 秒以内に thread が終了判定へ到達しなければ試験を失敗させます
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
 * ストア診断が失敗しても現在の勧告を残し、旧フォルダの通知は表示しないことを検証します
 */
//------------------------------------------------------------------------------
#[test]
fn poll_keeps_advisories_only_for_the_current_selection() {
	// 同じ通知順で、入力世代が一致する場合だけ勧告が画面へ届くことを検証する
	for (generation, expected) in [(5, true), (4, false)] {
		let mut app = app(Language::Japanese);
		app.input_generation = 5;
		app.automatic_generation = Some(generation);
		let report = advisory::Report {
			vendor: "Test vendor".to_owned(),
			version: "21.0.1+2".to_owned(),
			product: None,
			download_page: None,
			status: advisory::Status::Unsupported,
			findings: Vec::new(),
			catalog_date: advisory::CATALOG_DATE.to_owned(),
		};
		finish_after_initial_drain(
			&mut app,
			vec![
				Event::Advisories(advisory_file::AdvisoryResult {
					report,
					source: advisory_file::Source::Embedded,
					selection: None,
					read_started_at: Instant::now(),
				}),
				Event::Done(Err(Failure::Process(
					trust_repair_windows::ProcessError::InvalidPassword,
				))),
			],
			false,
		);
		app.poll();
		assert_eq!(app.advisories.is_some(), expected);
		app.selected_cve = Some(1);
		app.schedule_check(Duration::ZERO);
		assert!(app.advisories.is_none());
		assert!(app.selected_cve.is_none());
	}
}

//------------------------------------------------------------------------------
/**
 * 対応不要の項目を除いて表示し、クリックした行に対応する詳細を開くことを検証します
 */
//------------------------------------------------------------------------------
#[test]
fn opens_clicked_cve_details_from_table() {
	let findings = (1000..1083).map(|number| advisory::Finding {
		cve: format!("CVE-2026-{number}"),
		cvss: match number {
			1001 => Some(39),
			1003 => Some(70),
			1005 => Some(91),
			1006 => Some(40),
			_ => None,
		}
		.map(|tenths| advisory::Cvss {
			version: "3.1",
			tenths,
		}),
		summary: advisory::Localized {
			ja: format!("概要 {number}"),
			en: format!("Summary {number}"),
		},
		condition: advisory::Localized {
			ja: format!("影響条件 {number}"),
			en: format!("Conditions {number}"),
		},
		details_url: "https://openjdk.org/groups/vulnerability/advisories/2026-11-17".to_owned(),
		status: match number {
			1000 => advisory::Status::Fixed,
			1002 => advisory::Status::NotAffected,
			1003 => advisory::Status::PotentiallyAffected,
			1004 => advisory::Status::UnknownVersion,
			_ => advisory::Status::AffectedVersion,
		},
		guidance: Some(advisory::Guidance {
			fixed_build: match number {
				1001 => Some("21.0.9+10"),
				1003 => Some("21.0.11+10"),
				1004 => None,
				_ => Some("21.0.13.1+2"),
			}
			.map(str::to_owned),
			updates_url: "https://github.com/adoptium/temurin/issues/326".to_owned(),
			workaround: None,
		}),
	});
	let mut result = advisory_file::AdvisoryResult {
		source: advisory_file::Source::Embedded,
		selection: None,
		read_started_at: Instant::now(),
		report: advisory::Report {
			vendor: "Eclipse Adoptium".to_owned(),
			version: "21.0.6+7".to_owned(),
			product: Some(advisory::Product::Temurin),
			download_page: Some("https://adoptium.net/temurin/releases/".to_owned()),
			status: advisory::Status::AffectedVersion,
			findings: findings.collect(),
			catalog_date: advisory::CATALOG_DATE.to_owned(),
		},
	};
	let context = egui::Context::default();
	ui_style::configure(&context);
	let draw = |result: &advisory_file::AdvisoryResult, selected: &mut Option<usize>, events| {
		let mut output = context.run_ui(
			egui::RawInput {
				screen_rect: Some(egui::Rect::from_min_size(
					egui::Pos2::ZERO,
					egui::vec2(640.0, 360.0),
				)),
				events,
				..Default::default()
			},
			|ui| {
				advisory_view::draw(
					ui,
					Language::Japanese,
					Some(result),
					&StartupUpdate::Idle,
					false,
					selected,
				)
			},
		);
		output.textures_delta.clear();
		output
	};
	let text_position = |output: &egui::FullOutput, label: &str| {
		output.shapes.iter().find_map(|shape| {
			if let egui::epaint::Shape::Text(text) = &shape.shape
				&& text.galley.text() == label
				&& text.galley.rows.len() == 1
				&& shape.clip_rect.contains(text.pos + egui::vec2(2.0, 6.0))
			{
				Some(text.pos + egui::vec2(2.0, 6.0))
			} else {
				None
			}
		})
	};
	let click = |result: &advisory_file::AdvisoryResult, selected: &mut Option<usize>, pos| {
		for pressed in [true, false] {
			draw(
				result,
				selected,
				vec![
					egui::Event::PointerMoved(pos),
					egui::Event::PointerButton {
						pos,
						button: egui::PointerButton::Primary,
						pressed,
						modifiers: egui::Modifiers::NONE,
					},
				],
			);
		}
		draw(result, selected, vec![])
	};
	let mut selected = None;
	let initial = draw(&result, &mut selected, vec![]);
	assert!(text_position(&initial, "修正版").is_some());
	assert!(text_position(&initial, "CVSS 深刻度 ↓").is_some());
	let critical = text_position(&initial, "緊急 9.1").expect("critical score is visible");
	let high = text_position(&initial, "高 7.0").expect("high score is visible");
	let medium = text_position(&initial, "中 4.0").expect("medium score is visible");
	let low = text_position(&initial, "低 3.9").expect("low score is visible");
	let unscored = text_position(&initial, "CVE-2026-1004").expect("unscored CVE follows scores");
	assert!(critical.y < high.y && high.y < medium.y && medium.y < low.y && low.y < unscored.y);
	assert!(text_position(&initial, "表示 81 件（対象バージョン 79 件、要確認 2 件）").is_some());
	assert!(text_position(&initial, "CVE-2026-1000").is_none());
	assert!(text_position(&initial, "CVE-2026-1002").is_none());
	assert!(text_position(&initial, "CVE-2026-1003").is_some());
	assert!(text_position(&initial, "CVE-2026-1004").is_some());
	assert!(text_position(&initial, "影響条件 1001").is_none());
	let pos = text_position(&initial, "概要 1001").expect("affected CVE is visible");
	let detail = click(&result, &mut selected, pos);
	assert_eq!(selected, Some(1));
	let condition =
		text_position(&detail, "影響条件 1001").expect("selected conditions are visible");
	assert!(text_position(&detail, "影響条件 1000").is_none());
	assert!(text_position(&detail, "公式勧告").is_some());
	let updates = text_position(&detail, "更新情報").expect("update link fits on one line");
	let download = text_position(&detail, "ダウンロード").expect("download link fits on one line");
	assert_eq!(updates.y, download.y);
	let close = text_position(&detail, "閉じる").expect("close button is visible");
	assert!(
		close.x - condition.x > 530.0,
		"dialog uses the available width"
	);
	let escape = [true, false].map(|pressed| egui::Event::Key {
		key: egui::Key::Escape,
		physical_key: None,
		pressed,
		repeat: false,
		modifiers: egui::Modifiers::NONE,
	});
	draw(&result, &mut selected, escape.to_vec());
	assert!(selected.is_none());
	assert!(text_position(&initial, "CVE-2026-1082").is_none());
	draw(
		&result,
		&mut selected,
		vec![egui::Event::MouseWheel {
			unit: egui::MouseWheelUnit::Point,
			delta: egui::vec2(0.0, -3000.0),
			phase: egui::TouchPhase::Move,
			source: egui::MouseWheelSource::Unknown,
			modifiers: egui::Modifiers::NONE,
		}],
	);
	let last = (0..20)
		.find_map(|_| {
			let output = draw(&result, &mut selected, vec![]);
			text_position(&output, "CVE-2026-1082").map(|_| output)
		})
		.expect("last CVE is reachable by scrolling");
	assert_eq!(
		text_position(&last, "修正版"),
		text_position(&initial, "修正版")
	);
	let cvss_header = text_position(&last, "CVSS 深刻度 ↓").expect("CVSS header is visible");
	let ascending = click(&result, &mut selected, cvss_header);
	assert!(text_position(&ascending, "CVSS 深刻度 ↑").is_some());
	assert!(
		text_position(&ascending, "低 3.9").unwrap().y
			< text_position(&ascending, "緊急 9.1").unwrap().y
	);
	assert!(
		text_position(&ascending, "緊急 9.1").unwrap().y
			< text_position(&ascending, "CVE-2026-1004").unwrap().y
	);
	let descending = click(&result, &mut selected, cvss_header);
	assert!(text_position(&descending, "CVSS 深刻度 ↓").is_some());
	assert_eq!(text_position(&descending, "緊急 9.1"), Some(critical));
	let detail = click(&result, &mut selected, critical);
	assert_eq!(selected, Some(5));
	assert!(text_position(&detail, "CVSS 3.1  緊急 9.1").is_some());
	draw(&result, &mut selected, escape.into());
	assert!(selected.is_none());
	let reopened_table = draw(&result, &mut selected, vec![]);
	let fixed_header =
		text_position(&reopened_table, "修正版").expect("fixed-build header is visible");
	let by_build = click(&result, &mut selected, fixed_header);
	assert!(text_position(&by_build, "修正版 ↑").is_some());
	assert!(
		text_position(&by_build, "21.0.9+10").unwrap().y
			< text_position(&by_build, "21.0.11+10").unwrap().y
	);
	let mut sorted = by_build;
	for (header, sorted_header) in [("CVE", "CVE ↑"), ("概要", "概要 ↑"), ("判定", "判定 ↓")]
	{
		let position = text_position(&sorted, header).expect("sortable header is visible");
		sorted = click(&result, &mut selected, position);
		assert!(text_position(&sorted, sorted_header).is_some());
	}
	result.report.status = advisory::Status::Fixed;
	result.report.findings.retain(|finding| {
		matches!(
			finding.status,
			advisory::Status::Fixed | advisory::Status::NotAffected
		)
	});
	let empty = draw(&result, &mut selected, vec![]);
	assert!(
		text_position(
			&empty,
			"収録済みの勧告に、対応または確認が必要な項目はありません。"
		)
		.is_some()
	);
	assert!(text_position(&empty, "CVE").is_none());
}

//------------------------------------------------------------------------------
/**
 * 隔離済みの実 Java と GUI の worker を使い、定義差し替え後の再照合を検証します
 *
 * # Notes
 *
 * 実行する試験 EXE は専用の空フォルダへコピーします。合成 CVE は試験定義だけに記載します
 */
//------------------------------------------------------------------------------
#[test]
#[ignore = "試験EXEをartifacts/java-advisories-previewの空フォルダへコピーして実行"]
fn reads_updated_catalog_on_the_next_java_selection() {
	let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
		.join("../..")
		.canonicalize()
		.expect("workspace");
	let qa_root = workspace
		.join("artifacts/java-advisories-preview")
		.canonicalize()
		.expect("isolated QA area");
	let exe = std::env::current_exe().expect("test executable");
	assert!(
		exe.canonicalize()
			.expect("test executable path")
			.starts_with(qa_root)
	);
	let definition = exe.with_file_name(advisory_file::FILE_NAME);
	assert!(!definition.exists(), "empty folder for this test");
	let fixture = workspace.join("artifacts/diagnostics/integration/Java 21 読取 診断");
	assert!(
		fixture.join("bin/java.exe").is_file(),
		"isolated Temurin fixture"
	);

	let mut app = app(Language::Japanese);
	app.root_text = fixture.display().to_string();
	app.builtin[0].standard = false;
	let context = egui::Context::default();
	let read = |app: &mut TrustRepairApp| {
		app.schedule_check(Duration::ZERO);
		app.pump_auto_check(&context);
		let deadline = Instant::now() + Duration::from_secs(20);
		// 子の終了は本番と同じ poll に任せ、試験の異常時も所有 worker を回収する
		while app.worker.is_some() && Instant::now() < deadline {
			app.poll();
			thread::sleep(Duration::from_millis(10));
		}
		// 実行が終わらない場合は、試験の中断要求で所有する子だけを終了させる
		if let Some(worker) = app.worker.take() {
			worker.cancellation.cancel();
			worker.handle.join().expect("cancelled worker returns");
			panic!("advisory worker did not finish");
		}
		assert!(matches!(app.current_status, CurrentStatus::Unavailable));
	};
	read(&mut app);
	let initial = app
		.advisories
		.as_ref()
		.expect("version despite invalid store credentials");
	assert_eq!(initial.source, advisory_file::Source::Embedded);
	assert_eq!(initial.report.findings[0].cve, "CVE-2026-114938");
	assert!(
		initial.report.version.contains('+'),
		"verified runtime build"
	);
	let download_page =
		"https://adoptium.net/temurin/releases/?arch=x64&mode=filter&os=windows&version=21";
	assert_eq!(initial.report.download_page.as_deref(), Some(download_page));

	let catalog = include_str!("../../../data/java-advisories.json")
		.replace(advisory::CATALOG_DATE, "2026-11-20")
		.replace("CVE-2026-114938", "CVE-2099-0001");
	let (sender, receiver) = mpsc::channel();
	let prefetched = advisory::Catalog::from_json(&catalog).expect("validated startup download");
	sender
		.send(Ok(((prefetched, false), Some(Instant::now()))))
		.unwrap();
	let mut update = StartupUpdate::Checking(receiver);
	assert!(update.poll(&context));
	let selected = app.advisories.as_mut().expect("already selected Java");
	assert!(update.apply_to(selected));
	assert_eq!(selected.source, advisory_file::Source::Downloaded);
	assert_eq!(selected.report.findings[0].cve, "CVE-2099-0001");
	assert_eq!(
		selected.report.download_page.as_deref(),
		Some(download_page)
	);
	let memory_only = StartupUpdate::Ready {
		catalog: advisory::Catalog::from_json(&catalog).unwrap(),
		stored_at: None,
		incomplete: false,
	};
	read(&mut app);
	let selected = app
		.advisories
		.as_mut()
		.expect("version selected after startup");
	assert!(!update.apply_to(selected));
	assert!(memory_only.apply_to(selected));
	assert_eq!(selected.report.findings[0].cve, "CVE-2099-0001");
	std::fs::write(&definition, catalog).expect("isolated revised catalog");
	read(&mut app);
	let updated = app.advisories.as_ref().expect("reloaded result");
	assert_eq!(updated.source, advisory_file::Source::External);
	assert_eq!(updated.report.catalog_date, "2026-11-20");
	assert_eq!(updated.report.findings[0].cve, "CVE-2099-0001");
	assert_eq!(updated.report.download_page.as_deref(), Some(download_page));

	std::fs::write(&definition, b"{invalid json").expect("isolated malformed catalog");
	read(&mut app);
	let fallback = app.advisories.as_ref().expect("fallback result");
	assert_eq!(fallback.source, advisory_file::Source::Fallback);
	assert_eq!(fallback.report.findings[0].cve, "CVE-2026-114938");
}

//------------------------------------------------------------------------------
/**
 * pollの初回受信を必ずEmptyにし、その直後だけ通知送信・thread終了を許可します。
 * 実際のpollを呼ぶ試験専用で、panic指定時も所有threadはpollで回収します
 *
 * # Arguments
 *
 * - `app`: 初回 drain 後の一回限りの同期点を設定する試験画面
 * - `events`: 同期点の受理後に送る順序付き通知
 * - `panics`: `true` は通知後に制御 thread を panic させます
 *
 * # Notes
 *
 * UI 側の初回 Empty を確認するまで通知を保留し、実際の poll の競合窓を固定します
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
 * 初回Empty→Done送信→thread終了の順でも、検証済み状態・再起動要否を一度だけ採用します
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
 * Done欠落・実panic・成功通知後の実panicは、古い結果を残さず予期しない終了へ分類します
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
 * 遅着した失敗の分類を維持し、同じ競合窓でも古い自動確認世代だけは採用しません
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
 * Done受信後も生存workerを保持し、最新工程・中断要求・close待機を終了回収まで維持します
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
 * 言語の主番号と地域差、未知値を検証します。日本語以外は英語を要求します
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
 * 入力秘密を結果保存へ含めず、入力変更で確認・再入力を破棄する契約を検証します
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
 * 群全体成功後のNoTargetsだけを無効化済みとし、失敗・警告をその状態へ変換しません
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
 * 古い入力世代の失敗は新しいfolderの表示を変更せず、空入力には自動jobを予約しません
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
 * 自動確認のsnapshot後もcustom入力を保持し、続く無効化操作で同じ入力を一度だけ消費できます
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
 * 読み取り/特権/保存の実権限不足は、日英の主画面と自動確認で管理者起動案内を維持します
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
 * 別Javaを選択した時点で古い履歴/復元確認を捨て、表示・保存先も選択Java内へ切り替えます
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
 * 未完了履歴を復旧入口へ優先し、worker 切断を成功や outcome にしないことを検証します
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
 * 実際の egui widget に Tab/Space を渡し、マウスなしで標準値を明示選択できることを確認します
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
