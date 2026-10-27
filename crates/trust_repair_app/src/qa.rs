//------------------------------------------------------------------------------
/*!
 * - ファイル: qa.rs
 * - 概要: 明示 feature と引数でだけ有効な native 描画・隔離 fixture の縦経路 QA です
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
 * 通常起動では動作しません。既存 GUI 証拠と内部 QA の新規コピーを分離します
 */
//------------------------------------------------------------------------------

use crate::{
	Command, Confirmation, CurrentStatus, Language, PasswordInput, StoreInput, TrustRepairApp,
};
use eframe::egui;
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};
use trust_repair_core::PlanError;
use trust_repair_windows::{TransactionOptions, TransactionState};

/// 明示引数だけで有効な自アプリQAです。通常起動・実Javaを対象にしません
pub struct Preview {
	/// 選択時の自動確認を検証するか
	auto_status: bool,
	/// 読み取りだけで終了し、変更/backup不在を外から照合するか
	readonly: bool,
	/// 存在しないfolderを選択するか
	invalid_folder: bool,
	/// 自動確認中に新しい入力世代へ切り替えるか
	switch_folder: bool,
	/// 日英描画の明示override
	language: Language,
	/// 空の簡素画面だけを描画するか
	preview_only: bool,
	/// 中断経路を確認するか
	cancel: bool,
	/// 自分のQA windowへのcloseを確認するか
	close: bool,
	/// 不正passwordの拒否経路を確認するか
	failure: bool,
	/// 所有fixtureへの実作成denyで、主画面の管理者起動案内を確認するか
	permission: bool,
	/// 完了通知なしのchannel切断を確認するか
	disconnect: bool,
	/// 必ずartifacts/settings-layout内の新規fixtureです
	root: PathBuf,
	/// 逐次actionの位置
	stage: usize,
	/// 次のactionまで描画する時刻
	after: Instant,
	/// screenshot保存結果
	capture: Option<Receiver<Result<(), String>>>,
	/// 実際の工程・回収結果
	log: Vec<String>,
	/// 所有workerの進捗表示を一度だけ撮ったか
	progress_captured: bool,
}
impl Preview {
	//------------------------------------------------------------------------------
	/**
	 * 既知QA引数一つだけを受け入れます。空引数は通常OS言語のまま起動します
	 *
	 * # Returns
	 *
	 * 引数なしなら `None`、既知の明示引数一つなら対応する QA 状態
	 *
	 * # Errors
	 *
	 * 引数の件数または内容が既知一覧に一致しない場合に InvalidInput
	 */
	//------------------------------------------------------------------------------
	pub fn from_arguments(arguments: &[OsString]) -> Result<Option<Self>, std::io::Error> {
		// 引数のない通常起動では、QA 状態を生成しない
		if arguments.is_empty() {
			return Ok(None);
		}
		let value = arguments
			.first()
			.and_then(|value| value.to_str())
			.unwrap_or("");
		// 既知の明示引数一つだけを許可し、未知の試験操作を開始しない
		if arguments.len() != 1
			|| ![
				"--preview-simple-ja",
				"--preview-simple-en",
				"--qa-simple-ja",
				"--qa-simple-en",
				"--qa-simple-cancel",
				"--qa-simple-close",
				"--qa-simple-failure",
				"--qa-simple-permission-ja",
				"--qa-simple-permission-en",
				"--qa-simple-disconnect",
				"--qa-auto-ja",
				"--qa-auto-en",
				"--qa-auto-readonly-ja",
				"--qa-auto-readonly-en",
				"--qa-auto-failure",
				"--qa-auto-invalid",
				"--qa-auto-switch",
			]
			.contains(&value)
		{
			return Err(std::io::Error::new(
				std::io::ErrorKind::InvalidInput,
				"Unknown explicit QA arguments",
			));
		}
		// 明示引数から表示試験の言語を選び、OS の設定自体は変更しない
		let language = if value.ends_with("en") {
			Language::English
		} else {
			Language::Japanese
		};
		let preview_only = value.starts_with("--preview");
		let auto_status = value.starts_with("--qa-auto-");
		let folder = value
			.trim_start_matches("--preview-simple-")
			.trim_start_matches("--qa-simple-")
			.trim_start_matches("--qa-auto-");
		// 描画だけの preview と動作 QA で、専用記録先の名前を分ける
		let folder = if preview_only {
			format!("preview-{folder}")
		} else {
			folder.to_owned()
		};
		Ok(Some(Self {
			auto_status,
			readonly: value.contains("readonly"),
			invalid_folder: value.ends_with("invalid"),
			switch_folder: value.ends_with("switch"),
			language,
			preview_only,
			cancel: value.ends_with("cancel"),
			close: value.ends_with("close"),
			failure: value.ends_with("failure"),
			permission: value.contains("permission"),
			disconnect: value.ends_with("disconnect"),
			root: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
				// 自動状態確認と通常操作の QA を、それぞれの専用領域へ限定する
				.join(if auto_status {
					"../../artifacts/settings-layout/gui-auto-status"
				} else {
					"../../artifacts/settings-layout/gui-simple"
				})
				.join(folder),
			stage: 0,
			after: Instant::now() + Duration::from_millis(700),
			capture: None,
			log: Vec::new(),
			progress_captured: false,
		}))
	}

	//------------------------------------------------------------------------------
	/**
	 * 初期画面と処理後のQAで、設定を閉じた処理結果のnative描画を確認します
	 */
	//------------------------------------------------------------------------------
	pub(super) fn shows_results(&self) -> bool {
		(self.preview_only && matches!(self.stage, 100 | 101))
			|| (!self.preview_only && matches!(self.stage, 90 | 91))
	}

	//------------------------------------------------------------------------------
	/**
	 * 結果確認の後でだけ特殊設定を開き、有効な入力欄を描画します
	 */
	//------------------------------------------------------------------------------
	pub(super) fn shows_settings(&self) -> bool {
		self.preview_only && matches!(self.stage, 102..=105)
	}

	//------------------------------------------------------------------------------
	/**
	 * 自アプリの実描画だけをPNGへ保存します。独立threadの完了をchannelで受け取ります
	 *
	 * # Arguments
	 *
	 * - `context`: このアプリの描画画像を要求する context
	 * - `name`: QA root 内の PNG ファイル名の基部
	 *
	 * # Notes
	 *
	 * 画像保存 thread の結果を channel に保持し、後続 qa_tick が完了を確認します。
	 * この関数自体は保存完了を待たず、保存の成否も同期的には返しません
	 */
	//------------------------------------------------------------------------------
	fn screenshot(&mut self, context: &egui::Context, name: &str) {
		let path = self.root.join(format!("{name}.png"));
		let (sender, receiver) = mpsc::channel();
		self.capture = Some(receiver);
		context.request_screenshot(move |image| {
			std::thread::spawn(move || {
				let bytes: Vec<u8> = image
					.pixels
					.iter()
					.flat_map(|pixel| pixel.to_array())
					.collect();
				let result = image::save_buffer_with_format(
					path,
					&bytes,
					image.width() as u32,
					image.height() as u32,
					image::ColorType::Rgba8,
					image::ImageFormat::Png,
				)
				.map_err(|error| error.to_string());
				let _closed = sender.send(result);
			});
		});
	}

	//------------------------------------------------------------------------------
	/**
	 * 実callbackの中断可否を証跡へ記録します。状態判定に自由文は使いません
	 */
	//------------------------------------------------------------------------------
	pub(super) fn progress(&mut self, value: trust_repair_windows::TransactionProgress) {
		self.log.push(format!(
			"{:?}: cancellable={}",
			value.phase, value.cancellable
		));
	}
}

//------------------------------------------------------------------------------
/**
 * 明示QAだけを新規領域へ向けます。通常の既存candidateやuser windowにアクセスしません
 *
 * # Arguments
 *
 * - `app`: QA 設定を反映して返す、まだ I/O を始めていない画面状態
 * - `preview`: 明示 QA がなければ `None`
 * - `font_source`: 実採用した font の出所。QA の log へだけ記録します
 *
 * # Returns
 *
 * 通常状態、または専用 fixture と採用言語を設定した画面状態
 *
 * # Errors
 *
 * QA root の作成・正規化、保存先設定、または必要な fixture 不足
 */
//------------------------------------------------------------------------------
pub fn configure(
	mut app: TrustRepairApp,
	preview: Option<Preview>,
	font_source: String,
) -> Result<TrustRepairApp, Box<dyn std::error::Error + Send + Sync>> {
	// 明示 QA がなければ、通常の画面状態をそのまま返す
	let Some(mut preview) = preview else {
		return Ok(app);
	};
	std::fs::create_dir_all(&preview.root)?;
	preview.root = std::fs::canonicalize(&preview.root)?;
	preview.log.push(format!("runtime UI font: {font_source}"));
	app.language = preview.language;
	app.legacy_options = TransactionOptions::with_backup_root(preview.root.join("legacy-backups"))?;
	// 変更を伴う QA だけに fixture 入力を設定し、preview と切断試験を分ける
	if !preview.preview_only && !preview.disconnect {
		let java = preview.root.join("Java");
		// 必要な隔離 Java が準備されていない場合は、実環境へ fallback せず失敗させる
		if !java.join("bin/java.exe").is_file() {
			return Err("Prepare new gui-simple fixture first".into());
		}
		app.root_text = java.display().to_string();
		// 両形式の custom を明示入力へ加え、標準ストア以外も同じ操作で検証する
		for name in ["custom.jks", "custom.p12"] {
			app.custom.push(StoreInput {
				path: preview.root.join(name),
				password: PasswordInput {
					value: zeroize::Zeroizing::new(String::new()),
					standard: true,
				},
			});
		}
		// 認証失敗試験だけに非秘密の誤入力を設定する
		if preview.failure {
			app.custom[0].password.standard = false;
			*app.custom[0].password.value = "deliberately-wrong-test-password".to_owned();
		}
		// 自動確認では custom 入力を保持する契約も検証するため、手入力 mode を使う
		if preview.auto_status && !preview.failure {
			app.custom[0].password.standard = false;
			*app.custom[0].password.value = "changeit".to_owned();
		}
		// 不正フォルダ試験だけで、所有領域の存在しない Java を選択する
		if preview.invalid_folder {
			app.root_text = preview.root.join("missing-Java").display().to_string();
		}
		// 自動状態確認の QA だけを即時予約し、通常操作とは開始契機を分ける
		if preview.auto_status {
			app.invalidate();
			app.auto_due = Some(Instant::now());
		}
	}
	app.qa = Some(preview);
	Ok(app)
}
impl TrustRepairApp {
	//------------------------------------------------------------------------------
	/**
	 * 自分の新規fixtureだけで通常の選択・自動Scan・無効化・復元actionを検証します
	 */
	//------------------------------------------------------------------------------
	fn qa_auto_step(&mut self, qa: &mut Preview, context: &egui::Context) {
		let idle = self.worker.is_none();
		// 所有する QA の段階と worker の完了を基準に、検証・撮影・次操作を順に進める
		match qa.stage {
			0 if qa.switch_folder && self.automatic_generation.is_some() => {
				self.root_text = qa.root.join("new-missing-Java").display().to_string();
				self.invalidate();
				self.auto_due = Some(Instant::now());
				qa.log
					.push("folder changed while old automatic worker was running".to_owned());
				qa.stage = 1;
			}
			0 | 1 if idle && self.auto_due.is_none() => {
				// 認証失敗・存在しない入力・切替後の古い世代を、無効化済みと表示しないことを確認する
				if qa.failure || qa.invalid_folder || qa.switch_folder {
					assert!(self.current_status == CurrentStatus::Unavailable);
					assert!(self.outcome.is_none());
					qa.log
						.push("unavailable; no disabled claim; no transaction".to_owned());
					qa.screenshot(context, "unavailable");
					qa.stage = 90;
				} else {
					assert!(self.current_status == CurrentStatus::TargetsRemain);
					assert!(self.custom[0].password.value.as_str() == "changeit");
					assert!(!self.selected_backup_root().exists());
					assert!(!self.legacy_options.backup_root().exists());
					qa.log.push(
						"automatic selection: targets remain; custom password retained; no backup"
							.to_owned(),
					);
					qa.screenshot(context, "targets-remain");
					// 読み取りだけの試験ではここで完了し、変更試験だけ次の適用へ進める
					qa.stage = if qa.readonly { 90 } else { 2 };
				}
			}
			2 if idle => {
				self.execute_confirmed(Confirmation::Deactivate, context);
				qa.stage = 3;
			}
			3 if idle => {
				assert!(
					self.current_status == CurrentStatus::Disabled
						&& self
							.outcome
							.as_ref()
							.is_some_and(|value| value.state == TransactionState::Applied)
				);
				qa.log.push(
					"after disable: disabled, backed by complete backend verification".to_owned(),
				);
				qa.screenshot(context, "disabled");
				qa.stage = 4;
			}
			4 if idle => {
				*self.custom[0].password.value = "changeit".to_owned();
				self.invalidate();
				self.auto_due = Some(Instant::now());
				qa.stage = 5;
			}
			5 if idle && self.auto_due.is_none() => {
				assert!(
					self.current_status == CurrentStatus::Disabled
						&& self.custom[0].password.value.as_str() == "changeit"
				);
				qa.log.push(
					"automatic rescan of target-free stores: disabled; password retained"
						.to_owned(),
				);
				qa.screenshot(context, "no-targets");
				qa.stage = 6;
			}
			6 if idle => {
				self.execute_confirmed(Confirmation::Deactivate, context);
				qa.stage = 16;
			}
			16 if idle => {
				assert!(
					self.current_status == CurrentStatus::Disabled
						&& self.outcome.is_none()
						&& self
							.diagnosis
							.as_ref()
							.is_some_and(|value| matches!(value.plan, Err(PlanError::NoTargets)))
				);
				qa.log
					.push("target-free disable: no changes; disabled status preserved".to_owned());
				*self.custom[0].password.value = "changeit".to_owned();
				self.invalidate();
				self.prepare_restore(context);
				qa.stage = 7;
			}
			7 if idle => {
				let confirmation = self.confirmation.take().expect("restore confirmation");
				self.execute_confirmed(confirmation, context);
				qa.stage = 8;
			}
			8 if idle => {
				assert!(
					self.current_status == CurrentStatus::TargetsRemain
						&& self
							.outcome
							.as_ref()
							.is_some_and(|value| value.state == TransactionState::Restored)
				);
				qa.log.push(
					"after restore: targets remain; original bytes/inventory/metadata verified"
						.to_owned(),
				);
				qa.screenshot(context, "restored");
				qa.stage = 90;
			}
			90 if idle => {
				qa.log.push("auto-status QA complete".to_owned());
				qa.stage = 91;
			}
			91 | 99 if idle => {
				context.send_viewport_cmd(egui::ViewportCommand::Close);
			}
			_ => {}
		}
	}

	//------------------------------------------------------------------------------
	/**
	 * 通常と同じ確認後action・復元ボタンを逐次呼びます。自動確認は明示QAに限ります
	 */
	//------------------------------------------------------------------------------
	pub(super) fn qa_tick(&mut self, context: &egui::Context) {
		// 明示 QA の状態がないフレームでは、試験操作を行わない
		let Some(mut qa) = self.qa.take() else {
			return;
		};
		context.request_repaint_after(Duration::from_millis(80));
		// 画像保存の結果が届くまでは状態を保持し、同じ画像要求を重ねない
		if let Some(receiver) = &qa.capture {
			// 保存成功・失敗・未完了を分け、失敗時は証跡を残して終了段階へ進む
			match receiver.try_recv() {
				Ok(Ok(())) => qa.capture = None,
				Ok(Err(error)) => {
					qa.log.push(error);
					qa.stage = 99;
					qa.capture = None;
				}
				Err(_) => {
					self.qa = Some(qa);
					return;
				}
			}
		}
		// 段階間の期限までは状態を戻し、UI thread を待機させない
		if Instant::now() < qa.after {
			self.qa = Some(qa);
			return;
		}
		let idle = self.worker.is_none();
		// 自動状態確認の QA は専用の状態機械へ渡し、通常操作の段階と混在させない
		if qa.auto_status {
			self.qa_auto_step(&mut qa, context);
			qa.after = Instant::now() + Duration::from_millis(250);
			self.qa = Some(qa);
			return;
		}
		// 実行中の進捗は一度だけ撮影し、worker の完了前後を取り違えない
		if qa.stage == 3 && !idle && !qa.progress_captured {
			qa.progress_captured = true;
			qa.screenshot(context, "progress");
			self.qa = Some(qa);
			return;
		}
		// 通常と同じ確認・適用・復元の順序を、明示した試験条件で進める
		match qa.stage {
			0 if idle => {
				// preview は描画、切断試験は通知欠落、通常 QA は確認画面から開始する
				if qa.preview_only {
					qa.screenshot(context, "initial");
					qa.stage = 92;
				}
				// 切断 QA では Done のない終了を再現し、通常操作の確認へ進めない
				else if qa.disconnect {
					self.launch(Command::QaDisconnect, context);
					qa.stage = 81;
				} else {
					self.confirmation = Some(Confirmation::Deactivate);
					qa.stage = 1;
				}
			}
			1 => {
				qa.screenshot(context, "disable-confirmation");
				qa.stage = 10;
			}
			10 => {
				context.set_zoom_factor(1.5);
				qa.stage = 11;
			}
			11 => {
				qa.screenshot(context, "disable-confirmation-150");
				qa.stage = 12;
			}
			12 => {
				context.set_zoom_factor(1.0);
				qa.stage = 2;
			}
			2 if idle => {
				self.confirmation = None;
				self.execute_confirmed(Confirmation::Deactivate, context);
				let id = self
					.worker
					.as_ref()
					.map(|worker| worker.handle.thread().id());
				self.launch(
					Command::History {
						root: self.selected_root(),
					},
					context,
				);
				assert_eq!(
					id,
					self.worker
						.as_ref()
						.map(|worker| worker.handle.thread().id())
				);
				qa.log.push("busy duplicate suppressed".to_owned());
				qa.stage = 3;
			}
			3 if (qa.cancel || qa.close) && !idle => {
				// close 試験は通常の close 要求、中断試験は所有 worker の cancel で再現する
				if qa.close {
					context.send_viewport_cmd(egui::ViewportCommand::Close);
				}
				// close 試験以外では所有 worker に中断を要求し、通常の安全な回収を検証する
				else if let Some(worker) = &self.worker {
					worker.cancellation.cancel();
				}
				qa.stage = 80;
			}
			80 if idle => {
				assert!(self.outcome.is_none());
				qa.log.push("cancel returned without an outcome".to_owned());
				qa.screenshot(context, "cancelled");
				qa.stage = 90;
			}
			81 if idle => {
				assert!(self.error && self.outcome.is_none());
				qa.log
					.push("worker disconnect rejected as success".to_owned());
				qa.screenshot(context, "interrupted");
				qa.stage = 90;
			}
			3 if idle && qa.failure => {
				assert!(self.error && self.outcome.is_none());
				qa.log.push("bad password: blocked; no outcome".to_owned());
				qa.screenshot(context, "failure");
				qa.stage = 90;
			}
			3 if idle && qa.permission => {
				assert!(self.error && self.outcome.is_none());
				assert_eq!(self.message, self.language.administrator_required());
				assert!(!self.selected_backup_root().exists());
				assert!(!self.legacy_options.backup_root().exists());
				qa.log.push(format!(
					"permission denied; administrator advice on main screen: {}",
					self.message
				));
				qa.screenshot(context, "permission-denied");
				qa.stage = 90;
			}
			3 if idle => {
				assert!(
					self.outcome
						.as_ref()
						.is_some_and(|value| value.state == TransactionState::Applied),
					"{}",
					self.error_details
				);
				assert_eq!(
					self.outcome
						.as_ref()
						.expect("applied")
						.backup_directory
						.parent(),
					Some(self.selected_backup_root().as_path())
				);
				assert!(!self.legacy_options.backup_root().exists());
				qa.log.push(
					"one disable action: Applied; all inventory/metadata verified".to_owned(),
				);
				qa.screenshot(context, "disabled");
				qa.stage = 4;
			}
			4 if idle => {
				self.execute_confirmed(Confirmation::Deactivate, context);
				qa.stage = 5;
			}
			5 if idle => {
				assert!(
					self.diagnosis
						.as_ref()
						.is_some_and(|value| matches!(value.plan, Err(PlanError::NoTargets)))
				);
				assert!(self.outcome.is_none() && !self.error);
				qa.log
					.push("repeat disable: no targets; no transaction created".to_owned());
				qa.screenshot(context, "no-change");
				qa.stage = 6;
			}
			6 if idle => {
				self.prepare_restore(context);
				qa.stage = 7;
			}
			7 if idle => {
				assert!(matches!(self.confirmation, Some(Confirmation::Restore(_))));
				qa.screenshot(context, "restore-confirmation");
				qa.stage = 8;
			}
			8 if idle => {
				let confirmation = self.confirmation.take().expect("one restore confirmation");
				self.execute_confirmed(confirmation, context);
				qa.stage = 9;
			}
			9 if idle => {
				assert!(
					self.outcome
						.as_ref()
						.is_some_and(|value| value.state == TransactionState::Restored)
				);
				qa.log.push(
					"restore button: Restored; original byte/inventory/metadata verified"
						.to_owned(),
				);
				qa.screenshot(context, "restored");
				qa.stage = 90;
			}
			92 if idle => {
				context.set_zoom_factor(1.5);
				qa.stage = 93;
			}
			93 if idle => {
				qa.screenshot(context, "initial-150");
				qa.stage = 94;
			}
			94 if idle => {
				context.set_zoom_factor(1.0);
				qa.stage = 95;
			}
			95 if idle => {
				context
					.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(640.0, 360.0)));
				qa.stage = 96;
			}
			96 if idle => {
				qa.screenshot(context, "initial-minimum");
				qa.stage = 97;
			}
			97 if idle => {
				context
					.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(720.0, 400.0)));
				qa.stage = 100;
			}
			100 if idle => {
				qa.screenshot(context, "results");
				qa.stage = 101;
			}
			101 if idle => {
				context
					.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(720.0, 560.0)));
				qa.stage = 102;
			}
			102 if idle => {
				qa.screenshot(context, "settings");
				qa.stage = 103;
			}
			103 if idle => {
				self.builtin[0].standard = false;
				*self.builtin[0].value = "qa-only-input".to_owned();
				qa.stage = 104;
			}
			104 if idle => {
				assert!(!self.builtin[0].standard && !self.builtin[0].value.is_empty());
				qa.log
					.push("special settings: custom password input enabled and masked".to_owned());
				qa.screenshot(context, "settings-input");
				qa.stage = 105;
			}
			105 if idle => {
				qa.stage = 90;
			}
			90 if idle => {
				qa.log.push(format!("completed; error={}", self.error));
				qa.screenshot(context, "results-completed");
				qa.stage = 91;
			}
			91 | 99 if idle => {
				context.send_viewport_cmd(egui::ViewportCommand::Close);
			}
			_ => {}
		}
		qa.after = Instant::now() + Duration::from_millis(450);
		self.qa = Some(qa);
	}

	//------------------------------------------------------------------------------
	/**
	 * 所有したQA processの終了結果だけを専用領域へ記録します
	 */
	//------------------------------------------------------------------------------
	pub(super) fn qa_exit_log(&mut self) {
		// このアプリが所有した QA だけに、終了時の回収結果を記録する
		if let Some(qa) = &mut self.qa {
			qa.log.push(format!(
				"exit: worker_reaped={}; closing={}; close_ready={}",
				self.worker.is_none(),
				self.closing,
				self.close_ready
			));
			// 終了 log の保存失敗は標準 error へ残し、成功した記録として扱わない
			if let Err(error) = std::fs::write(qa.root.join("qa.log"), qa.log.join("\n")) {
				eprintln!("QA log write failed: {error}");
			}
		}
	}
}
