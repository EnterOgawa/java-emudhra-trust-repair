//------------------------------------------------------------------------------
/*!
 * - ファイル: qa.rs
 * - 概要: 明示 feature と引数でだけ有効な native 描画・隔離 fixture の縦経路 QA です。
 * - バージョン: 01.04.02
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
 * Ver.01.00.00  Shunji Ogawa  2026/10/26  自アプリ screenshot と同じ UI action/worker の隔離 QA を追加。
 * Ver.01.01.00  Shunji Ogawa  2026/10/26  別の内部 QA 領域で未完了復旧・確定中 close・切断を検証。
 * Ver.01.02.00  Shunji Ogawa  2026/10/26  新規隔離領域で簡素化GUIの一操作・復元・無変更を検証。
 * Ver.01.03.00  Shunji Ogawa  2026/10/26  別の新規fixtureで自動状態と非消費入力・世代拒否を検証。
 * Ver.01.04.00  Shunji Ogawa  2026/10/26  Java内backupの確認/復元と従来rootの不使用を新規領域で検証。
 * Ver.01.04.01  Shunji Ogawa  2026/10/26  新規classic-ui領域でfont出典・等倍/拡大・小型画面を記録。
 * Ver.01.04.02  Shunji Ogawa  2026/10/26  新規settings-layout領域で結果と設定の分離・入力欄を記録。
 * ```
 *
 * 備考: 通常起動では動作しません。既存 GUI 証拠と内部 QA の新規コピーを分離します。
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

/// 明示引数だけで有効な自アプリQAです。通常起動・実Javaを対象にしません。
pub struct Preview {
	/// 選択時の自動確認を検証するか。
	auto_status: bool,
	/// 読み取りだけで終了し、変更/backup不在を外から照合するか。
	readonly: bool,
	/// 存在しないfolderを選択するか。
	invalid_folder: bool,
	/// 自動確認中に新しい入力世代へ切り替えるか。
	switch_folder: bool,
	/// 日英描画の明示override。
	language: Language,
	/// 空の簡素画面だけを描画するか。
	preview_only: bool,
	/// 中断経路を確認するか。
	cancel: bool,
	/// 自分のQA windowへのcloseを確認するか。
	close: bool,
	/// 不正passwordの拒否経路を確認するか。
	failure: bool,
	/// 所有fixtureへの実作成denyで、主画面の管理者起動案内を確認するか。
	permission: bool,
	/// 完了通知なしのchannel切断を確認するか。
	disconnect: bool,
	/// 必ずartifacts/settings-layout内の新規fixtureです。
	root: PathBuf,
	/// 逐次actionの位置。
	stage: usize,
	/// 次のactionまで描画する時刻。
	after: Instant,
	/// screenshot保存結果。
	capture: Option<Receiver<Result<(), String>>>,
	/// 実際の工程・回収結果。
	log: Vec<String>,
	/// 所有workerの進捗表示を一度だけ撮ったか。
	progress_captured: bool,
}
impl Preview {
	//------------------------------------------------------------------------------
	/** 既知QA引数一つだけを受け入れます。空引数は通常OS言語のまま起動します。 */
	//------------------------------------------------------------------------------
	pub fn from_arguments(arguments: &[OsString]) -> Result<Option<Self>, std::io::Error> {
		if arguments.is_empty() {
			return Ok(None);
		}
		let value = arguments
			.first()
			.and_then(|value| value.to_str())
			.unwrap_or("");
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
	/** 初期画面と処理後のQAで、設定を閉じた処理結果のnative描画を確認します。 */
	//------------------------------------------------------------------------------
	pub(super) fn shows_results(&self) -> bool {
		(self.preview_only && matches!(self.stage, 100 | 101))
			|| (!self.preview_only && matches!(self.stage, 90 | 91))
	}
	//------------------------------------------------------------------------------
	/** 結果確認の後でだけ特殊設定を開き、有効な入力欄を描画します。 */
	//------------------------------------------------------------------------------
	pub(super) fn shows_settings(&self) -> bool {
		self.preview_only && matches!(self.stage, 102..=105)
	}
	//------------------------------------------------------------------------------
	/** 自アプリの実描画だけをPNGへ保存します。独立threadの完了をchannelで受け取ります。 */
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
	/** 実callbackの中断可否を証跡へ記録します。状態判定に自由文は使いません。 */
	//------------------------------------------------------------------------------
	pub(super) fn progress(&mut self, value: trust_repair_windows::TransactionProgress) {
		self.log.push(format!(
			"{:?}: cancellable={}",
			value.phase, value.cancellable
		));
	}
}
//------------------------------------------------------------------------------
/** 明示QAだけを新規領域へ向けます。通常の既存candidateやuser windowにアクセスしません。 */
//------------------------------------------------------------------------------
pub fn configure(
	mut app: TrustRepairApp,
	preview: Option<Preview>,
	font_source: String,
) -> Result<TrustRepairApp, Box<dyn std::error::Error + Send + Sync>> {
	let Some(mut preview) = preview else {
		return Ok(app);
	};
	std::fs::create_dir_all(&preview.root)?;
	preview.root = std::fs::canonicalize(&preview.root)?;
	preview.log.push(format!("runtime UI font: {font_source}"));
	app.language = preview.language;
	app.legacy_options = TransactionOptions::with_backup_root(preview.root.join("legacy-backups"))?;
	if !preview.preview_only && !preview.disconnect {
		let java = preview.root.join("Java");
		if !java.join("bin/java.exe").is_file() {
			return Err("Prepare new gui-simple fixture first".into());
		}
		app.root_text = java.display().to_string();
		for name in ["custom.jks", "custom.p12"] {
			app.custom.push(StoreInput {
				path: preview.root.join(name),
				password: PasswordInput {
					value: zeroize::Zeroizing::new(String::new()),
					standard: true,
				},
			});
		}
		if preview.failure {
			app.custom[0].password.standard = false;
			*app.custom[0].password.value = "deliberately-wrong-test-password".to_owned();
		}
		if preview.auto_status && !preview.failure {
			app.custom[0].password.standard = false;
			*app.custom[0].password.value = "changeit".to_owned();
		}
		if preview.invalid_folder {
			app.root_text = preview.root.join("missing-Java").display().to_string();
		}
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
	/** 自分の新規fixtureだけで通常の選択・自動Scan・無効化・復元actionを検証します。 */
	//------------------------------------------------------------------------------
	fn qa_auto_step(&mut self, qa: &mut Preview, context: &egui::Context) {
		let idle = self.worker.is_none();
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
	/** 通常と同じ確認後action・復元ボタンを逐次呼びます。自動確認は明示QAに限ります。 */
	//------------------------------------------------------------------------------
	pub(super) fn qa_tick(&mut self, context: &egui::Context) {
		let Some(mut qa) = self.qa.take() else {
			return;
		};
		context.request_repaint_after(Duration::from_millis(80));
		if let Some(receiver) = &qa.capture {
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
		if Instant::now() < qa.after {
			self.qa = Some(qa);
			return;
		}
		let idle = self.worker.is_none();
		if qa.auto_status {
			self.qa_auto_step(&mut qa, context);
			qa.after = Instant::now() + Duration::from_millis(250);
			self.qa = Some(qa);
			return;
		}
		if qa.stage == 3 && !idle && !qa.progress_captured {
			qa.progress_captured = true;
			qa.screenshot(context, "progress");
			self.qa = Some(qa);
			return;
		}
		match qa.stage {
			0 if idle => {
				if qa.preview_only {
					qa.screenshot(context, "initial");
					qa.stage = 92;
				} else if qa.disconnect {
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
				if qa.close {
					context.send_viewport_cmd(egui::ViewportCommand::Close);
				} else if let Some(worker) = &self.worker {
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
	/** 所有したQA processの終了結果だけを専用領域へ記録します。 */
	//------------------------------------------------------------------------------
	pub(super) fn qa_exit_log(&mut self) {
		if let Some(qa) = &mut self.qa {
			qa.log.push(format!(
				"exit: worker_reaped={}; closing={}; close_ready={}",
				self.worker.is_none(),
				self.closing,
				self.close_ready
			));
			if let Err(error) = std::fs::write(qa.root.join("qa.log"), qa.log.join("\n")) {
				eprintln!("QA log write failed: {error}");
			}
		}
	}
}
