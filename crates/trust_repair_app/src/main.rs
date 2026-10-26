//------------------------------------------------------------------------------
/*!
 * - ファイル: main.rs
 * - 概要: 日英の native 画面から診断・適用・復元・未完了復旧を提供します。
 * - バージョン: 01.05.02
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
 * Ver.01.00.00  Shunji Ogawa  2026/10/26  埋込み日本語フォント、最小画面とバイナリ確認を追加。
 * Ver.01.01.00  Shunji Ogawa  2026/10/26  日英操作画面・単一 worker・確認・履歴・復旧を追加。
 * Ver.01.02.00  Shunji Ogawa  2026/10/26  主操作を無効化/元に戻すへ簡素化し、詳細と履歴を折り畳み。
 * Ver.01.03.00  Shunji Ogawa  2026/10/26  選択時の非消費・世代付き読み取り確認を接続。
 * Ver.01.04.00  Shunji Ogawa  2026/10/26  選択Java内の保存先と選択後の履歴照合、従来rootからの復元を表示。
 * Ver.01.04.01  Shunji Ogawa  2026/10/26  OSのMSゴシックと従来Windows風の小型表示へ調整。
 * Ver.01.04.02  Shunji Ogawa  2026/10/26  Javaのバージョンを変更しない案内の日本語を修正。
 * Ver.01.05.00  Shunji Ogawa  2026/10/26  処理結果と通常と異なる環境の設定を別の折畳へ分離。
 * Ver.01.05.01  Shunji Ogawa  2026/10/26  exe と同じ自作アイコンをタイトルバーへ指定。
 * Ver.01.05.02  Shunji Ogawa  2026/10/26  worker回収後の最終通知を採用し、受信との終了競合を修正。
 * ```
 *
 * 備考: password を保存・Debug しません。worker の回収前には終了しません。
 */
//------------------------------------------------------------------------------
#![forbid(unsafe_code)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod language;
#[cfg(feature = "gui-qa")]
mod qa;
#[cfg(test)]
mod tests;
mod ui_style;
mod worker;

use eframe::egui::{self, Color32, RichText};
use language::Language;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::{Duration, Instant};
use trust_repair_core::{IssueCode, PlanError, Policy, embedded_policy};
use trust_repair_windows::{
	CustomStore, HistoryEntry, HistoryState, StorePassword, TransactionCode, TransactionInspection,
	TransactionOptions, TransactionOutcome, TransactionState, ensure_supported_target,
	user_ui_language,
};
use worker::{Command, Completed, Credentials, Diagnosis, Event, Failure, Worker};
use zeroize::{Zeroize, Zeroizing};

// 同じ製品名を両言語で識別できるようにする
const APP_TITLE: &str = "Java Trust Repair · eMudhra";

/// 初回受信後に制御workerを終了させる、試験時だけの一回限りの同期処理です。
#[cfg(test)]
type AfterWorkerDrain = Box<dyn FnOnce(&Worker)>;

/// 秘密入力と明示的な標準値の選択です。Debug・保存を実装しません。
struct PasswordInput {
	/// drop 時に消去する編集 buffer。
	value: Zeroizing<String>,
	/// 利用者が明示した changeit の使用。
	standard: bool,
}
impl PasswordInput {
	//------------------------------------------------------------------------------
	/** 入力を消費せず、一回のread-only確認だけで使う消去対象の秘密へ複写します。保存・Debugしません。 */
	//------------------------------------------------------------------------------
	fn snapshot(&self) -> Result<StorePassword, trust_repair_windows::ProcessError> {
		StorePassword::new(if self.standard {
			"changeit".to_owned()
		} else {
			self.value.as_str().to_owned()
		})
	}
	//------------------------------------------------------------------------------
	/** 未入力・標準値未選択で生成します。 */
	//------------------------------------------------------------------------------
	fn new() -> Self {
		Self {
			value: Zeroizing::new(String::new()),
			standard: false,
		}
	}
	//------------------------------------------------------------------------------
	/** マスクと明示 checkbox を描画して編集の有無を返します。 */
	//------------------------------------------------------------------------------
	fn draw(&mut self, ui: &mut egui::Ui, language: Language) -> bool {
		let mut edited = false;
		ui.horizontal_wrapped(|ui| {
			let response = ui.add_enabled(
				!self.standard,
				egui::TextEdit::singleline(&mut *self.value)
					.password(true)
					.desired_width(200.0)
					.hint_text(language.text("パスワード", "Password")),
			);
			ui_style::text_edit_frame(ui, &response);
			edited |= response.changed();
			if ui
				.checkbox(
					&mut self.standard,
					language.text("標準値 changeit を使う", "Use standard password changeit"),
				)
				.changed()
			{
				self.value.zeroize();
				edited = true;
			}
		});
		edited
	}
	//------------------------------------------------------------------------------
	/** 元 buffer を空にして一回分の秘密へ移動します。失敗時も自動試行しません。 */
	//------------------------------------------------------------------------------
	fn take(&mut self) -> Result<StorePassword, trust_repair_windows::ProcessError> {
		StorePassword::new(if self.standard {
			"changeit".to_owned()
		} else {
			std::mem::take(&mut *self.value)
		})
	}
}

/// 明示追加した一件の store と診断入力です。
struct StoreInput {
	/// 表示変換を識別へ使わない元 path。
	path: PathBuf,
	/// 診断時だけ使う password。
	password: PasswordInput,
}

/// 副作用前に一度だけ表示する確認です。診断結果やpasswordを保持しません。
enum Confirmation {
	/// 選択した Java と追加ストアの無効化。
	Deactivate,
	/// 現物照合した直近履歴の復元・未完了復旧。
	Restore(Box<TransactionInspection>),
}

/// 選択した確認範囲の現状です。失敗や警告から無効化済みを推測しません。
#[derive(Clone, Copy, PartialEq, Eq)]
enum CurrentStatus {
	/// 未選択、または入力変更後の確認待ちです。
	Unknown,
	/// 読み取り確認中です。
	Checking,
	/// 完全な群に対象証明書が残っています。
	TargetsRemain,
	/// 群全体を検証し、対象4rootを検出しませんでした。
	Disabled,
	/// 失敗・警告・変更不可により判定を確定できません。
	Unavailable,
}
impl CurrentStatus {
	//------------------------------------------------------------------------------
	/** 全群の型付きplanから現状を選びます。NoTargetsは全件診断合格後にだけ返る契約です。 */
	//------------------------------------------------------------------------------
	fn from_plan(plan: &Result<trust_repair_core::ChangePlan, PlanError>) -> Self {
		match plan {
			Ok(_) => Self::TargetsRemain,
			Err(PlanError::NoTargets) => Self::Disabled,
			Err(_) => Self::Unavailable,
		}
	}
}

/// 一画面の入力と結果、唯一の実行workerを所有します。
struct TrustRepairApp {
	/// 埋込み4rootの識別定義。
	policy: Policy,
	/// OSから選択した表示言語。
	language: Language,
	/// 従来版の履歴だけを参照する本人用root。新規backupには使用しません。
	legacy_options: TransactionOptions,
	/// 編集用Javaフォルダ表示。
	root_text: String,
	/// dialogで得た元pathと表示値。
	picked_root: Option<(PathBuf, String)>,
	/// 入力変更ごとに進める、古い非同期結果を拒否する世代。
	input_generation: u64,
	/// 自動確認workerが読んでいる入力世代。手動操作ではNone。
	automatic_generation: Option<u64>,
	/// 入力の短い静止後に一度だけ確認する期限。
	auto_due: Option<Instant>,
	/// フォルダ欄直下の一行状態。
	current_status: CurrentStatus,
	/// 一操作の認証入力。標準値は小補足に明示します。
	builtin: [PasswordInput; 2],
	/// 明示追加したストアとその入力。
	custom: Vec<StoreInput>,
	/// 結果の詳細。主操作に診断手順を要求しません。
	diagnosis: Option<Box<Diagnosis>>,
	/// 詳細内で表示する検査済み履歴。
	history: Vec<HistoryEntry>,
	/// 未完了があり復元を優先するか。
	needs_recovery: bool,
	/// 一回の変更確認。
	confirmation: Option<Confirmation>,
	/// joinするまで所有する唯一のworker。
	worker: Option<Worker>,
	/// join前の完了通知。
	pending: Option<Result<Completed, Failure>>,
	/// 初回受信直後の終了競合を固定する、試験時だけの一回限りの同期点。
	#[cfg(test)]
	after_worker_drain: Option<AfterWorkerDrain>,
	/// 簡潔な実工程の表示。
	progress: String,
	/// backendが通知した中断可否。
	cancellable: bool,
	/// 通常画面へ表示する短い結果。
	message: String,
	/// 詳細でだけ表示する証跡と拒否理由。
	error_details: String,
	/// 正常・拒否の見分け。
	error: bool,
	/// 最後の検証済み書換え結果。
	outcome: Option<TransactionOutcome>,
	/// 安全な終了を待っているか。
	closing: bool,
	/// worker回収済みでcloseできるか。
	close_ready: bool,
	/// 明示feature/引数だけで有効な自アプリQA。
	#[cfg(feature = "gui-qa")]
	qa: Option<qa::Preview>,
}

impl TrustRepairApp {
	//------------------------------------------------------------------------------
	/** 定義と設定を受け取り、標準password利用を明示する初期画面を作ります。I/Oはworkerで行います。 */
	//------------------------------------------------------------------------------
	fn new(policy: Policy, language: Language, legacy_options: TransactionOptions) -> Self {
		let standard = || {
			let mut input = PasswordInput::new();
			input.standard = true;
			input
		};
		Self {
			policy,
			language,
			legacy_options,
			root_text: String::new(),
			picked_root: None,
			input_generation: 0,
			automatic_generation: None,
			auto_due: None,
			current_status: CurrentStatus::Unknown,
			builtin: [standard(), standard()],
			custom: Vec::new(),
			diagnosis: None,
			history: Vec::new(),
			needs_recovery: false,
			confirmation: None,
			worker: None,
			pending: None,
			#[cfg(test)]
			after_worker_drain: None,
			progress: String::new(),
			cancellable: true,
			message: String::new(),
			error_details: String::new(),
			error: false,
			outcome: None,
			closing: false,
			close_ready: false,
			#[cfg(feature = "gui-qa")]
			qa: None,
		}
	}
	//------------------------------------------------------------------------------
	/** dialogで得た非Unicode pathを失わず、選択したJavaを返します。 */
	//------------------------------------------------------------------------------
	fn selected_root(&self) -> PathBuf {
		self.picked_root
			.as_ref()
			.filter(|(_, shown)| shown == &self.root_text)
			.map(|(path, _)| path.clone())
			.unwrap_or_else(|| PathBuf::from(&self.root_text))
	}
	//------------------------------------------------------------------------------
	/** 未作成でも表示できる、選択Java内の固定backup rootを返します。I/Oは行いません。 */
	//------------------------------------------------------------------------------
	fn selected_backup_root(&self) -> PathBuf {
		self.diagnosis
			.as_ref()
			.map_or_else(
				|| self.selected_root(),
				|diagnosis| diagnosis.environment.root().to_path_buf(),
			)
			.join("emudhra-backup")
	}
	//------------------------------------------------------------------------------
	/** 選択Javaだけの直近履歴から未完了を案内します。従来の未帰属記録は詳細に保全します。 */
	//------------------------------------------------------------------------------
	fn accept_history(&mut self, entries: Vec<HistoryEntry>) {
		self.needs_recovery = entries
			.iter()
			.filter_map(|entry| entry.inspection.as_ref().ok())
			.find(|entry| {
				!entry.java_root.as_os_str().is_empty()
					|| entry
						.backup_directory
						.parent()
						.and_then(|path| path.file_name())
						== Some(std::ffi::OsStr::new("emudhra-backup"))
			})
			.is_some_and(|entry| {
				matches!(
					entry.state,
					HistoryState::Recoverable
						| HistoryState::RecoveryRequired
						| HistoryState::IncompletePreparation
						| HistoryState::Invalid
				)
			});
		self.history = entries;
	}
	//------------------------------------------------------------------------------
	/** 入力変更で古い診断・確認・結果を破棄します。履歴自体を書き換えません。 */
	//------------------------------------------------------------------------------
	fn invalidate(&mut self) {
		self.schedule_check(Duration::from_millis(600));
		self.diagnosis = None;
		self.confirmation = None;
		self.outcome = None;
		self.message.clear();
		self.error_details.clear();
		self.error = false;
		self.needs_recovery = false;
		self.history.clear();
	}
	//------------------------------------------------------------------------------
	/** 入力世代を進め、古い状態を即時破棄します。実行中の自動確認だけは安全に中断を要求します。 */
	//------------------------------------------------------------------------------
	fn schedule_check(&mut self, delay: Duration) {
		self.input_generation = self.input_generation.wrapping_add(1);
		self.current_status = CurrentStatus::Unknown;
		self.diagnosis = None;
		self.auto_due = if self.root_text.trim().is_empty() {
			None
		} else {
			Some(Instant::now() + delay)
		};
		if self.automatic_generation.is_some()
			&& let Some(worker) = &self.worker
		{
			worker.cancellation.cancel();
		}
	}
	//------------------------------------------------------------------------------
	/** 自動確認用の一時snapshotを作ります。画面のcustom passwordは移動・消去しません。 */
	//------------------------------------------------------------------------------
	fn snapshot_credentials(&self) -> Result<Credentials, trust_repair_windows::ProcessError> {
		let cacerts = self.builtin[0].snapshot()?;
		let jsse = if !self.builtin[1].standard && self.builtin[1].value.is_empty() {
			None
		} else {
			Some(self.builtin[1].snapshot()?)
		};
		let custom = self
			.custom
			.iter()
			.map(|store| {
				Ok(CustomStore {
					path: store.path.clone(),
					password: store.password.snapshot()?,
				})
			})
			.collect::<Result<Vec<_>, trust_repair_windows::ProcessError>>()?;
		Ok(Credentials {
			builtin: (cacerts, jsse),
			custom,
		})
	}
	//------------------------------------------------------------------------------
	/** 一度の期限到来時だけ既存Scanをworkerへ送り、入力途中や重複実行を避けます。 */
	//------------------------------------------------------------------------------
	fn pump_auto_check(&mut self, context: &egui::Context) {
		let Some(due) = self.auto_due else {
			return;
		};
		if self.worker.is_some() || self.confirmation.is_some() || self.closing {
			return;
		}
		if due > Instant::now() {
			context.request_repaint_after(due.saturating_duration_since(Instant::now()));
			return;
		}
		self.auto_due = None;
		let generation = self.input_generation;
		match self.snapshot_credentials() {
			Ok(credentials) => {
				self.launch(
					Command::Scan {
						root: self.selected_root(),
						credentials,
					},
					context,
				);
				if self.worker.is_some() {
					self.automatic_generation = Some(generation);
					self.current_status = CurrentStatus::Checking;
					context.request_repaint();
				}
			}
			Err(value) => self.accept_auto_check(generation, Err(Failure::Process(value))),
		}
	}
	//------------------------------------------------------------------------------
	/** 現入力と同じ世代のread-only結果だけを採用します。古い結果と一時秘密はそのままdropします。 */
	//------------------------------------------------------------------------------
	fn accept_auto_check(&mut self, generation: u64, result: Result<Completed, Failure>) {
		self.progress.clear();
		if generation != self.input_generation {
			return;
		}
		match result {
			Ok(Completed::Scan(mut value)) => {
				self.accept_history(std::mem::take(&mut value.history));
				self.current_status = if self.needs_recovery {
					CurrentStatus::Unavailable
				} else {
					CurrentStatus::from_plan(&value.plan)
				};
				if value.needs_administrator() {
					self.message = self.language.administrator_required().to_owned();
					self.error = true;
				}
				self.diagnosis = Some(value);
			}
			Err(value) => {
				let permission = value.needs_administrator();
				self.accept(Err(value));
				if !permission {
					self.message.clear();
					self.error = false;
				}
				self.current_status = CurrentStatus::Unavailable;
			}
			_ => {
				self.current_status = CurrentStatus::Unavailable;
			}
		}
	}
	//------------------------------------------------------------------------------
	/** フォルダ欄下に確認範囲を限定した一行の状態を表示します。 */
	//------------------------------------------------------------------------------
	fn draw_current_status(&self, ui: &mut egui::Ui) {
		let color = match self.current_status {
			CurrentStatus::Disabled => Color32::from_rgb(25, 110, 60),
			CurrentStatus::TargetsRemain => Color32::from_rgb(150, 80, 0),
			CurrentStatus::Unavailable => Color32::from_rgb(165, 45, 30),
			_ => Color32::from_gray(90),
		};
		ui.horizontal_wrapped(|ui| {
			if self.current_status == CurrentStatus::Checking {
				ui.spinner();
			}
			ui.colored_label(
				color,
				self.language
					.current_status(self.current_status, !self.root_text.trim().is_empty()),
			);
		});
	}
	//------------------------------------------------------------------------------
	/** 入力を一回のworkerへ移します。操作終了後に保持する秘密を返しません。 */
	//------------------------------------------------------------------------------
	fn take_credentials(&mut self) -> Result<Credentials, trust_repair_windows::ProcessError> {
		let cacerts = self.builtin[0].take()?;
		let jsse = if !self.builtin[1].standard && self.builtin[1].value.is_empty() {
			None
		} else {
			Some(self.builtin[1].take()?)
		};
		let custom = self
			.custom
			.iter_mut()
			.map(|store| {
				Ok(CustomStore {
					path: store.path.clone(),
					password: store.password.take()?,
				})
			})
			.collect::<Result<Vec<_>, trust_repair_windows::ProcessError>>()?;
		Ok(Credentials {
			builtin: (cacerts, jsse),
			custom,
		})
	}
	//------------------------------------------------------------------------------
	/** busy/close待機中は二重開始せず、渡された秘密をdropします。 */
	//------------------------------------------------------------------------------
	fn launch(&mut self, command: Command, context: &egui::Context) {
		if self.worker.is_some() || self.closing {
			return;
		}
		if matches!(
			&command,
			Command::Scan { .. } | Command::Deactivate { .. } | Command::Restore { .. }
		) {
			self.auto_due = None;
			self.current_status = CurrentStatus::Unknown;
		}
		self.message.clear();
		self.error_details.clear();
		self.error = false;
		self.progress = self
			.language
			.text("Java を確認しています…", "Checking Java…")
			.to_owned();
		self.cancellable = !matches!(
			&command,
			Command::History { .. } | Command::PrepareRestore { .. } | Command::Save { .. }
		);
		match worker::start(command, self.legacy_options.clone(), context.clone()) {
			Ok(worker) => self.worker = Some(worker),
			Err(_) => self.accept(Err(Failure::Interrupted)),
		}
	}
	//------------------------------------------------------------------------------
	/**
	 * 完了済みthreadだけjoinし、回収後の最終通知まで受信して結果を一度だけ採用します。
	 * 実行中はworkerを保持し、panicまたは完了通知欠落だけを予期しない終了へ分類します。
	 * ファイル処理や実行中waitをUIで行いません。
	 */
	//------------------------------------------------------------------------------
	fn poll(&mut self) {
		let Some(worker) = self.worker.take() else {
			return;
		};
		self.drain_worker_events(&worker.receiver);
		#[cfg(test)]
		if let Some(after_drain) = self.after_worker_drain.take() {
			after_drain(&worker);
		}
		if !worker.handle.is_finished() {
			self.worker = Some(worker);
			return;
		}
		let joined = worker.handle.join().is_ok();
		// 初回Emptyの直後に送信されたDoneも、thread回収後なら漏れなく取得できる
		self.drain_worker_events(&worker.receiver);
		let result = match (joined, self.pending.take()) {
			(true, Some(result)) => result,
			_ => Err(Failure::Interrupted),
		};
		if let Some(generation) = self.automatic_generation.take() {
			self.accept_auto_check(generation, result);
		} else {
			self.accept(result);
		}
	}
	//------------------------------------------------------------------------------
	/** 同じ通知処理で工程・中断可否・完了結果を受信します。実行中threadの通知は待ちません。 */
	//------------------------------------------------------------------------------
	fn drain_worker_events(&mut self, receiver: &Receiver<Event>) {
		loop {
			match receiver.try_recv() {
				Ok(Event::Scan(value)) => {
					self.progress = self.language.simple_scan_phase(value.phase).to_owned();
					self.cancellable = true;
				}
				Ok(Event::Transaction(value)) => {
					#[cfg(feature = "gui-qa")]
					if let Some(qa) = &mut self.qa {
						qa.progress(value);
					}
					self.progress = self.language.simple_phase(value.phase).to_owned();
					self.cancellable = value.cancellable;
				}
				Ok(Event::Done(result)) => self.pending = Some(result),
				Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
			}
		}
	}
	//------------------------------------------------------------------------------
	/** 型付き結果を短い通常表示と専門詳細へ反映します。未完了や切断を成功表示しません。 */
	//------------------------------------------------------------------------------
	fn accept(&mut self, result: Result<Completed, Failure>) {
		self.progress.clear();
		match result {
			Ok(Completed::Scan(mut value)) => {
				self.accept_history(std::mem::take(&mut value.history));
				self.current_status = if self.needs_recovery {
					CurrentStatus::Unavailable
				} else {
					CurrentStatus::from_plan(&value.plan)
				};
				self.message = self
					.language
					.text(
						"確認しました。詳しい結果は下に表示しています。",
						"Checked. Detailed results are shown below.",
					)
					.to_owned();
				if value.needs_administrator() {
					self.message = self.language.administrator_required().to_owned();
					self.error = true;
				}
				self.diagnosis = Some(value);
			}
			Ok(Completed::Deactivated { diagnosis, outcome }) => {
				self.history.clear();
				if let Some(outcome) = outcome {
					self.set_outcome(outcome);
				} else {
					self.current_status = CurrentStatus::from_plan(&diagnosis.plan);
					self.outcome = None;
					self.error = !matches!(diagnosis.plan, Err(PlanError::NoTargets));
					self.message = if matches!(diagnosis.plan, Err(PlanError::NoTargets)) {
						self.language.text(
							"選択したストアに対象証明書はありませんでした。変更はしていません。",
							"No matching certificates were found in the selected stores. Nothing was changed.",
						)
					} else if diagnosis
						.group
						.stores()
						.iter()
						.any(|store| store.report().issues().contains(&IssueCode::Cancelled))
					{
						self.error = false;
						self.language.text(
							"中断しました。変更はしていません。",
							"Cancelled. Nothing was changed.",
						)
					} else {
						self.language.text(
							"無効化できませんでした。処理結果をご確認ください。",
							"Could not disable the certificates. See Results.",
						)
					}
					.to_owned();
				}
				if diagnosis.needs_administrator() {
					self.message = self.language.administrator_required().to_owned();
					self.error = true;
				}
				self.diagnosis = Some(diagnosis);
			}
			Ok(Completed::Transaction(value)) => {
				self.set_outcome(value);
				self.diagnosis = None;
				self.history.clear();
				self.needs_recovery = false;
			}
			Ok(Completed::RestoreReady(Some(value))) => {
				let mut scope_changed = false;
				// 履歴に含む追加ストアを再表示し、再起動後も復元の入力先を失わない
				for path in &value.stores {
					if path != &value.java_root.join("lib/security/cacerts")
						&& path != &value.java_root.join("lib/security/jssecacerts")
						&& !self.custom.iter().any(|store| &store.path == path)
					{
						self.custom.push(StoreInput {
							path: path.clone(),
							password: PasswordInput {
								value: Zeroizing::new(String::new()),
								standard: true,
							},
						});
						scope_changed = true;
					}
				}
				if scope_changed {
					self.schedule_check(Duration::ZERO);
				}
				if value.java_unchanged
					&& matches!(
						value.state,
						HistoryState::Applied | HistoryState::Recoverable
					) {
					self.needs_recovery = value.state == HistoryState::Recoverable;
					self.confirmation = Some(Confirmation::Restore(value));
				} else {
					self.error = true;
					self.needs_recovery = true;
					self.message = self
						.language
						.text(
							"現在の内容を安全に元へ戻せません。詳細とバックアップを確認してください。",
							"The current files cannot be safely restored. Review the details and backup.",
						)
						.to_owned();
					self.error_details = format!(
						"{}\n{}\n{}\n{}",
						self.language.history(value.state),
						value.java_root.display(),
						value.transaction_id,
						value.backup_directory.display()
					);
				}
			}
			Ok(Completed::RestoreReady(None)) => {
				self.message = self
					.language
					.text(
						"この Java に元へ戻す変更はありません。",
						"There are no changes to restore for this Java.",
					)
					.to_owned();
			}
			Ok(Completed::History(entries)) => {
				self.accept_history(entries);
				if self.needs_recovery {
					self.current_status = CurrentStatus::Unavailable;
				}
			}
			Ok(Completed::Saved(path)) => {
				self.message = self
					.language
					.text("結果を保存しました。", "Results saved.")
					.to_owned();
				self.error_details = path.display().to_string();
			}
			Err(failure) => {
				self.current_status = CurrentStatus::Unavailable;
				self.outcome = None;
				self.confirmation = None;
				self.error = true;
				self.error_details = match &failure {
					Failure::Java(value) => self.language.java(value),
					Failure::Process(value) => self.language.process(value),
					Failure::Transaction(value) => self.language.transaction_error(value),
					Failure::Save(kind) => {
						if *kind == std::io::ErrorKind::AlreadyExists {
							self.language
								.text(
									"既存のファイルは上書きしません。別の保存名を選んでください。",
									"Existing files are not overwritten. Choose a new file name.",
								)
								.to_owned()
						} else {
							self.language
								.text("結果を保存できません。", "Could not save results.")
								.to_owned()
						}
					}
					Failure::Policy => self
						.language
						.text(
							"選択した Java・ストア・対策定義を照合できません。",
							"The selected Java, stores or policy could not be matched.",
						)
						.to_owned(),
					Failure::Interrupted => self
						.language
						.text(
							"処理が予期せず終了しました。成功とは判定できません。履歴とバックアップを確認してください。",
							"Processing ended unexpectedly. Success cannot be confirmed. Inspect history and backups.",
						)
						.to_owned(),
				};
				self.message = match &failure {
					value if value.needs_administrator() => {
						if matches!(value, Failure::Transaction(error) if error.state == TransactionState::RecoveryRequired) { self.needs_recovery = true; }
						self.language.administrator_required()
					}
					Failure::Process(trust_repair_windows::ProcessError::Cancelled)
					| Failure::Java(trust_repair_windows::JavaError::Process(
						trust_repair_windows::ProcessError::Cancelled,
					)) => {
						self.error = false;
						self.language.text(
							"中断しました。変更はしていません。",
							"Cancelled. Nothing was changed.",
						)
					}
					Failure::Transaction(value) if value.code == TransactionCode::Cancelled => {
						self.error = false;
						self.language.text(
							"中断しました。変更はしていません。",
							"Cancelled. Nothing was changed.",
						)
					}
					Failure::Process(trust_repair_windows::ProcessError::InvalidPassword) => {
						self.language.text(
							"「通常と異なる環境の設定」でパスワードを入力してください。",
							"Enter the password in Settings for nonstandard environments.",
						)
					}
					Failure::Transaction(value)
						if value.state == TransactionState::RecoveryRequired =>
					{
						self.needs_recovery = true;
						self.language.text(
							"処理が完了していません。元に戻す操作で復旧を確認してください。",
							"Processing is incomplete. Use Restore to review recovery.",
						)
					}
					_ => self.language.text(
						"処理を完了できませんでした。処理結果をご確認ください。",
						"The operation could not be completed. See Results.",
					),
				}
				.to_owned();
			}
		}
	}
	//------------------------------------------------------------------------------
	/** backendが全件検証した状態だけを、無効化・復元の結果として表示します。 */
	//------------------------------------------------------------------------------
	fn set_outcome(&mut self, outcome: TransactionOutcome) {
		self.current_status = match outcome.state {
			TransactionState::Applied => CurrentStatus::Disabled,
			TransactionState::Restored
			| TransactionState::AlreadyRestored
			| TransactionState::RolledBack => CurrentStatus::TargetsRemain,
			_ => CurrentStatus::Unavailable,
		};
		self.error = false;
		self.message = match outcome.state {
			TransactionState::Applied => self.language.text(
				"eMudhra 関連証明書を無効化しました。",
				"eMudhra-related certificates have been disabled.",
			),
			TransactionState::Restored
			| TransactionState::AlreadyRestored
			| TransactionState::RolledBack => self.language.text(
				"元の状態に戻しました。",
				"The original state has been restored.",
			),
			_ => {
				self.error = true;
				self.language.state(outcome.state)
			}
		}
		.to_owned();
		self.outcome = Some(outcome);
	}
	//------------------------------------------------------------------------------
	/** 無効化は一度の確認、診断は詳細からだけ開始します。認証をworkerへ移動してUI bufferを空にします。 */
	//------------------------------------------------------------------------------
	fn execute_confirmed(&mut self, confirmation: Confirmation, context: &egui::Context) {
		if self.worker.is_some() || self.closing {
			return;
		}
		let credentials = match self.take_credentials() {
			Ok(value) => value,
			Err(value) => {
				self.accept(Err(Failure::Process(value)));
				return;
			}
		};
		let command = match confirmation {
			Confirmation::Deactivate => Command::Deactivate {
				root: self.selected_root(),
				credentials,
			},
			Confirmation::Restore(value) => Command::Restore {
				backup_root: value
					.backup_directory
					.parent()
					.unwrap_or(&value.backup_directory)
					.to_path_buf(),
				root: value.java_root,
				id: value.transaction_id,
				recovery: value.state == HistoryState::Recoverable,
				credentials,
			},
		};
		self.diagnosis = None;
		self.outcome = None;
		self.launch(command, context);
	}
	//------------------------------------------------------------------------------
	/** 選択Javaの直近の現物照合をworkerで行い、一回の復元確認へ進みます。 */
	//------------------------------------------------------------------------------
	fn prepare_restore(&mut self, context: &egui::Context) {
		self.launch(
			Command::PrepareRestore {
				root: self.selected_root(),
			},
			context,
		);
	}
	//------------------------------------------------------------------------------
	/** 通常操作を妨げず、診断・履歴・結果保存を処理結果の折畳へ格納します。 */
	//------------------------------------------------------------------------------
	fn draw_results(&mut self, ui: &mut egui::Ui) {
		let language = self.language;
		#[cfg(feature = "gui-qa")]
		let open = self.qa.as_ref().map(|qa| qa.shows_results());
		#[cfg(not(feature = "gui-qa"))]
		let open = None;
		egui::CollapsingHeader::new(language.text("処理結果", "Results")).open(open).show(ui, |ui| {
   ui.horizontal_wrapped(|ui| {
    if ui_style::button(ui, egui::Button::new(language.text("変更せず詳しく確認", "Inspect without changing files")), !self.root_text.is_empty()).clicked() {
     match self.take_credentials() { Ok(credentials) => self.launch(Command::Scan { root: self.selected_root(), credentials }, ui.ctx()), Err(value) => self.accept(Err(Failure::Process(value))) }
    }
    if ui_style::button(ui, egui::Button::new(language.text("履歴を更新", "Refresh history")), !self.root_text.trim().is_empty()).clicked() { self.launch(Command::History { root: self.selected_root() }, ui.ctx()); }
    if ui_style::button(ui, egui::Button::new(language.text("結果を保存…", "Save results…")), !self.message.is_empty() || self.diagnosis.is_some()).clicked() && let Some(path) = rfd::FileDialog::new().set_file_name("java-trust-repair-results.txt").save_file() { self.launch(Command::Save { path, text: self.report() }, ui.ctx()); }
   });
   if !self.error_details.is_empty() { ui.label(&self.error_details); }
   if let Some(diagnosis) = &self.diagnosis {
    ui.label(format!("Java {} · {}", diagnosis.environment.version(), diagnosis.environment.vendor()));
    if let Err(reason) = &diagnosis.plan { ui.label(language.plan(reason)); }
    for store in diagnosis.group.stores() {
     ui.separator(); ui.label(RichText::new(language.status(store.report().status())).strong());
     for path in store.input_paths() { ui.label(path.display().to_string()); }
     for issue in store.report().issues() { ui.label(language.issue(*issue)); }
     if let Some(value) = store.failure() { ui.label(language.failure(value)); }
     for target in store.report().targets() { let name = self.policy.roots().iter().find(|root| root.id() == target.policy_root_id()).map_or(target.policy_root_id(), |root| root.name()); ui.label(format!("{name} · {}", target.alias())); ui.add(egui::Label::new(RichText::new(target.sha256()).monospace().size(12.0)).wrap()); }
    }
   }
   ui.separator(); if !self.root_text.trim().is_empty() { ui.small(self.selected_backup_root().display().to_string()); }
   if let Some(value) = &self.outcome { ui.label(format!("ID: {}", value.transaction_id)); }
   for entry in &self.history {
    ui.separator(); ui.small(&entry.transaction_id);
    match &entry.inspection {
     Ok(value) => { ui.label(language.history(value.state)); ui.small(value.backup_directory.display().to_string()); if value.java_root.as_os_str().is_empty() { ui.label(language.text("保存時の Java を特定できません。元の記録を保持し、自動復元は行いません。", "The original Java folder cannot be identified. The records are preserved; automatic restoration is unavailable.")); } else { ui.small(value.java_root.display().to_string()); } for (index, path) in value.stores.iter().enumerate() { ui.label(path.display().to_string()); if let Some(state) = value.items.get(index) { ui.small(language.item(*state)); } } },
     Err(value) => { ui.label(language.transaction_error(value)); },
    }
   }
  });
	}
	//------------------------------------------------------------------------------
	/** 標準passwordを変更した環境と追加ストアだけに必要な入力を、閉じた別欄へ格納します。 */
	//------------------------------------------------------------------------------
	fn draw_environment_settings(&mut self, ui: &mut egui::Ui) {
		let language = self.language;
		#[cfg(feature = "gui-qa")]
		let open = self.qa.as_ref().map(|qa| qa.shows_settings());
		#[cfg(not(feature = "gui-qa"))]
		let open = None;
		egui::CollapsingHeader::new(language.text("通常と異なる環境の設定", "Settings for nonstandard environments")).default_open(false).open(open).show(ui, |ui| {
   let mut edited = false;
   ui.label(language.text("通常は設定の変更は不要です。標準パスワードは changeit です。変更している場合だけ入力してください。入力した値は操作終了時に消去します。", "These settings are usually unnecessary. The standard password is changeit. Enter a custom password only if it was changed. Entered values are erased after each operation."));
   for (index, name) in ["cacerts", "jssecacerts"].into_iter().enumerate() { ui.push_id(index, |ui| { ui.label(name); edited |= self.builtin[index].draw(ui, language); }); }
   let mut remove = None;
   for (index, store) in self.custom.iter_mut().enumerate() { ui.push_id(("custom", index), |ui| {
    ui.horizontal_wrapped(|ui| { ui.label(store.path.display().to_string()); if ui_style::button(ui, egui::Button::new(language.text("除外", "Remove")).small(), true).clicked() { remove = Some(index); } }); edited |= store.password.draw(ui, language);
   }); }
   if let Some(index) = remove { self.custom.remove(index); edited = true; }
   if ui_style::button(ui, egui::Button::new(language.text("追加の信頼ストア…", "Add a trust store…")), true).clicked() && let Some(path) = rfd::FileDialog::new().set_title(language.text("追加の信頼ストア", "Additional trust store")).pick_file() {
    self.custom.push(StoreInput { path, password: PasswordInput { value: Zeroizing::new(String::new()), standard: true } }); edited = true;
   }
   if edited { self.invalidate(); }
  });
	}
	//------------------------------------------------------------------------------
	/** 副作用前の一回だけ、対象・自動backup・通信への影響を簡潔に確認します。 */
	//------------------------------------------------------------------------------
	fn draw_confirmation(&mut self, context: &egui::Context) {
		let Some(confirmation) = &self.confirmation else {
			return;
		};
		let language = self.language;
		let restore = matches!(confirmation, Confirmation::Restore(_));
		let mut run = false;
		let mut cancel = false;
		egui::Modal::new(egui::Id::unique("simple-confirm")).backdrop_color(Color32::from_black_alpha(45)).show(context, |ui| {
   ui.set_max_width((context.content_rect().width() - 48.0).min(600.0));
   egui::ScrollArea::vertical().max_height((context.content_rect().height() - 100.0).max(80.0)).show(ui, |ui| {
   ui.heading(if restore { language.text("元に戻しますか？", "Restore the original state?") } else { language.text("証明書を無効化しますか？", "Disable the certificates?") });
   ui.add_space(4.0);
   let path = match confirmation { Confirmation::Deactivate => self.selected_root(), Confirmation::Restore(value) => value.java_root.clone() };
   ui.label(path.display().to_string());
   if restore { ui.label(language.text("バックアップから元に戻します。無効化した CA への信頼も元に戻ります。", "Restore from the backup. This also restores trust in the disabled CAs.")); }
   else {
    ui.label(language.text("元に戻せるよう自動でバックアップしてから、対象の証明書だけを無効化します。", "A backup is saved automatically before disabling the matching certificates."));
    for store in &self.custom { ui.small(store.path.display().to_string()); }
    ui.label(language.text("対象 CA を使う通信や署名の検証が失敗する場合があります。対象を使うアプリと同時更新するツールを終了してから実行してください。", "Connections or signature checks using these CAs may fail. Close applications and tools that use or update these stores before continuing."));
   }
   let backup = match confirmation { Confirmation::Deactivate => self.selected_backup_root(), Confirmation::Restore(value) => value.backup_directory.clone() };
   ui.add(egui::Label::new(format!("{}: {}", language.text("バックアップ", "Backup"), backup.display())).wrap());
   });
   ui.add_space(6.0);
   ui.horizontal_wrapped(|ui| {
    if ui_style::button(ui, egui::Button::new(language.text("キャンセル", "Cancel")), true).clicked() { cancel = true; }
    if ui_style::button(ui, egui::Button::new(if restore { language.text("元に戻す", "Restore") } else { language.text("無効化する", "Disable certificates") }), true).clicked() { run = true; }
   });
  });
		if cancel {
			self.confirmation = None;
		}
		if run && let Some(confirmation) = self.confirmation.take() {
			self.execute_confirmed(confirmation, context);
		}
	}
	//------------------------------------------------------------------------------
	/** 秘密や外部出力全文を含めず、選択scopeの結果と証跡だけを保存用textへ組み立てます。 */
	//------------------------------------------------------------------------------
	fn report(&self) -> String {
		let mut text = format!(
			"{APP_TITLE}\n{}\n{}\n{}\n",
			self.root_text, self.message, self.error_details
		);
		text.push_str(self.language.text(
			"確認範囲は選択したストアだけです。\n",
			"Inspection covers only the selected stores.\n",
		));
		if !self.root_text.trim().is_empty() {
			text.push_str(&format!(
				"{}: {}\n",
				self.language
					.text("新規バックアップ先", "New backup location"),
				self.selected_backup_root().display()
			));
		}
		if let Some(value) = &self.outcome {
			text.push_str(&format!(
				"ID: {}\n{}\n",
				value.transaction_id,
				value.backup_directory.display()
			));
		}
		if let Some(value) = &self.diagnosis {
			for store in value.group.stores() {
				text.push_str(&format!(
					"{}\n",
					self.language.status(store.report().status())
				));
				for path in store.input_paths() {
					text.push_str(&format!("{}\n", path.display()));
				}
				for issue in store.report().issues() {
					text.push_str(&format!("{}\n", self.language.issue(*issue)));
				}
				for target in store.report().targets() {
					text.push_str(&format!("{} · {}\n", target.alias(), target.sha256()));
				}
			}
		}
		for entry in &self.history {
			text.push_str(&format!("ID: {}\n", entry.transaction_id));
			match &entry.inspection {
				Ok(value) => text.push_str(&format!(
					"{}\n{}\n",
					self.language.history(value.state),
					value.backup_directory.display()
				)),
				Err(value) => {
					text.push_str(&format!("{}\n", self.language.transaction_error(value)))
				}
			}
		}
		text
	}
	//------------------------------------------------------------------------------
	/** 実行中closeは安全な中断/確定待ちへ変え、回収後にだけcloseを許可します。 */
	//------------------------------------------------------------------------------
	fn handle_close(&mut self, context: &egui::Context) {
		if context.input(|input| input.viewport().close_requested())
			&& !self.close_ready
			&& self.worker.is_some()
		{
			context.send_viewport_cmd(egui::ViewportCommand::CancelClose);
			self.closing = true;
			if self.cancellable
				&& let Some(worker) = &self.worker
			{
				worker.cancellation.cancel();
			}
		}
		if self.closing && self.worker.is_none() {
			self.close_ready = true;
			context.send_viewport_cmd(egui::ViewportCommand::Close);
		}
	}
}

impl eframe::App for TrustRepairApp {
	//------------------------------------------------------------------------------
	/** 主操作を一画面に描画します。結果と特殊な環境の設定は別々に折り畳みます。 */
	//------------------------------------------------------------------------------
	fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
		self.poll();
		self.handle_close(ui.ctx());
		let language = self.language;
		egui::CentralPanel::default().frame(egui::Frame::central_panel(ui.style()).inner_margin(12)).show(ui, |ui| {
			egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
				ui.heading(language.text("Java の eMudhra 対策", "eMudhra protection for Java"));
				ui.label(language.text("Java フォルダを選ぶと、関連する証明書を無効化できます。必要なときは元に戻せます。", "Choose a Java folder to disable the related certificates. You can restore them when needed."));
				ui.add_space(6.0);
				ui.add_enabled_ui(self.worker.is_none() && !self.closing, |ui| {
					ui.label(language.text("Java フォルダ", "Java folder"));
					let mut edited = false; let mut committed = false;
					ui.horizontal(|ui| {
						let response = ui.add(egui::TextEdit::singleline(&mut self.root_text).desired_width((ui.available_width() - 140.0).max(100.0)).hint_text(language.text("Java のインストール先", "Java installation folder")));
						ui_style::text_edit_frame(ui, &response);
						edited |= response.changed(); committed |= response.lost_focus() || (response.has_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter)));
						if ui_style::button(ui, egui::Button::new(language.text("フォルダを選ぶ…", "Choose folder…")), true).clicked() && let Some(path) = rfd::FileDialog::new().set_title(language.text("Java フォルダを選択", "Select the Java folder")).pick_folder() { self.root_text = path.display().to_string(); self.picked_root = Some((path, self.root_text.clone())); edited = true; committed = true; }
					});
					if edited { self.invalidate(); }
					if committed && self.current_status == CurrentStatus::Unknown && !self.root_text.trim().is_empty() { self.auto_due = Some(Instant::now()); }
					self.draw_current_status(ui);
					ui.add_space(6.0);
					ui.horizontal_wrapped(|ui| {
						let valid = !self.root_text.trim().is_empty();
						if ui_style::button(ui, egui::Button::new(language.text("eMudhra 関連証明書を無効化", "Disable eMudhra-related certificates")).min_size(egui::vec2(240.0, 25.0)), valid && !self.needs_recovery).clicked() { self.confirmation = Some(Confirmation::Deactivate); }
						if ui_style::button(ui, egui::Button::new(language.text("元に戻す", "Restore")).min_size(egui::vec2(86.0, 25.0)), valid).clicked() { self.prepare_restore(ui.ctx()); }
					});
				});
				ui.add_space(6.0);
				if self.needs_recovery { ui.colored_label(Color32::from_rgb(150, 80, 0), language.text("前回の処理が未完了です。「元に戻す」で復旧を確認してください。", "A previous operation is incomplete. Choose Restore to review recovery.")); }
				if self.worker.is_some() && self.automatic_generation.is_none() {
					egui::Frame::group(ui.style()).fill(ui.visuals().panel_fill).show(ui, |ui| {
						ui.horizontal_wrapped(|ui| { ui.spinner(); ui.label(&self.progress); if ui_style::button(ui, egui::Button::new(language.text("中断", "Cancel")), self.cancellable && !self.closing).clicked() && let Some(worker) = &self.worker { worker.cancellation.cancel(); } });
						if !self.cancellable { ui.small(language.text("安全のため、完了までお待ちください。", "For safety, please wait until this step completes.")); }
						if self.closing { ui.label(language.text("処理の終了を待ってから画面を閉じます。", "The window will close after processing finishes safely.")); }
					}); ui.ctx().request_repaint_after(Duration::from_millis(80));
				}
				if !self.message.is_empty() { egui::Frame::group(ui.style()).fill(ui.visuals().panel_fill).show(ui, |ui| {
					ui.label(RichText::new(&self.message).color(if self.error { Color32::from_rgb(150, 35, 20) } else { Color32::BLACK }));
					if self.outcome.as_ref().is_some_and(|value| value.restart_required) { ui.label(language.text("この Java を使うアプリを再起動してください。", "Restart applications using this Java.")); }
				}); }
				ui.add_space(6.0);
				ui.small(language.text("対応: Windows x64 / Java 11・17・21・25。Javaのバージョンは変更しません。", "Supports Windows x64 / Java 11, 17, 21 and 25. Your Java version stays the same."));
				ui.add_space(6.0); ui.separator();
				ui.add_enabled_ui(self.worker.is_none() && !self.closing, |ui| { self.draw_results(ui); self.draw_environment_settings(ui); });
			});
		});
		self.pump_auto_check(ui.ctx());
		self.draw_confirmation(ui.ctx());
		#[cfg(feature = "gui-qa")]
		self.qa_tick(ui.ctx());
	}
	//------------------------------------------------------------------------------
	/** 通常closeは応答UIで先に回収し、例外の終了経路でもworkerを放置しません。 */
	//------------------------------------------------------------------------------
	fn on_exit(&mut self) {
		if let Some(worker) = self.worker.take() {
			worker.cancellation.cancel();
			let _panicked = worker.handle.join().is_err();
		}
		#[cfg(feature = "gui-qa")]
		self.qa_exit_log();
	}
}
impl Drop for TrustRepairApp {
	//------------------------------------------------------------------------------
	/** on_exitが呼ばれない破棄でも所有workerを停止・回収します。 */
	//------------------------------------------------------------------------------
	fn drop(&mut self) {
		if let Some(worker) = self.worker.take() {
			worker.cancellation.cancel();
			let _panicked = worker.handle.join().is_err();
		}
	}
}
//------------------------------------------------------------------------------
/** Windows 表示言語で native GUI を開始します。資材確認と明示 QA 以外の引数は拒否します。 */
//------------------------------------------------------------------------------
fn run(language: Language) -> Result<(), String> {
	let arguments: Vec<_> = std::env::args_os().skip(1).collect();
	if arguments.len() == 1 && (arguments[0] == "--help" || arguments[0] == "-h") {
		println!(
			"java-trust-repair [--verify-binary | --help]\nNo arguments: native GUI using the Windows display language."
		);
		return Ok(());
	}
	ensure_supported_target().map_err(|_| {
		language
			.text(
				"Windows x64 MSVC 用のビルドが必要です。",
				"A Windows x64 MSVC build is required.",
			)
			.to_owned()
	})?;
	let policy = embedded_policy().map_err(|_| {
		language
			.text(
				"埋込み対策定義を検証できません。",
				"The embedded policy could not be verified.",
			)
			.to_owned()
	})?;
	if arguments.len() == 1 && arguments[0] == "--verify-binary" {
		println!(
			"Binary verification OK: policy={}, roots={}, font_bytes={}, ui_langid={}; ui_font={}; trust stores were not inspected.",
			policy.id(),
			policy.roots().len(),
			ui_style::JAPANESE_FONT.len(),
			user_ui_language(),
			ui_style::fonts().source
		);
		return Ok(());
	}
	#[cfg(feature = "gui-qa")]
	let preview = qa::Preview::from_arguments(&arguments).map_err(|_| {
		language
			.text("未知の QA 引数です。", "Unknown QA arguments.")
			.to_owned()
	})?;
	#[cfg(not(feature = "gui-qa"))]
	if !arguments.is_empty() {
		return Err(language
			.text(
				"未知の引数です。--help を参照してください。",
				"Unknown arguments. Use --help.",
			)
			.to_owned());
	}
	let options =
		TransactionOptions::local_app_data().map_err(|error| language.transaction_error(&error))?;
	let icon =
		eframe::icon_data::from_png_bytes(include_bytes!("../assets/app.png")).map_err(|_| {
			language
				.text(
					"埋込みアイコンを検証できません。",
					"The embedded icon could not be verified.",
				)
				.to_owned()
		})?;
	let native = eframe::NativeOptions {
		viewport: egui::ViewportBuilder::default()
			.with_icon(icon)
			.with_inner_size([720.0, 400.0])
			.with_min_inner_size([640.0, 360.0]),
		..Default::default()
	};
	eframe::run_native(
		APP_TITLE,
		native,
		Box::new(move |context| {
			let font_source = ui_style::configure(&context.egui_ctx);
			#[cfg(not(feature = "gui-qa"))]
			let _ = font_source;
			let app = TrustRepairApp::new(policy, language, options);
			#[cfg(feature = "gui-qa")]
			let app = qa::configure(app, preview, font_source)?;
			Ok(Box::new(app))
		}),
	).map_err(|_| language.text("ネイティブ画面を開始・維持できません。描画環境とアプリの資材を確認してください。", "The native window could not be started or maintained. Check the graphics environment and application resources.").to_owned())?;
	Ok(())
}

//------------------------------------------------------------------------------
/** 起動失敗も OS 表示言語で案内します。通常 GUI では native dialog、明示 CLI では標準 error を使います。 */
//------------------------------------------------------------------------------
fn main() -> std::process::ExitCode {
	let language = Language::from_langid(user_ui_language());
	match run(language) {
		Ok(()) => std::process::ExitCode::SUCCESS,
		Err(message) => {
			if std::env::args_os().len() == 1 {
				let _answer = rfd::MessageDialog::new()
					.set_title(APP_TITLE)
					.set_description(&message)
					.set_level(rfd::MessageLevel::Error)
					.set_buttons(rfd::MessageButtons::Ok)
					.show();
			} else {
				eprintln!("{message}");
			}
			std::process::ExitCode::FAILURE
		}
	}
}
