//------------------------------------------------------------------------------
/*!
 * - ファイル: main.rs
 * - 概要: 日英の native 画面から診断・適用・復元・未完了復旧を提供します
 * - バージョン: 01.01.00
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
 * Ver.01.01.00  Shunji Ogawa  2026/10/27  CLI から Cargo と一致する製品版数を確認可能にする
 * ```
 *
 * 備考:
 *
 * password を保存・Debug しません。worker の回収前には終了しません
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

/// 初回受信後に制御workerを終了させる、試験時だけの一回限りの同期処理です
#[cfg(test)]
type AfterWorkerDrain = Box<dyn FnOnce(&Worker)>;

/// 秘密入力と明示的な標準値の選択です。Debug・保存を実装しません
struct PasswordInput {
	/// drop 時に消去する編集 buffer
	value: Zeroizing<String>,
	/// 利用者が明示した changeit の使用
	standard: bool,
}
impl PasswordInput {
	//------------------------------------------------------------------------------
	/**
	 * 入力を消費せず、一回のread-only確認だけで使う消去対象の秘密へ複写します。保存・Debugしません
	 *
	 * # Returns
	 *
	 * 入力欄を保持したまま複写した、一回の自動確認用の秘密
	 *
	 * # Errors
	 *
	 * 標準値が未選択で、入力が空・4096 byte 超過・制御文字を含む場合。
	 * 失敗した複写は消去しますが、画面の入力は消費しません
	 */
	//------------------------------------------------------------------------------
	fn snapshot(&self) -> Result<StorePassword, trust_repair_windows::ProcessError> {
		// 標準値の選択を尊重し、手入力の元 buffer は消費せず一回分だけ複写する
		StorePassword::new(if self.standard {
			"changeit".to_owned()
		} else {
			self.value.as_str().to_owned()
		})
	}

	//------------------------------------------------------------------------------
	/**
	 * 未入力・標準値未選択で生成します
	 */
	//------------------------------------------------------------------------------
	fn new() -> Self {
		Self {
			value: Zeroizing::new(String::new()),
			standard: false,
		}
	}

	//------------------------------------------------------------------------------
	/**
	 * マスクと明示 checkbox を描画して編集の有無を返します
	 *
	 * # Arguments
	 *
	 * - `ui`: このフレームの入力欄の描画先
	 * - `language`: checkbox と補足へ用いる表示言語
	 *
	 * # Returns
	 *
	 * 文字列または標準値の選択が変化した場合は `true`。
	 * 標準値の選択を切り替えた場合、編集 buffer を消去します
	 */
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
			// 標準値の選択が変わったら、以後使わない手入力の秘密を消去する
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
	/**
	 * 元 buffer を空にして一回分の秘密へ移動します。失敗時も自動試行しません
	 *
	 * # Returns
	 *
	 * 標準値、または入力欄から移動した一回分の秘密
	 *
	 * # Errors
	 *
	 * 移動した入力が空・4096 byte 超過・制御文字を含む場合。
	 * 移動済みの入力を画面へ戻さず、秘密の所有値を消去します
	 */
	//------------------------------------------------------------------------------
	fn take(&mut self) -> Result<StorePassword, trust_repair_windows::ProcessError> {
		// 標準値のときは固定値を作り、手入力のときだけ元 buffer から秘密を移動する
		StorePassword::new(if self.standard {
			"changeit".to_owned()
		} else {
			std::mem::take(&mut *self.value)
		})
	}
}

/// 明示追加した一件の store と診断入力です
struct StoreInput {
	/// 表示変換を識別へ使わない元 path
	path: PathBuf,
	/// 診断時だけ使う password
	password: PasswordInput,
}

/// 副作用前に一度だけ表示する確認です。診断結果やpasswordを保持しません
enum Confirmation {
	/// 選択した Java と追加ストアの無効化
	Deactivate,
	/// 現物照合した直近履歴の復元・未完了復旧
	Restore(
		/// 現物照合済みの復元候補。確認を受理するまで所有します
		Box<TransactionInspection>,
	),
}

/// 選択した確認範囲の現状です。失敗や警告から無効化済みを推測しません
#[derive(Clone, Copy, PartialEq, Eq)]
enum CurrentStatus {
	/// 未選択、または入力変更後の確認待ちです
	Unknown,
	/// 読み取り確認中です
	Checking,
	/// 完全な群に対象証明書が残っています
	TargetsRemain,
	/// 群全体を検証し、対象4rootを検出しませんでした
	Disabled,
	/// 失敗・警告・変更不可により判定を確定できません
	Unavailable,
}
impl CurrentStatus {
	//------------------------------------------------------------------------------
	/**
	 * 全群の型付きplanから現状を選びます。NoTargetsは全件診断合格後にだけ返る契約です
	 */
	//------------------------------------------------------------------------------
	fn from_plan(plan: &Result<trust_repair_core::ChangePlan, PlanError>) -> Self {
		// 全群成功後の NoTargets だけを無効化済みとし、他の計画失敗を区別する
		match plan {
			Ok(_) => Self::TargetsRemain,
			Err(PlanError::NoTargets) => Self::Disabled,
			Err(_) => Self::Unavailable,
		}
	}
}

/// 一画面の入力と結果、唯一の実行workerを所有します
struct TrustRepairApp {
	/// 埋込み4rootの識別定義
	policy: Policy,
	/// OSから選択した表示言語
	language: Language,
	/// 従来版の履歴だけを参照する本人用root。新規backupには使用しません
	legacy_options: TransactionOptions,
	/// 編集用Javaフォルダ表示
	root_text: String,
	/// dialogで得た元pathと表示値
	picked_root: Option<(PathBuf, String)>,
	/// 入力変更ごとに進める、古い非同期結果を拒否する世代
	input_generation: u64,
	/// 自動確認workerが読んでいる入力世代。手動操作ではNone
	automatic_generation: Option<u64>,
	/// 入力の短い静止後に一度だけ確認する期限
	auto_due: Option<Instant>,
	/// フォルダ欄直下の一行状態
	current_status: CurrentStatus,
	/// 一操作の認証入力。標準値は小補足に明示します
	builtin: [PasswordInput; 2],
	/// 明示追加したストアとその入力
	custom: Vec<StoreInput>,
	/// 結果の詳細。主操作に診断手順を要求しません
	diagnosis: Option<Box<Diagnosis>>,
	/// 詳細内で表示する検査済み履歴
	history: Vec<HistoryEntry>,
	/// 未完了があり復元を優先するか
	needs_recovery: bool,
	/// 一回の変更確認
	confirmation: Option<Confirmation>,
	/// joinするまで所有する唯一のworker
	worker: Option<Worker>,
	/// join前の完了通知
	pending: Option<Result<Completed, Failure>>,
	/// 初回受信直後の終了競合を固定する、試験時だけの一回限りの同期点
	#[cfg(test)]
	after_worker_drain: Option<AfterWorkerDrain>,
	/// 簡潔な実工程の表示
	progress: String,
	/// backendが通知した中断可否
	cancellable: bool,
	/// 通常画面へ表示する短い結果
	message: String,
	/// 詳細でだけ表示する証跡と拒否理由
	error_details: String,
	/// 正常・拒否の見分け
	error: bool,
	/// 最後の検証済み書換え結果
	outcome: Option<TransactionOutcome>,
	/// 安全な終了を待っているか
	closing: bool,
	/// worker回収済みでcloseできるか
	close_ready: bool,
	/// 明示feature/引数だけで有効な自アプリQA
	#[cfg(feature = "gui-qa")]
	qa: Option<qa::Preview>,
}

impl TrustRepairApp {
	//------------------------------------------------------------------------------
	/**
	 * 定義と設定を受け取り、標準password利用を明示する初期画面を作ります。I/Oはworkerで行います
	 *
	 * # Arguments
	 *
	 * - `policy`: DER の照合と表示名に用いる、検証済みの定義
	 * - `language`: 起動時に選択した表示言語
	 * - `legacy_options`: 従来 root の履歴参照と互換復元だけに用いる設定
	 *
	 * # Returns
	 *
	 * 未選択の画面状態。両標準ストアでは標準値の使用を選択済みにします
	 */
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
	/**
	 * dialogで得た非Unicode pathを失わず、選択したJavaを返します
	 */
	//------------------------------------------------------------------------------
	fn selected_root(&self) -> PathBuf {
		self.picked_root
			.as_ref()
			.filter(|(_, shown)| shown == &self.root_text)
			.map(|(path, _)| path.clone())
			.unwrap_or_else(|| PathBuf::from(&self.root_text))
	}

	//------------------------------------------------------------------------------
	/**
	 * 未作成でも表示できる、選択Java内の固定backup rootを返します。I/Oは行いません
	 */
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
	/**
	 * 選択Javaだけの直近履歴から未完了を案内します。従来の未帰属記録は詳細に保全します
	 */
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
	/**
	 * 入力変更で古い診断・確認・結果を破棄します。履歴自体を書き換えません
	 */
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
	/**
	 * 入力世代を進め、古い状態を即時破棄します。実行中の自動確認だけは安全に中断を要求します
	 *
	 * # Arguments
	 *
	 * - `delay`: 今回の入力が静止してから自動確認を開始するまでの待機時間
	 *
	 * # Notes
	 *
	 * 空の Java 入力には予約を作りません。中断要求後も worker は poll で終了回収します
	 */
	//------------------------------------------------------------------------------
	fn schedule_check(&mut self, delay: Duration) {
		self.input_generation = self.input_generation.wrapping_add(1);
		self.current_status = CurrentStatus::Unknown;
		self.diagnosis = None;
		// 空入力には確認を予約せず、入力がある場合だけ新しい期限を作る
		self.auto_due = if self.root_text.trim().is_empty() {
			None
		} else {
			Some(Instant::now() + delay)
		};
		// 入力変更では自動確認だけに中断を要求し、手動の確定処理へ介入しない
		if self.automatic_generation.is_some()
			&& let Some(worker) = &self.worker
		{
			worker.cancellation.cancel();
		}
	}

	//------------------------------------------------------------------------------
	/**
	 * 自動確認用の一時snapshotを作ります。画面のcustom passwordは移動・消去しません
	 *
	 * # Returns
	 *
	 * 入力順に複写した一操作分の認証。未入力・標準値未選択の jssecacerts は `None`
	 *
	 * # Errors
	 *
	 * 必要な入力の一つでも秘密の検証に失敗した場合。途中の複写を消去し、元入力は保持します
	 */
	//------------------------------------------------------------------------------
	fn snapshot_credentials(&self) -> Result<Credentials, trust_repair_windows::ProcessError> {
		let cacerts = self.builtin[0].snapshot()?;
		// 未入力の任意 jssecacerts は不在として保持し、他ストアの秘密を流用しない
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
	/**
	 * 一度の期限到来時だけ既存Scanをworkerへ送り、入力途中や重複実行を避けます
	 *
	 * # Arguments
	 *
	 * - `context`: 予約期限と worker 起動に応じて再描画を要求する画面 context
	 *
	 * # Notes
	 *
	 * 既存 worker・確認画面・close 待機中は開始しません。I/O は起動した worker が行います
	 */
	//------------------------------------------------------------------------------
	fn pump_auto_check(&mut self, context: &egui::Context) {
		// 予約のない通常フレームでは、診断を開始しない
		let Some(due) = self.auto_due else {
			return;
		};
		// 実行中・確認中・終了待機中に、自動診断を重ねて開始しない
		if self.worker.is_some() || self.confirmation.is_some() || self.closing {
			return;
		}
		// 予約時刻までは再描画だけを予約し、UI thread を待機させない
		if due > Instant::now() {
			context.request_repaint_after(due.saturating_duration_since(Instant::now()));
			return;
		}
		self.auto_due = None;
		let generation = self.input_generation;
		// 一時認証の検証に合格した場合だけ worker へ渡し、失敗は同じ世代の結果にする
		match self.snapshot_credentials() {
			Ok(credentials) => {
				self.launch(
					Command::Scan {
						root: self.selected_root(),
						credentials,
					},
					context,
				);
				// 実際に worker が起動した場合だけ、自動確認の世代と確認中表示を保持する
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
	/**
	 * 現入力と同じ世代のread-only結果だけを採用します。古い結果と一時秘密はそのままdropします
	 *
	 * # Arguments
	 *
	 * - `generation`: worker を開始したときの入力世代
	 * - `result`: その世代で完了した読み取り操作の所有結果
	 *
	 * # Notes
	 *
	 * 進捗を消した後、世代が異なれば結果を採用せず破棄します。
	 * 読み取りの失敗を、証明書の無効化完了へ変換しません
	 */
	//------------------------------------------------------------------------------
	fn accept_auto_check(&mut self, generation: u64, result: Result<Completed, Failure>) {
		self.progress.clear();
		// 古い入力世代の完了結果で、現在の選択先や結果表示を上書きしない
		if generation != self.input_generation {
			return;
		}
		// 読み取り結果・失敗・想定外の完了種別を分け、成功状態を推測しない
		match result {
			Ok(Completed::Scan(mut value)) => {
				self.accept_history(std::mem::take(&mut value.history));
				// 未完了履歴があれば、対象ゼロでも新しい変更を許可する状態にしない
				self.current_status = if self.needs_recovery {
					CurrentStatus::Unavailable
				} else {
					CurrentStatus::from_plan(&value.plan)
				};
				// 自動診断でも実際の権限不足は主画面の起動案内へ残す
				if value.needs_administrator() {
					self.message = self.language.administrator_required().to_owned();
					self.error = true;
				}
				self.diagnosis = Some(value);
			}
			Err(value) => {
				let permission = value.needs_administrator();
				self.accept(Err(value));
				// 権限案内以外の自動確認失敗は詳細へ保持し、主画面は限定した判定不能表示にする
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
	/**
	 * フォルダ欄下に確認範囲を限定した一行の状態を表示します
	 */
	//------------------------------------------------------------------------------
	fn draw_current_status(&self, ui: &mut egui::Ui) {
		// 検証済みの現状分類へ色を対応させ、未知・確認中を成功色にしない
		let color = match self.current_status {
			CurrentStatus::Disabled => Color32::from_rgb(25, 110, 60),
			CurrentStatus::TargetsRemain => Color32::from_rgb(150, 80, 0),
			CurrentStatus::Unavailable => Color32::from_rgb(165, 45, 30),
			_ => Color32::from_gray(90),
		};
		ui.horizontal_wrapped(|ui| {
			// 実際に自動確認を実行している期間だけ、動作中の表示を添える
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
	/**
	 * 入力を一回のworkerへ移します。操作終了後に保持する秘密を返しません
	 *
	 * # Returns
	 *
	 * 一操作に移した認証入力。未入力・標準値未選択の jssecacerts は `None`
	 *
	 * # Errors
	 *
	 * 途中の秘密検証が失敗した場合。先に移動した入力は消去し、自動再試行や画面への復元をしません
	 */
	//------------------------------------------------------------------------------
	fn take_credentials(&mut self) -> Result<Credentials, trust_repair_windows::ProcessError> {
		let cacerts = self.builtin[0].take()?;
		// 任意 jssecacerts の未入力は None に保ち、別の秘密を自動試行しない
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
	/**
	 * busy/close待機中は二重開始せず、渡された秘密をdropします
	 *
	 * # Arguments
	 *
	 * - `command`: 一操作の命令と秘密を含む所有入力
	 * - `context`: worker から通知後の再描画を要求する画面 context
	 *
	 * # Notes
	 *
	 * 起動した唯一の worker を終了回収まで所有します。
	 * thread の開始失敗は画面の失敗結果として採用し、渡された秘密を保持しません
	 */
	//------------------------------------------------------------------------------
	fn launch(&mut self, command: Command, context: &egui::Context) {
		// 既存 worker と終了待機を優先し、重複命令の所有入力はそのまま破棄する
		if self.worker.is_some() || self.closing {
			return;
		}
		// 診断や変更を始めるときは、古い自動確認の予約と表示を無効にする
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
		// 開始できた worker だけを保持し、開始失敗を完了成功として扱わない
		match worker::start(command, self.legacy_options.clone(), context.clone()) {
			Ok(worker) => self.worker = Some(worker),
			Err(_) => self.accept(Err(Failure::Interrupted)),
		}
	}

	//------------------------------------------------------------------------------
	/**
	 * 完了済みthreadだけjoinし、回収後の最終通知まで受信して結果を一度だけ採用します。
	 * 実行中はworkerを保持し、panicまたは完了通知欠落だけを予期しない終了へ分類します。
	 * ファイル処理や実行中waitをUIで行いません
	 *
	 * # Notes
	 *
	 * 初回の受信が Empty でも、終了済み thread の join 後に再受信します。
	 * Done の有無と join 成功を両方確認してから、手動結果または入力世代付き結果を採用します
	 */
	//------------------------------------------------------------------------------
	fn poll(&mut self) {
		// worker のないフレームでは、通知回収や完了判定を行わない
		let Some(worker) = self.worker.take() else {
			return;
		};
		self.drain_worker_events(&worker.receiver);
		#[cfg(test)]
		// 試験時だけ初回 Empty 後の同期点を実行し、本番の callback を追加しない
		if let Some(after_drain) = self.after_worker_drain.take() {
			after_drain(&worker);
		}
		// 実行中の thread は join せず所有を戻し、UI の応答を保つ
		if !worker.handle.is_finished() {
			self.worker = Some(worker);
			return;
		}
		let joined = worker.handle.join().is_ok();
		// 初回Emptyの直後に送信されたDoneも、thread回収後なら漏れなく取得できる
		self.drain_worker_events(&worker.receiver);
		// join 成功と Done の受信が両方揃う結果だけを、一回の完了として採用する
		let result = match (joined, self.pending.take()) {
			(true, Some(result)) => result,
			_ => Err(Failure::Interrupted),
		};
		// 自動確認は入力世代を検査する経路へ渡し、手動結果と採用条件を分ける
		if let Some(generation) = self.automatic_generation.take() {
			self.accept_auto_check(generation, result);
		} else {
			self.accept(result);
		}
	}

	//------------------------------------------------------------------------------
	/**
	 * 同じ通知処理で工程・中断可否・完了結果を受信します。実行中threadの通知は待ちません
	 *
	 * # Arguments
	 *
	 * - `receiver`: 画面が所有する現在の worker の通知受信先
	 *
	 * # Notes
	 *
	 * Empty または切断で今回の受信を終了します。Done は pending に保持し、
	 * thread の終了回収が確認されるまで成功結果を確定しません
	 */
	//------------------------------------------------------------------------------
	fn drain_worker_events(&mut self, receiver: &Receiver<Event>) {
		// 現在受信できる通知だけを順に処理し、Empty または切断で今回の受信を終える
		loop {
			// 工程・中断可否・Done を同じ順序で反映し、実行中の通知を待たない
			match receiver.try_recv() {
				Ok(Event::Scan(value)) => {
					self.progress = self.language.simple_scan_phase(value.phase).to_owned();
					self.cancellable = true;
				}
				Ok(Event::Transaction(value)) => {
					#[cfg(feature = "gui-qa")]
					// 明示 QA のときだけ実工程の証跡を残し、通常処理の結果判定へ介入しない
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
	/**
	 * 型付き結果を短い通常表示と専門詳細へ反映します。未完了や切断を成功表示しません
	 *
	 * # Arguments
	 *
	 * - `result`: 終了回収を確認した worker の所有結果
	 *
	 * # Notes
	 *
	 * 主表示・詳細・履歴・復旧要否を型付き結果から更新します。秘密入力は結果保存へ含めません
	 */
	//------------------------------------------------------------------------------
	fn accept(&mut self, result: Result<Completed, Failure>) {
		self.progress.clear();
		// 命令ごとの型付き結果を採用し、途中状態や worker の切断を成功にしない
		match result {
			Ok(Completed::Scan(mut value)) => {
				self.accept_history(std::mem::take(&mut value.history));
				// 診断成功でも未完了履歴がある場合は、復旧の確認を優先する
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
				// 詳細診断の実権限不足も、主画面の管理者起動案内へ反映する
				if value.needs_administrator() {
					self.message = self.language.administrator_required().to_owned();
					self.error = true;
				}
				self.diagnosis = Some(value);
			}
			Ok(Completed::Deactivated { diagnosis, outcome }) => {
				self.history.clear();
				// backend の変更結果がある場合と、対象ゼロ等で変更しなかった場合を分ける
				if let Some(outcome) = outcome {
					self.set_outcome(outcome);
				} else {
					self.current_status = CurrentStatus::from_plan(&diagnosis.plan);
					self.outcome = None;
					self.error = !matches!(diagnosis.plan, Err(PlanError::NoTargets));
					// 全群の対象ゼロ・利用者中断・その他の失敗を区別し、未変更の理由を保持する
					self.message = if matches!(diagnosis.plan, Err(PlanError::NoTargets)) {
						self.language.text(
							"選択したストアに対象証明書はありませんでした。変更はしていません。",
							"No matching certificates were found in the selected stores. Nothing was changed.",
						)
					}
					// 診断が利用者の中断で止まった場合は、対象ゼロの成功と分けて未変更の中断を案内する
					else if diagnosis
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
				// 無効化を始められなかった場合も、実権限不足だけを管理者案内へ反映する
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
					// 履歴の標準ストア以外で、未表示の対象だけを追加入力へ復元する
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
				// 復元の入力範囲が増えた場合は、古い診断世代を破棄して再確認を予約する
				if scope_changed {
					self.schedule_check(Duration::ZERO);
				}
				// 保存時 Java が不変で、適用済みまたは既知の復旧可能状態だけを確認へ渡す
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
				// 履歴の更新で未完了が見つかった場合は、通常の変更可能表示を解除する
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
				// 下位の型付き失敗から詳細を作り、秘密や出力全文を表示へ持ち込まない
				self.error_details = match &failure {
					Failure::Java(value) => self.language.java(value),
					Failure::Process(value) => self.language.process(value),
					Failure::Transaction(value) => self.language.transaction_error(value),
					Failure::Save(kind) => {
						// 既存保存先への衝突は、一般の保存失敗と分けて新しい名前を案内する
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
				// 実権限・中断・秘密未入力・要復旧を優先して、主画面の次の操作を案内する
				self.message = match &failure {
					value if value.needs_administrator() => {
						// 権限案内を出す場合も、未完了変更の復旧要否を失わない
						if matches!(
							value,
							Failure::Transaction(error) if error.state == TransactionState::RecoveryRequired
						) {
							self.needs_recovery = true;
						}
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
	/**
	 * backendが全件検証した状態だけを、無効化・復元の結果として表示します
	 *
	 * # Arguments
	 *
	 * - `outcome`: backend が全件照合した変更結果。画面が所有します
	 */
	//------------------------------------------------------------------------------
	fn set_outcome(&mut self, outcome: TransactionOutcome) {
		// backend が検証した主状態だけを、選択範囲の短い現状へ対応させる
		self.current_status = match outcome.state {
			TransactionState::Applied => CurrentStatus::Disabled,
			TransactionState::Restored
			| TransactionState::AlreadyRestored
			| TransactionState::RolledBack => CurrentStatus::TargetsRemain,
			_ => CurrentStatus::Unavailable,
		};
		self.error = false;
		// 適用・元状態への復元・未完了を区別し、検証結果にない成功文を作らない
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
	/**
	 * 無効化は一度の確認、診断は詳細からだけ開始します。認証をworkerへ移動してUI bufferを空にします
	 *
	 * # Arguments
	 *
	 * - `confirmation`: 画面から取り出した、一回だけ受理する確認内容
	 * - `context`: 一操作の worker 起動と再描画に用いる context
	 *
	 * # Notes
	 *
	 * 認証入力の移動に失敗した場合は失敗表示へ進み、変更 worker を開始しません
	 */
	//------------------------------------------------------------------------------
	fn execute_confirmed(&mut self, confirmation: Confirmation, context: &egui::Context) {
		// 既存 worker や終了待機が始まっていれば、確認の再受理を抑止する
		if self.worker.is_some() || self.closing {
			return;
		}
		// 一操作分の秘密を移動できなければ、変更を開始せず失敗表示へ進む
		let credentials = match self.take_credentials() {
			Ok(value) => value,
			Err(value) => {
				self.accept(Err(Failure::Process(value)));
				return;
			}
		};
		// 受理した確認の種類に従い、新規適用と照合済み履歴の復元を分ける
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
	/**
	 * 選択Javaの直近の現物照合をworkerで行い、一回の復元確認へ進みます
	 */
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
	/**
	 * 通常操作を妨げず、診断・履歴・結果保存を処理結果の折畳へ格納します
	 *
	 * # Arguments
	 *
	 * - `ui`: 診断・履歴・保存操作を表示する、このフレームの描画先
	 *
	 * # Notes
	 *
	 * 選択・保存 dialog は明示操作でだけ表示し、ファイルの診断・履歴取得・保存は worker へ渡します
	 */
	//------------------------------------------------------------------------------
	fn draw_results(&mut self, ui: &mut egui::Ui) {
		let language = self.language;
		#[cfg(feature = "gui-qa")]
		let open = self.qa.as_ref().map(|qa| qa.shows_results());
		#[cfg(not(feature = "gui-qa"))]
		let open = None;
		egui::CollapsingHeader::new(language.text("処理結果", "Results"))
			.open(open)
			.show(ui, |ui| {
				ui.horizontal_wrapped(|ui| {
					// 明示した診断操作に限り、認証入力を一回分の worker へ移す
					if ui_style::button(
						ui,
						egui::Button::new(language.text(
							"変更せず詳しく確認",
							"Inspect without changing files",
						)),
						!self.root_text.is_empty(),
					)
					.clicked()
					{
						// 認証の不正はその場で表示し、診断を自動再試行しない
						match self.take_credentials() {
							Ok(credentials) => self.launch(
								Command::Scan {
									root: self.selected_root(),
									credentials,
								},
								ui.ctx(),
							),
							Err(value) => self.accept(Err(Failure::Process(value))),
						}
					}
					// 入力先がある場合だけ、その Java に対応する履歴を再取得する
					if ui_style::button(
						ui,
						egui::Button::new(language.text("履歴を更新", "Refresh history")),
						!self.root_text.trim().is_empty(),
					)
					.clicked()
					{
						self.launch(
							Command::History {
								root: self.selected_root(),
							},
							ui.ctx(),
						);
					}
					// 保存先の選択を受理した場合だけ、現在の結果を保存 worker へ渡す
					if ui_style::button(
						ui,
						egui::Button::new(language.text("結果を保存…", "Save results…")),
						!self.message.is_empty() || self.diagnosis.is_some(),
					)
					.clicked()
						&& let Some(path) = rfd::FileDialog::new()
							.set_file_name("java-trust-repair-results.txt")
							.save_file()
					{
						self.launch(
							Command::Save {
								path,
								text: self.report(),
							},
							ui.ctx(),
						);
					}
				});
				// 通常表示で省いた失敗の証跡を、結果欄を開いたときに案内する
				if !self.error_details.is_empty() {
					ui.label(&self.error_details);
				}
				// 保持している診断の範囲だけを表示し、未検査のストアへ一般化しない
				if let Some(diagnosis) = &self.diagnosis {
					ui.label(format!(
						"Java {} · {}",
						diagnosis.environment.version(),
						diagnosis.environment.vendor()
					));
					// 計画を作れなかった理由も、診断結果の一部として残す
					if let Err(reason) = &diagnosis.plan {
						ui.label(language.plan(reason));
					}
					// 診断した全ストアについて、入力範囲と抑止理由と対象を順に表示する
					for store in diagnosis.group.stores() {
						ui.separator();
						ui.label(RichText::new(language.status(store.report().status())).strong());
						// 同一実体へ統合した指定パスも、確認範囲から省かない
						for path in store.input_paths() {
							ui.label(path.display().to_string());
						}
						// 全群の変更を止めた理由を診断順に表示する
						for issue in store.report().issues() {
							ui.label(language.issue(*issue));
						}
						// 型付きの下位失敗がある場合は、表示言語に合わせて案内する
						if let Some(value) = store.failure() {
							ui.label(language.failure(value));
						}
						// DER で一致した全別名を表示し、同一証明書の別名も省略しない
						for target in store.report().targets() {
							let name = self
								.policy
								.roots()
								.iter()
								.find(|root| root.id() == target.policy_root_id())
								.map_or(target.policy_root_id(), |root| root.name());
							ui.label(format!("{name} · {}", target.alias()));
							ui.add(
								egui::Label::new(
									RichText::new(target.sha256()).monospace().size(12.0),
								)
								.wrap(),
							);
						}
					}
				}
				ui.separator();
				// 新規保存先は入力済みの Java に対応する固定 root だけを案内する
				if !self.root_text.trim().is_empty() {
					ui.small(self.selected_backup_root().display().to_string());
				}
				// 検証済みの変更結果がある場合だけ、その transaction ID を表示する
				if let Some(value) = &self.outcome {
					ui.label(format!("ID: {}", value.transaction_id));
				}
				// 各履歴の実体照合結果を表示し、個別の不正記録も隠さない
				for entry in &self.history {
					ui.separator();
					ui.small(&entry.transaction_id);
					// 照合できた履歴と、読込み自体を拒否した履歴を区別する
					match &entry.inspection {
						Ok(value) => {
							ui.label(language.history(value.state));
							ui.small(value.backup_directory.display().to_string());
							// 保存時 Java を特定できない旧記録は、復元可能と案内しない
							if value.java_root.as_os_str().is_empty() {
								ui.label(language.text(
									"保存時の Java を特定できません。元の記録を保持し、自動復元は行いません。",
									"The original Java folder cannot be identified. The records are preserved; automatic restoration is unavailable.",
								));
							} else {
								ui.small(value.java_root.display().to_string());
							}
							// manifest 順に対象パスと対応する現物状態を並べる
							for (index, path) in value.stores.iter().enumerate() {
								ui.label(path.display().to_string());
								// 対応する状態がある対象だけに分類を付ける
								if let Some(state) = value.items.get(index) {
									ui.small(language.item(*state));
								}
							}
						}
						Err(value) => {
							ui.label(language.transaction_error(value));
						}
					}
				}
			});
	}

	//------------------------------------------------------------------------------
	/**
	 * 標準passwordを変更した環境と追加ストアだけに必要な入力を、閉じた別欄へ格納します
	 *
	 * # Arguments
	 *
	 * - `ui`: 認証入力と追加ストアを編集する、このフレームの描画先
	 *
	 * # Notes
	 *
	 * 追加ストアの反復中は除外位置だけを保持し、借用終了後に削除します。
	 * 編集があれば既存の診断と確認を無効にし、新しい入力世代の確認を予約します
	 */
	//------------------------------------------------------------------------------
	fn draw_environment_settings(&mut self, ui: &mut egui::Ui) {
		let language = self.language;
		#[cfg(feature = "gui-qa")]
		let open = self.qa.as_ref().map(|qa| qa.shows_settings());
		#[cfg(not(feature = "gui-qa"))]
		let open = None;
		egui::CollapsingHeader::new(language.text(
			"通常と異なる環境の設定",
			"Settings for nonstandard environments",
		))
		.default_open(false)
		.open(open)
		.show(ui, |ui| {
			let mut edited = false;
			ui.label(language.text(
				"通常は設定の変更は不要です。標準パスワードは changeit です。変更している場合だけ入力してください。入力した値は操作終了時に消去します。",
				"These settings are usually unnecessary. The standard password is changeit. Enter a custom password only if it was changed. Entered values are erased after each operation.",
			));
			// 二つの標準ストアの入力を、描画間で衝突しない ID に分けて編集する
			for (index, name) in ["cacerts", "jssecacerts"].into_iter().enumerate() {
				ui.push_id(index, |ui| {
					ui.label(name);
					edited |= self.builtin[index].draw(ui, language);
				});
			}
			let mut remove = None;
			// 追加ストアを入力順に描き、削除する位置だけを反復後へ持ち出す
			for (index, store) in self.custom.iter_mut().enumerate() {
				ui.push_id(("custom", index), |ui| {
					ui.horizontal_wrapped(|ui| {
						ui.label(store.path.display().to_string());
						// 反復中に collection を変更せず、一件の除外要求を記録する
						if ui_style::button(
							ui,
							egui::Button::new(language.text("除外", "Remove")).small(),
							true,
						)
						.clicked()
						{
							remove = Some(index);
						}
					});
					edited |= store.password.draw(ui, language);
				});
			}
			// 反復後に除外し、診断結果の再確認が必要な変更として記録する
			if let Some(index) = remove {
				self.custom.remove(index);
				edited = true;
			}
			// 明示選択を受理したファイルだけを新規の認証入力とともに追加する
			if ui_style::button(
				ui,
				egui::Button::new(language.text("追加の信頼ストア…", "Add a trust store…")),
				true,
			)
			.clicked()
				&& let Some(path) = rfd::FileDialog::new()
					.set_title(language.text("追加の信頼ストア", "Additional trust store"))
					.pick_file()
			{
				self.custom.push(StoreInput {
					path,
					password: PasswordInput {
						value: Zeroizing::new(String::new()),
						standard: true,
					},
				});
				edited = true;
			}
			// 入力が変化した場合だけ、古い診断・確認結果を破棄する
			if edited {
				self.invalidate();
			}
		});
	}

	//------------------------------------------------------------------------------
	/**
	 * 副作用前の一回だけ、対象・自動backup・通信への影響を簡潔に確認します
	 *
	 * # Arguments
	 *
	 * - `context`: 確認 modal と一操作の起動に用いる画面 context
	 *
	 * # Notes
	 *
	 * 描画中は確認内容を借用し、描画終了後に取消または一回の受理を反映します
	 */
	//------------------------------------------------------------------------------
	fn draw_confirmation(&mut self, context: &egui::Context) {
		// 確認待ちでない通常フレームでは modal を作らない
		let Some(confirmation) = &self.confirmation else {
			return;
		};
		let language = self.language;
		let restore = matches!(confirmation, Confirmation::Restore(_));
		let mut run = false;
		let mut cancel = false;
		egui::Modal::new(egui::Id::unique("simple-confirm"))
			.backdrop_color(Color32::from_black_alpha(45))
			.show(context, |ui| {
				ui.set_max_width((context.content_rect().width() - 48.0).min(600.0));
				egui::ScrollArea::vertical()
					.max_height((context.content_rect().height() - 100.0).max(80.0))
					.show(ui, |ui| {
						// 確認中の操作に対応する見出しを選び、適用と復元を混同させない
						ui.heading(if restore {
							language.text("元に戻しますか？", "Restore the original state?")
						} else {
							language.text("証明書を無効化しますか？", "Disable the certificates?")
						});
						ui.add_space(4.0);
						// 復元は照合済み履歴の Java、無効化は現在の選択先を示す
						let path = match confirmation {
							Confirmation::Deactivate => self.selected_root(),
							Confirmation::Restore(value) => value.java_root.clone(),
						};
						ui.label(path.display().to_string());
						// 復元と無効化の副作用を、それぞれの確認時に案内する
						if restore {
							ui.label(language.text(
								"バックアップから元に戻します。無効化した CA への信頼も元に戻ります。",
								"Restore from the backup. This also restores trust in the disabled CAs.",
							));
						} else {
							ui.label(language.text(
								"元に戻せるよう自動でバックアップしてから、対象の証明書だけを無効化します。",
								"A backup is saved automatically before disabling the matching certificates.",
							));
							// 標準ストアに加える明示入力の範囲を、実行前にすべて示す
							for store in &self.custom {
								ui.small(store.path.display().to_string());
							}
							ui.label(language.text(
								"対象 CA を使う通信や署名の検証が失敗する場合があります。対象を使うアプリと同時更新するツールを終了してから実行してください。",
								"Connections or signature checks using these CAs may fail. Close applications and tools that use or update these stores before continuing.",
							));
						}
						// 新規保存先と既存履歴の復元元を、確認する操作に合わせて選ぶ
						let backup = match confirmation {
							Confirmation::Deactivate => self.selected_backup_root(),
							Confirmation::Restore(value) => value.backup_directory.clone(),
						};
						ui.add(
							egui::Label::new(format!(
								"{}: {}",
								language.text("バックアップ", "Backup"),
								backup.display()
							))
							.wrap(),
						);
					});
				ui.add_space(6.0);
				ui.horizontal_wrapped(|ui| {
					// 確認内容を借用している描画中は、取消要求だけを記録する
					if ui_style::button(
						ui,
						egui::Button::new(language.text("キャンセル", "Cancel")),
						true,
					)
					.clicked()
					{
						cancel = true;
					}
					// 同じ確認内容を一度だけ実行へ渡すため、先に受理要求を記録する
					if ui_style::button(
						ui,
						// 実行ボタンも、確認中の適用または復元へ文言を合わせる
						egui::Button::new(if restore {
							language.text("元に戻す", "Restore")
						} else {
							language.text("無効化する", "Disable certificates")
						}),
						true,
					)
					.clicked()
					{
						run = true;
					}
				});
			});
		// 描画時の借用が終わってから、取消された確認を破棄する
		if cancel {
			self.confirmation = None;
		}
		// 残っている確認を取り出すことで、同じ操作の二重受理を防ぐ
		if run && let Some(confirmation) = self.confirmation.take() {
			self.execute_confirmed(confirmation, context);
		}
	}

	//------------------------------------------------------------------------------
	/**
	 * 秘密や外部出力全文を含めず、選択scopeの結果と証跡だけを保存用textへ組み立てます
	 *
	 * # Returns
	 *
	 * 現在の入力範囲・検証結果・履歴の証跡を所有する保存用文字列。ファイル書込みは行いません
	 */
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
		// 入力済みの Java に限り、新規 backup の保存先を結果へ含める
		if !self.root_text.trim().is_empty() {
			text.push_str(&format!(
				"{}: {}\n",
				self.language
					.text("新規バックアップ先", "New backup location"),
				self.selected_backup_root().display()
			));
		}
		// 検証済みの変更結果がある場合だけ、transaction ID と実保存先を記録する
		if let Some(value) = &self.outcome {
			text.push_str(&format!(
				"ID: {}\n{}\n",
				value.transaction_id,
				value.backup_directory.display()
			));
		}
		// 保持している診断の範囲だけを、保存する結果へ含める
		if let Some(value) = &self.diagnosis {
			// 全ストアの状態と入力範囲を順に記録し、部分結果だけを抽出しない
			for store in value.group.stores() {
				text.push_str(&format!(
					"{}\n",
					self.language.status(store.report().status())
				));
				// 同一実体へ統合したパスも、確認範囲の証跡として残す
				for path in store.input_paths() {
					text.push_str(&format!("{}\n", path.display()));
				}
				// 全群の適用を抑止した理由を保存結果へ残す
				for issue in store.report().issues() {
					text.push_str(&format!("{}\n", self.language.issue(*issue)));
				}
				// 一致した全別名と DER ハッシュを記録し、同一証明書の複数出現も保つ
				for target in store.report().targets() {
					text.push_str(&format!("{} · {}\n", target.alias(), target.sha256()));
				}
			}
		}
		// 個別に失敗した履歴も含めて、取得した順序で証跡を組み立てる
		for entry in &self.history {
			text.push_str(&format!("ID: {}\n", entry.transaction_id));
			// 照合済み履歴と読込み失敗を区別し、不明な履歴を成功へ言い換えない
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
	/**
	 * 実行中closeは安全な中断/確定待ちへ変え、回収後にだけcloseを許可します
	 *
	 * # Arguments
	 *
	 * - `context`: close 要求の取得、取消、および回収後の close 通知先
	 *
	 * # Notes
	 *
	 * 実行中の worker がある場合は即時 close を取り消します。
	 * 中断不可の工程では要求を送らず、通常の poll による回収を待ちます
	 */
	//------------------------------------------------------------------------------
	fn handle_close(&mut self, context: &egui::Context) {
		// 実行中の close は取り消し、worker を所有したまま安全な終了待機へ移す
		if context.input(|input| input.viewport().close_requested())
			&& !self.close_ready
			&& self.worker.is_some()
		{
			context.send_viewport_cmd(egui::ViewportCommand::CancelClose);
			self.closing = true;
			// backend が中断可能とした工程だけに中断を要求する
			if self.cancellable
				&& let Some(worker) = &self.worker
			{
				worker.cancellation.cancel();
			}
		}
		// worker の終了回収が終わった場合だけ、保留していた close を許可する
		if self.closing && self.worker.is_none() {
			self.close_ready = true;
			context.send_viewport_cmd(egui::ViewportCommand::Close);
		}
	}
}

impl eframe::App for TrustRepairApp {
	//------------------------------------------------------------------------------
	/**
	 * 主操作を一画面に描画します。結果と特殊な環境の設定は別々に折り畳みます
	 *
	 * # Notes
	 *
	 * [`eframe::App::ui`] のフレーム処理です。通知回収、close 判定、描画、
	 * 予約済みの自動確認、確認 modal の順で処理し、I/O と実行中の終了待ちは worker へ委ねます
	 */
	//------------------------------------------------------------------------------
	fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
		self.poll();
		self.handle_close(ui.ctx());
		let language = self.language;
		egui::CentralPanel::default()
			.frame(egui::Frame::central_panel(ui.style()).inner_margin(12))
			.show(ui, |ui| {
				egui::ScrollArea::vertical()
					.auto_shrink([false, false])
					.show(ui, |ui| {
						ui.heading(language.text("Java の eMudhra 対策", "eMudhra protection for Java"));
						ui.label(language.text(
							"Java フォルダを選ぶと、関連する証明書を無効化できます。必要なときは元に戻せます。",
							"Choose a Java folder to disable the related certificates. You can restore them when needed.",
						));
						ui.add_space(6.0);
						ui.add_enabled_ui(self.worker.is_none() && !self.closing, |ui| {
							ui.label(language.text("Java フォルダ", "Java folder"));
							let mut edited = false;
							let mut committed = false;
							ui.horizontal(|ui| {
								let response = ui.add(
									egui::TextEdit::singleline(&mut self.root_text)
										.desired_width((ui.available_width() - 140.0).max(100.0))
										.hint_text(language.text("Java のインストール先", "Java installation folder")),
								);
								ui_style::text_edit_frame(ui, &response);
								edited |= response.changed();
								committed |= response.lost_focus()
									|| (response.has_focus()
										&& ui.input(|input| input.key_pressed(egui::Key::Enter)));
								// 明示したフォルダ選択を受理したときだけ、元の OS パスも保持する
								if ui_style::button(
									ui,
									egui::Button::new(language.text("フォルダを選ぶ…", "Choose folder…")),
									true,
								)
								.clicked()
									&& let Some(path) = rfd::FileDialog::new()
										.set_title(language.text("Java フォルダを選択", "Select the Java folder"))
										.pick_folder()
								{
									self.root_text = path.display().to_string();
									self.picked_root = Some((path, self.root_text.clone()));
									edited = true;
									committed = true;
								}
							});
							// 編集に対応しない古い診断や確認を、実行に使わせない
							if edited {
								self.invalidate();
							}
							// 入力確定時は待機期限を早めるが、既知状態の重複診断は予約しない
							if committed
								&& self.current_status == CurrentStatus::Unknown
								&& !self.root_text.trim().is_empty()
							{
								self.auto_due = Some(Instant::now());
							}
							self.draw_current_status(ui);
							ui.add_space(6.0);
							ui.horizontal_wrapped(|ui| {
								let valid = !self.root_text.trim().is_empty();
								// 未完了復旧が必要な場合は、新しい適用の確認へ進めない
								if ui_style::button(
									ui,
									egui::Button::new(language.text(
										"eMudhra 関連証明書を無効化",
										"Disable eMudhra-related certificates",
									))
									.min_size(egui::vec2(240.0, 25.0)),
									valid && !self.needs_recovery,
								)
								.clicked()
								{
									self.confirmation = Some(Confirmation::Deactivate);
								}
								// 復元操作では先に現物と履歴を確認し、その後で一回の確認を求める
								if ui_style::button(
									ui,
									egui::Button::new(language.text("元に戻す", "Restore"))
										.min_size(egui::vec2(86.0, 25.0)),
									valid,
								)
								.clicked()
								{
									self.prepare_restore(ui.ctx());
								}
							});
						});
						ui.add_space(6.0);
						// 未完了の履歴がある場合は、主操作より先に復旧の入口を示す
						if self.needs_recovery {
							ui.colored_label(
								Color32::from_rgb(150, 80, 0),
								language.text(
									"前回の処理が未完了です。「元に戻す」で復旧を確認してください。",
									"A previous operation is incomplete. Choose Restore to review recovery.",
								),
							);
						}
						// 手動操作の worker だけを進捗枠へ表示し、終了回収まで再描画を続ける
						if self.worker.is_some() && self.automatic_generation.is_none() {
							egui::Frame::group(ui.style())
								.fill(ui.visuals().panel_fill)
								.show(ui, |ui| {
									ui.horizontal_wrapped(|ui| {
										ui.spinner();
										ui.label(&self.progress);
										// backend が中断可能と通知した工程だけに中断要求を送る
										if ui_style::button(
											ui,
											egui::Button::new(language.text("中断", "Cancel")),
											self.cancellable && !self.closing,
										)
										.clicked()
											&& let Some(worker) = &self.worker
										{
											worker.cancellation.cancel();
										}
									});
									// 確定・復旧中は安全な完了を待つ必要を案内する
									if !self.cancellable {
										ui.small(language.text(
											"安全のため、完了までお待ちください。",
											"For safety, please wait until this step completes.",
										));
									}
									// close 要求後も worker を放置せず、回収待ちを表示する
									if self.closing {
										ui.label(language.text(
											"処理の終了を待ってから画面を閉じます。",
											"The window will close after processing finishes safely.",
										));
									}
								});
							ui.ctx().request_repaint_after(Duration::from_millis(80));
						}
						// 確定した短い結果だけを主画面へ表示する
						if !self.message.is_empty() {
							egui::Frame::group(ui.style())
								.fill(ui.visuals().panel_fill)
								.show(ui, |ui| {
									// エラー結果は色でも区別し、表示する文言は同じ検証結果を使う
									ui.label(RichText::new(&self.message).color(if self.error {
										Color32::from_rgb(150, 35, 20)
									} else {
										Color32::BLACK
									}));
									// backend が要求した変更結果に限り、使用アプリの再起動を案内する
									if self.outcome.as_ref().is_some_and(|value| value.restart_required) {
										ui.label(language.text(
											"この Java を使うアプリを再起動してください。",
											"Restart applications using this Java.",
										));
									}
								});
						}
						ui.add_space(6.0);
						ui.small(language.text(
							"対応: Windows x64 / Java 11・17・21・25。Javaのバージョンは変更しません。",
							"Supports Windows x64 / Java 11, 17, 21 and 25. Your Java version stays the same.",
						));
						ui.add_space(6.0);
						ui.separator();
						ui.add_enabled_ui(self.worker.is_none() && !self.closing, |ui| {
							self.draw_results(ui);
							self.draw_environment_settings(ui);
						});
					});
			});
		self.pump_auto_check(ui.ctx());
		self.draw_confirmation(ui.ctx());
		#[cfg(feature = "gui-qa")]
		self.qa_tick(ui.ctx());
	}

	//------------------------------------------------------------------------------
	/**
	 * 通常closeは応答UIで先に回収し、例外の終了経路でもworkerを放置しません
	 */
	//------------------------------------------------------------------------------
	fn on_exit(&mut self) {
		// 通常 UI の回収経路を外れた終了でも、所有 worker を停止して join する
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
	/**
	 * on_exitが呼ばれない破棄でも所有workerを停止・回収します
	 */
	//------------------------------------------------------------------------------
	fn drop(&mut self) {
		// on_exit が呼ばれなかった破棄でも、所有 worker を残さず回収する
		if let Some(worker) = self.worker.take() {
			worker.cancellation.cancel();
			let _panicked = worker.handle.join().is_err();
		}
	}
}

//------------------------------------------------------------------------------
/**
 * Windows 表示言語で native GUI を開始します。版数・使用方法・資材確認と明示 QA に対応します
 *
 * # Arguments
 *
 * - `language`: 起動失敗の通知にも使用する OS 由来の表示言語
 *
 * # Errors
 *
 * 引数・対象ビルド・埋込み定義・保存先設定・アイコン・native 画面の初期化に失敗した場合。
 * 明示 QA の設定失敗も同じ境界へ返します
 *
 * # Notes
 *
 * 通常は native のイベント処理が終了するまで戻りません。CLI の確認だけなら画面を開きません
 */
//------------------------------------------------------------------------------
fn run(language: Language) -> Result<(), String> {
	let arguments: Vec<_> = std::env::args_os().skip(1).collect();
	// 明示の版数確認は、Java の走査や native 画面の生成前に返す
	if arguments.len() == 1 && (arguments[0] == "--version" || arguments[0] == "-V") {
		println!("java-trust-repair {}", env!("CARGO_PKG_VERSION"));
		return Ok(());
	}
	// 明示の help 操作だけは、native 画面を作らず使用方法を返す
	if arguments.len() == 1 && (arguments[0] == "--help" || arguments[0] == "-h") {
		println!(
			"java-trust-repair {}\nUsage: java-trust-repair [--version | --verify-binary | --help]\nNo arguments: native GUI using the Windows display language.",
			env!("CARGO_PKG_VERSION")
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
	// 明示の資材確認では、信頼ストアを診断せず埋込み定義と font を確認する
	if arguments.len() == 1 && arguments[0] == "--verify-binary" {
		println!(
			"Binary verification OK: version={}, policy={}, roots={}, font_bytes={}, ui_langid={}; ui_font={}; trust stores were not inspected.",
			env!("CARGO_PKG_VERSION"),
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
	// 通常版は未知引数を拒否し、QA の動作を暗黙に開始しない
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
	)
	.map_err(|_|
		language
			.text(
				"ネイティブ画面を開始・維持できません。描画環境とアプリの資材を確認してください。",
				"The native window could not be started or maintained. Check the graphics environment and application resources.",
			)
			.to_owned()
	)?;
	Ok(())
}

//------------------------------------------------------------------------------
/**
 * 起動失敗を OS 表示言語で案内します。
 * 通常 GUI は native dialog、明示 CLI は標準 error を使用します
 *
 * # Returns
 *
 * 通常終了または明示確認の成功なら SUCCESS、起動処理に失敗した場合は FAILURE
 */
//------------------------------------------------------------------------------
fn main() -> std::process::ExitCode {
	let language = Language::from_langid(user_ui_language());
	// 起動処理の成否を終了コードへ対応させ、失敗の文脈を利用者へ返す
	match run(language) {
		Ok(()) => std::process::ExitCode::SUCCESS,
		Err(message) => {
			// 通常起動の失敗は native dialog、明示 CLI の失敗は標準 error へ案内する
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
