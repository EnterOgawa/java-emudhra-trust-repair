//------------------------------------------------------------------------------
/*!
 * - ファイル: language.rs
 * - 概要: 日英の画面文言と backend の型付き判定を一か所で翻訳します
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
 * Display や外部自由文から分岐しません。実名・path・alias・hash は値のままです
 */
//------------------------------------------------------------------------------

use trust_repair_core::{InventoryErrorCode, IssueCode, PlanError, ScanStatus};
use trust_repair_windows::{
	FileSafetyError, HistoryState, ItemState, JavaError, ProcessError, ScanFailure, ScanPhase,
	TransactionCode, TransactionError, TransactionPhase, TransactionState,
};

/// 一度選択した画面全体の言語です
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Language {
	/// 日本語表示です
	Japanese,
	/// 日本語以外の Windows 表示言語に用いる英語です
	English,
}

impl Language {
	//------------------------------------------------------------------------------
	/**
	 * 実権限不足のとき主画面にも表示する、手動での管理者起動案内です
	 */
	//------------------------------------------------------------------------------
	pub fn administrator_required(self) -> &'static str {
		self.text(
			"権限が不足しています。このアプリを閉じ、右クリックの「管理者として実行」で起動し直してください。",
			"Insufficient permissions. Close this app, then right-click it and choose \"Run as administrator\" to start it again.",
		)
	}

	//------------------------------------------------------------------------------
	/**
	 * 確認範囲だけの現状を日英化します。判定失敗を無効化済みと表示しません
	 */
	//------------------------------------------------------------------------------
	pub fn current_status(self, value: crate::CurrentStatus, selected: bool) -> &'static str {
		// 選択範囲の状態だけを文言へ対応させ、未選択と判定不能も区別する
		match value {
			crate::CurrentStatus::Unknown if !selected => {
				self.text("フォルダ未選択", "No folder selected")
			}
			crate::CurrentStatus::Unknown => self.text("確認待ち…", "Waiting to check…"),
			crate::CurrentStatus::Checking => self.text(
				"現在の状態を確認しています…",
				"Checking the current status…",
			),
			crate::CurrentStatus::TargetsRemain => self.text(
				"未無効化（対象証明書が残っています）",
				"Not disabled · matching certificates remain",
			),
			crate::CurrentStatus::Disabled => self.text(
				"無効化済み（選択したストアの確認範囲）",
				"Disabled · within the checked stores only",
			),
			crate::CurrentStatus::Unavailable => self.text(
				"判定不可（処理結果をご確認ください）",
				"Unable to determine status · see Results",
			),
		}
	}

	//------------------------------------------------------------------------------
	/**
	 * 診断の専門工程を、通常操作で必要な短い案内へ変換します
	 */
	//------------------------------------------------------------------------------
	pub fn simple_scan_phase(self, _value: ScanPhase) -> &'static str {
		self.text(
			"対象の証明書を確認しています…",
			"Checking for matching certificates…",
		)
	}

	//------------------------------------------------------------------------------
	/**
	 * backend の工程から、通常操作向けの進捗を選びます。詳細は元の型を維持します
	 */
	//------------------------------------------------------------------------------
	pub fn simple_phase(self, value: TransactionPhase) -> &'static str {
		// 実際の transaction 工程を、通常操作で必要な短い進捗へ対応させる
		match value {
			TransactionPhase::Backup => self.text(
				"元に戻せるよう保存しています…",
				"Saving a backup for restoration…",
			),
			TransactionPhase::Stage => {
				self.text("証明書を無効化しています…", "Disabling the certificates…")
			}
			TransactionPhase::Restore | TransactionPhase::Recovery | TransactionPhase::Rollback => {
				self.text("元の状態へ戻しています…", "Restoring the original state…")
			}
			TransactionPhase::Commit | TransactionPhase::Verify | TransactionPhase::Complete => {
				self.text(
					"変更を反映・確認しています…",
					"Applying and checking the changes…",
				)
			}
			TransactionPhase::History => self.text(
				"元に戻せる変更を確認しています…",
				"Checking changes available to restore…",
			),
			_ => self.text("変更を準備しています…", "Preparing the changes…"),
		}
	}

	//------------------------------------------------------------------------------
	/**
	 * LANGID の主言語が日本語なら日本語、それ以外は英語を返します。OS を変更しません
	 */
	//------------------------------------------------------------------------------
	pub fn from_langid(id: u16) -> Self {
		// 地域差を除いた主言語で日本語を選び、未知の言語も英語へ戻す
		if id & 0x03ff == 0x11 {
			Self::Japanese
		} else {
			Self::English
		}
	}

	//------------------------------------------------------------------------------
	/**
	 * 同じ意味の静的な日英文言から、起動時に決めた言語を借用して返します
	 *
	 * # Arguments
	 *
	 * - `japanese`: 日本語表示時に選ぶ文言
	 * - `english`: それ以外の表示時に選ぶ文言
	 *
	 * # Returns
	 *
	 * 渡された二つの文言の片方を、入力と同じ寿命で借用して返します
	 */
	//------------------------------------------------------------------------------
	pub fn text<'a>(self, japanese: &'a str, english: &'a str) -> &'a str {
		// 起動時に決まった言語の文言だけを借用し、元の文字列を変更しない
		match self {
			Self::Japanese => japanese,
			Self::English => english,
		}
	}

	//------------------------------------------------------------------------------
	/**
	 * 診断状態を対象範囲の限定された表示へ変換します
	 */
	//------------------------------------------------------------------------------
	pub fn status(self, value: ScanStatus) -> &'static str {
		// 診断の状態分類を表示へ対応させ、部分失敗を成功の文言へ変換しない
		let (ja, en) = match value {
			ScanStatus::TargetsFound => ("対象検出", "Targets found"),
			ScanStatus::NoTargets => ("対象未検出（このファイル）", "No targets in this file"),
			ScanStatus::NotModifiable => ("要確認・変更不可", "Review required · changes blocked"),
			ScanStatus::Failed => ("診断失敗", "Diagnosis failed"),
		};
		self.text(ja, en)
	}

	//------------------------------------------------------------------------------
	/**
	 * 群全体の変更を止める型付き理由を翻訳します
	 */
	//------------------------------------------------------------------------------
	pub fn issue(self, value: IssueCode) -> &'static str {
		// 全群の変更を止めた型付き理由を、利用者向けの言語へ対応させる
		let (ja, en) = match value {
			IssueCode::UnsupportedJava => (
				"対応する Windows x64 Java 11/17/21/25 ではありません。",
				"Requires supported Windows x64 Java 11/17/21/25.",
			),
			IssueCode::UnsafeFile => (
				"通常のローカル NTFS ファイルの条件を満たしません。",
				"Local NTFS regular-file requirements were not met.",
			),
			IssueCode::MetadataUnavailable => (
				"保持するセキュリティ情報を取得できません。",
				"Required security metadata could not be read.",
			),
			IssueCode::ChangedDuringScan => (
				"診断中にファイルが変わりました。再診断してください。",
				"Files changed during diagnosis. Diagnose again.",
			),
			IssueCode::NameCollision => (
				"対象に似た名前で DER が異なる証明書があります。",
				"A similarly named certificate has a different DER hash.",
			),
			IssueCode::KeyMaterial => (
				"秘密鍵または対称鍵を含むため変更できません。",
				"Changes blocked because the store contains private or secret keys.",
			),
			IssueCode::KeytoolWarning => (
				"keytool の警告があるため変更できません。",
				"Changes blocked because keytool returned a warning.",
			),
			IssueCode::ProcessFailure => (
				"Java/keytool の実行を検証できません。",
				"Java/keytool execution could not be verified.",
			),
			IssueCode::InvalidInventory => (
				"完全な証明書一覧を検証できません。",
				"The complete certificate inventory could not be verified.",
			),
			IssueCode::MissingStore => (
				"必須ストアがありません。",
				"A required trust store is missing.",
			),
			IssueCode::Cancelled => ("診断を中断しました。", "Diagnosis cancelled."),
		};
		self.text(ja, en)
	}

	//------------------------------------------------------------------------------
	/**
	 * 適用不可を成功へ言い換えず、型付き計画理由を翻訳します
	 */
	//------------------------------------------------------------------------------
	pub fn plan(self, value: &PlanError) -> &'static str {
		// 対象ゼロと入力不備・群の失敗を、それぞれの計画理由として区別する
		let (ja, en) = match value {
			PlanError::EmptySelection => ("ストアが選択されていません。", "No stores selected."),
			PlanError::Blocked { .. } => (
				"失敗または要確認のストアがあるため全群の適用を禁止します。",
				"The entire group is blocked by a failed or review-required store.",
			),
			PlanError::PolicyMismatch => (
				"診断の対策定義が一致しません。再診断してください。",
				"Policy mismatch. Diagnose again.",
			),
			PlanError::NoTargets => (
				"今回確認したファイルに対象はありません。変更は不要です。",
				"No targets in the inspected files. No changes are needed.",
			),
		};
		self.text(ja, en)
	}

	//------------------------------------------------------------------------------
	/**
	 * 適用・復元の実工程を翻訳します
	 */
	//------------------------------------------------------------------------------
	pub fn phase(self, value: TransactionPhase) -> &'static str {
		// backend の実工程を翻訳し、推測した進捗を表示しない
		let (ja, en) = match value {
			TransactionPhase::Validate => (
				"診断と現在の実体を再検証",
				"Revalidating diagnosis and current files",
			),
			TransactionPhase::Lock => (
				"排他と変更権限を確認",
				"Locking stores and checking permissions",
			),
			TransactionPhase::Backup => (
				"新規バックアップを保存・検証",
				"Saving and verifying a new backup",
			),
			TransactionPhase::Stage => (
				"作業コピーで削除・全件検証",
				"Removing targets in staged copies and verifying all entries",
			),
			TransactionPhase::Prepare => {
				("復元用記録を固定", "Saving the immutable recovery manifest")
			}
			TransactionPhase::Journal => ("処理記録を永続化", "Persisting the transaction journal"),
			TransactionPhase::Commit => ("検証済みファイルを確定", "Committing verified files"),
			TransactionPhase::Verify => ("実ファイルを再検証", "Verifying committed files"),
			TransactionPhase::Rollback => (
				"途中の変更を戻して検証",
				"Rolling back and verifying partial changes",
			),
			TransactionPhase::Restore => (
				"元の内容を復元・検証",
				"Restoring and verifying original contents",
			),
			TransactionPhase::History => (
				"履歴と現在の実体を照合",
				"Inspecting history and current files",
			),
			TransactionPhase::Recovery => (
				"未完了の既知状態から復旧",
				"Recovering an incomplete transaction from known evidence",
			),
			TransactionPhase::Complete => ("全件処理終了", "All items finished"),
		};
		self.text(ja, en)
	}

	//------------------------------------------------------------------------------
	/**
	 * 検証済みの主状態を翻訳し、未完了を成功表示しません
	 */
	//------------------------------------------------------------------------------
	pub fn state(self, value: TransactionState) -> &'static str {
		// 検証済みの主状態を翻訳し、未完了と完全復旧の意味を保つ
		let (ja, en) = match value {
			TransactionState::Aborted => (
				"元対象の変更前に終了",
				"Stopped before changing original stores",
			),
			TransactionState::Prepared => ("準備済み・未完了", "Prepared · incomplete"),
			TransactionState::Committing => ("確定中・未完了", "Committing · incomplete"),
			TransactionState::Applied => ("適用・全件検証完了", "Applied and fully verified"),
			TransactionState::RollingBack => ("巻き戻し中・未完了", "Rolling back · incomplete"),
			TransactionState::RolledBack => (
				"変更前への巻き戻し検証済み",
				"Rollback to original contents verified",
			),
			TransactionState::Restoring => ("復元中・未完了", "Restoring · incomplete"),
			TransactionState::Restored => (
				"元の内容へ復元・全件検証完了",
				"Original contents restored and fully verified",
			),
			TransactionState::AlreadyRestored => (
				"既に元の内容です（書換えなし）",
				"Already original · no files rewritten",
			),
			TransactionState::RecoveryRequired => (
				"復旧要確認・自動上書き禁止",
				"Recovery requires review · automatic overwrite blocked",
			),
		};
		self.text(ja, en)
	}

	//------------------------------------------------------------------------------
	/**
	 * 履歴と現物の照合結果を翻訳します
	 */
	//------------------------------------------------------------------------------
	pub fn history(self, value: HistoryState) -> &'static str {
		// 保存履歴と現物の照合状態を、そのまま利用者向けの案内へ対応させる
		let (ja, en) = match value {
			HistoryState::Applied => ("適用済み", "Applied"),
			HistoryState::Restored => ("復元済み", "Restored"),
			HistoryState::RolledBack => ("巻き戻し済み", "Rolled back"),
			HistoryState::Recoverable => ("未完了・復旧可能", "Incomplete · recoverable"),
			HistoryState::RecoveryRequired => (
				"復旧要確認・上書き不可",
				"Recovery requires review · overwrite blocked",
			),
			HistoryState::IncompletePreparation => (
				"準備未完了・対象を推測しません",
				"Preparation incomplete · targets will not be guessed",
			),
			HistoryState::Invalid => (
				"記録不正・上書き不可",
				"Invalid records · overwrite blocked",
			),
		};
		self.text(ja, en)
	}

	//------------------------------------------------------------------------------
	/**
	 * 復元対象の現物状態を翻訳します
	 */
	//------------------------------------------------------------------------------
	pub fn item(self, value: ItemState) -> &'static str {
		// 元・適用後・欠落・未知の分類を保ち、復元可能性を文言から推測しない
		let (ja, en) = match value {
			ItemState::Original => ("元の内容", "Original contents"),
			ItemState::Applied => ("適用後の内容", "Applied contents"),
			ItemState::Missing => ("ファイル欠落", "File missing"),
			ItemState::Unknown => ("内容・属性不明", "Unknown contents or metadata"),
		};
		self.text(ja, en)
	}

	//------------------------------------------------------------------------------
	/**
	 * 安定した transaction 分類を翻訳します
	 */
	//------------------------------------------------------------------------------
	pub fn code(self, value: TransactionCode) -> &'static str {
		// 安定した失敗 code を翻訳し、外部出力本文に依存しない案内を作る
		let (ja, en) = match value {
			TransactionCode::Busy => (
				"別のアプリが対象を操作しています。",
				"Another application is operating on these stores.",
			),
			TransactionCode::Cancelled => ("確定前に中断しました。", "Cancelled before commit."),
			TransactionCode::InvalidPlan => (
				"診断・計画・パスワード数が一致しません。",
				"Diagnosis, plan or password count does not match.",
			),
			TransactionCode::StaleJava => (
				"Java が変わりました。再選択・再診断が必要です。",
				"Java changed. Select and diagnose it again.",
			),
			TransactionCode::BackupLocationMismatch => (
				"バックアップの保存時と Java フォルダが異なります。移動・コピーした記録からの自動復元はできません。元の場所と記録を保持してください。",
				"The Java folder differs from the backup's original location. Moved or copied records cannot be restored automatically. Preserve the original location and records.",
			),
			TransactionCode::StaleScan => (
				"診断後にファイルが変わりました。再診断が必要です。",
				"Stores changed since diagnosis. Diagnose again.",
			),
			TransactionCode::UnsafeFile => (
				"ファイルの安全性条件を満たしません。",
				"File safety requirements were not met.",
			),
			TransactionCode::UnsupportedMetadata => (
				"SACL 等の追加情報の不存在・保持を確認できません。",
				"The absence or preservation of additional metadata such as SACL could not be verified.",
			),
			TransactionCode::PermissionDenied => return self.administrator_required(),
			TransactionCode::Io => (
				"ファイル操作・永続化に失敗しました。",
				"File I/O or persistence failed.",
			),
			TransactionCode::Keytool => (
				"keytool の実行・一覧を検証できません。パスワードも確認してください。",
				"Keytool execution or inventory could not be verified. Check the password as well.",
			),
			TransactionCode::VerificationFailed => (
				"全件・形式・属性の照合に失敗しました。",
				"Inventory, format or metadata verification failed.",
			),
			TransactionCode::InvalidManifest => (
				"復元記録の形式・パス・整合性が不正です。",
				"Manifest schema, paths or consistency are invalid.",
			),
			TransactionCode::InvalidJournal => (
				"処理記録の順序・状態が不正です。",
				"Journal sequence or state is invalid.",
			),
			TransactionCode::BackupCorrupt => (
				"バックアップのハッシュが一致しません。",
				"The backup hash does not match.",
			),
			TransactionCode::ExternalChange => (
				"外部変更を検出しました。上書きしません。",
				"External changes detected. Files will not be overwritten.",
			),
			TransactionCode::RecoveryRequired => (
				"一意に復旧できません。記録と現物を保全してください。",
				"Recovery is ambiguous. Preserve records and files for review.",
			),
			TransactionCode::InjectedFailure => (
				"隔離試験用の指定境界で失敗しました。",
				"An isolated test failure was injected.",
			),
		};
		self.text(ja, en)
	}

	//------------------------------------------------------------------------------
	/**
	 * 階層を失わず主失敗・状態・rollback 原因を翻訳し、秘密は含めません
	 */
	//------------------------------------------------------------------------------
	pub fn transaction_error(self, value: &TransactionError) -> String {
		let mut text = format!(
			"{}\n{} · {}",
			self.code(value.code),
			self.phase(value.phase),
			self.state(value.state)
		);
		// 対象パスが判明している場合だけ、詳細へその場所を添える
		if let Some(path) = &value.path {
			text.push_str(&format!("\n{}", path.display()));
		}
		// 保存されている実 OS code を添え、主分類だけで下位原因を失わない
		if let Some(code) = value.os_code {
			text.push_str(&format!("\nWindows: {code}"));
		}
		// transaction の記録がある場合だけ、復旧履歴の識別子を添える
		if let Some(id) = &value.transaction_id {
			text.push_str(&format!("\nID: {id}"));
		}
		// 子の実行失敗を保持している場合は、その型付き理由を補足する
		if let Some(error) = &value.process_error {
			text.push_str(&format!("\n{}", self.process(error)));
		}
		// file の安全性検査の失敗を、元の分類のまま詳細へ添える
		if let Some(error) = &value.file_error {
			text.push_str(&format!("\n{}", self.file(error)));
		}
		// Java の選択・再照合の下位失敗を補足する
		if let Some(error) = &value.java_error {
			text.push_str(&format!("\n{}", self.java(error)));
		}
		// 診断の下位失敗を補足し、計画の主分類だけに縮約しない
		if let Some(error) = &value.scan_error {
			text.push_str(&format!("\n{}", self.failure(error)));
		}
		// 元の計画理由がある場合だけ、全群を止めた条件を補足する
		if let Some(error) = &value.plan_error {
			text.push_str(&format!("\n{}", self.plan(error)));
		}
		// 対象位置がある場合は利用者向けの 1 始まりへ変換し、群の失敗と区別する
		if let Some(item) = value.item {
			text.push_str(&format!(
				"\n{}: {}",
				self.text("ストア順", "Store position"),
				item + 1
			));
		}
		// 置換後の全残存証拠を列挙し、未知や欠落の判断材料を残す
		for evidence in &value.evidence {
			text.push_str(&format!(
				"\n{}: {}",
				self.text("確認した実体", "Inspected artifact"),
				evidence.path.display()
			));
			// 取得できた実体だけにハッシュを表示し、失敗した取得の値を捏造しない
			if let Some(hash) = &evidence.sha256 {
				text.push_str(&format!("\nSHA-256: {hash}"));
			}
			// 証拠の取得失敗も同じパスに結び付けて案内する
			if let Some(error) = &evidence.failure {
				text.push_str(&format!("\n{}", self.file(error)));
			}
		}
		// 主原因と別に全 rollback 失敗を表示し、復旧失敗で最初の原因を上書きしない
		for error in &value.rollback_errors {
			text.push_str(&format!(
				"\n{}: {}",
				self.text("復旧失敗", "Rollback failure"),
				self.transaction_error(error)
			));
		}
		text
	}

	//------------------------------------------------------------------------------
	/**
	 * Java 選択の原因を型から翻訳します
	 */
	//------------------------------------------------------------------------------
	pub fn java(self, value: &JavaError) -> String {
		// Java の選択理由を型から翻訳し、vendor 等の自己申告を安全保証へ変換しない
		match value {
			JavaError::File(error) => self.file(error),
			JavaError::Process(error) => self.process(error),
			JavaError::UnsupportedTarget => self
				.text(
					"Windows x64 MSVC ビルドが必要です。",
					"A Windows x64 MSVC build is required.",
				)
				.to_owned(),
			JavaError::InvalidRelease => self
				.text(
					"release の形式・必須項目が不正です。",
					"The release file has invalid structure or missing fields.",
				)
				.to_owned(),
			JavaError::InvalidExecutable => self
				.text(
					"Windows x64 の実行ファイルではありません。",
					"The executable is not Windows x64.",
				)
				.to_owned(),
			JavaError::MetadataMismatch => self
				.text(
					"release と実行中 Java の情報が一致しません。",
					"The release file and running Java metadata do not match.",
				)
				.to_owned(),
		}
	}

	//------------------------------------------------------------------------------
	/**
	 * パスワード・子プロセスの失敗を全文や秘密なしで翻訳します
	 */
	//------------------------------------------------------------------------------
	pub fn process(self, value: &ProcessError) -> String {
		// 秘密入力・実行・容量・中断の各理由を分け、子の出力全文は含めない
		let (ja, en) = match value {
			ProcessError::InvalidPassword => (
				"パスワードが未入力、長すぎる、または制御文字を含みます。",
				"Password is empty, too long, or contains control characters.",
			),
			ProcessError::Io { .. } => (
				"Java プロセスの OS 操作に失敗しました。",
				"An OS operation on the Java process failed.",
			),
			ProcessError::Unsuccessful { .. } => (
				"keytool/Java が失敗しました。パスワードとファイルを確認してください。",
				"Keytool/Java failed. Check the password and selected files.",
			),
			ProcessError::InvalidUtf8 => (
				"実行結果が厳密な UTF-8 ではありません。",
				"Process output is not valid UTF-8.",
			),
			ProcessError::OutputLimit => (
				"実行結果が容量上限を超えました。",
				"Process output exceeded its size limit.",
			),
			ProcessError::Timeout => (
				"120 秒で時間切れとなり、子を終了・回収しました。",
				"The 120-second timeout expired; the child process was stopped and reaped.",
			),
			ProcessError::Cancelled => (
				"中断し、子を終了・回収しました。",
				"Cancelled; the child process was stopped and reaped.",
			),
			ProcessError::Cleanup { .. } => (
				"子プロセスの終了・回収に失敗しました。",
				"Stopping or reaping the child process failed.",
			),
		};
		let mut text = self.text(ja, en).to_owned();
		// I/O の OS code と異常終了の code を、対応する原因にだけ添える
		match value {
			ProcessError::Io {
				os_code: Some(code),
				..
			} => text.push_str(&format!(" (Windows: {code})")),
			ProcessError::Unsuccessful {
				exit_code: Some(code),
			} => text.push_str(&format!(" ({code})")),
			ProcessError::Cleanup { cause, .. } => {
				text.push_str(&format!("\n{}", self.process(cause)))
			}
			_ => {}
		}
		text
	}

	//------------------------------------------------------------------------------
	/**
	 * 実体と属性の拒否理由を型から翻訳します
	 */
	//------------------------------------------------------------------------------
	pub fn file(self, value: &FileSafetyError) -> String {
		// file の仕様非対応・内容変化・実 I/O 失敗を区別して案内する
		let (ja, en) = match value {
			FileSafetyError::UnsupportedPath => (
				"対応する絶対ローカルパスではありません。",
				"An absolute supported local path is required.",
			),
			FileSafetyError::ReparsePoint => (
				"リンクまたは祖先の再解析ポイントを拒否しました。",
				"A link or ancestor reparse point was rejected.",
			),
			FileSafetyError::NotLocalNtfs => (
				"ローカル固定 NTFS ではありません。",
				"The volume is not local fixed NTFS.",
			),
			FileSafetyError::NotRegularFile => (
				"通常ファイルではありません。",
				"This is not a regular file.",
			),
			FileSafetyError::MultipleLinks => (
				"複数のハードリンクを持つファイルを拒否しました。",
				"A file with multiple hard links was rejected.",
			),
			FileSafetyError::UnsupportedAttributes { .. } => (
				"読み取り専用・圧縮・暗号化等の未対応属性です。",
				"Unsupported attributes such as read-only, compression or encryption were found.",
			),
			FileSafetyError::NamedStreams => (
				"通常でない追加ストリームを拒否しました。",
				"Nonstandard additional streams were rejected.",
			),
			FileSafetyError::TooLarge => (
				"ファイルが容量上限を超えます。",
				"The file exceeds the size limit.",
			),
			FileSafetyError::Changed => (
				"実体・内容・属性が変わりました。再診断してください。",
				"Identity, contents or metadata changed. Diagnose again.",
			),
			FileSafetyError::Io { .. } => (
				"ファイルを読み取れないか、属性を取得できません。",
				"The file or its metadata could not be read.",
			),
		};
		let mut text = self.text(ja, en).to_owned();
		// 実 OS code のある I/O 失敗に限り、診断へその code を添える
		if let FileSafetyError::Io {
			os_code: Some(code),
			..
		} = value
		{
			text.push_str(&format!(" (Windows: {code})"));
		}
		text
	}

	//------------------------------------------------------------------------------
	/**
	 * 全一覧の詳細を型付きで翻訳します。開発用 reason は UI に使いません
	 */
	//------------------------------------------------------------------------------
	pub fn failure(self, value: &ScanFailure) -> String {
		// 診断の下位分類を保ち、自由文 reason に依存せず表示する
		match value {
			ScanFailure::File(value) => self.file(value),
			ScanFailure::Java(value) => self.java(value),
			ScanFailure::Process(value) => self.process(value),
			ScanFailure::Inventory(value) => {
				// RFC 解析の失敗分類を、対象の出力本文を含めず案内する
				let (ja, en) = match value.code {
					InventoryErrorCode::InputLimit => (
						"一覧が容量上限を超えます。",
						"Inventory exceeds the size limit.",
					),
					InventoryErrorCode::Encoding => (
						"一覧の文字コードが不正です。",
						"Inventory encoding is invalid.",
					),
					InventoryErrorCode::Structure => (
						"一覧の構造・件数・DER を検証できません。",
						"Inventory structure, counts or DER could not be verified.",
					),
				};
				format!(
					"{} ({}: {})",
					self.text(ja, en),
					self.text("行", "line"),
					value.line
				)
			}
			ScanFailure::UnrecognizedStderr => self
				.text(
					"未知の警告・出力を受け取りました。",
					"Unrecognized warning or error output was received.",
				)
				.to_owned(),
			ScanFailure::FormatMismatch => self
				.text(
					"ファイルと一覧の形式が一致しません。",
					"File and inventory formats do not match.",
				)
				.to_owned(),
			ScanFailure::InventoryChanged => self
				.text(
					"二回の一覧が一致しません。再診断してください。",
					"Repeated inventories do not match. Diagnose again.",
				)
				.to_owned(),
		}
	}
}
