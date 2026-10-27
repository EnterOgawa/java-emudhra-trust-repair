//------------------------------------------------------------------------------
/*!
 * - ファイル: diagnosis.rs
 * - 概要: DER 一致による診断と、全ストアが合格した場合だけの変更計画を提供します
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
 * 計画は適用許可や lock の代わりではありません。実行直前に snapshot を再照合します
 */
//------------------------------------------------------------------------------

use crate::{EntryKind, Policy, StoreInventory};

/// GUI が日英の文言へ変換できる、変更抑止理由の識別値です
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueCode {
	/// 対応 major リスト、OS、CPU の条件に合格しません
	UnsupportedJava,
	/// NTFS、リンク、属性、stream 等の通常ファイル条件に合格しません
	UnsafeFile,
	/// owner/group/DACL 等を完全に取得できません
	MetadataUnavailable,
	/// 診断前後または二回の inventory が一致しません
	ChangedDuringScan,
	/// 同じ alias または CN が定義名に似ていますが、DER が異なります
	NameCollision,
	/// 秘密鍵または対称鍵を含みます
	KeyMaterial,
	/// keytool の既知の警告を検出しました
	KeytoolWarning,
	/// Java/keytool の実体または実行結果を検証できません
	ProcessFailure,
	/// RFC、DER、ストアの解析に失敗しました
	InvalidInventory,
	/// 必須のストアが見つかりません
	MissingStore,
	/// 診断を利用者が中断しました
	Cancelled,
}

/// 診断の重要状態を、ローカライズする文章から分離します
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanStatus {
	/// 正確な DER を検出しました。計画全体の可否は別に判断します
	TargetsFound,
	/// 今回読めたファイルに定義の 4 DER を検出しませんでした
	NoTargets,
	/// inventory はありますが、自動変更を許可できません
	NotModifiable,
	/// 完全な inventory を取得できませんでした
	Failed,
}

/// 一つの対象証明書の出現位置です。鍵チェーン内の位置も区別します
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetMatch {
	/// 定義内の識別子
	policy_root_id: String,
	/// 一致する証明書を含む別名
	alias: String,
	/// entry 内の 0 始まりの証明書位置
	certificate_index: usize,
	/// 完全一致した DER ハッシュ
	sha256: String,
}

impl TargetMatch {
	//------------------------------------------------------------------------------
	/**
	 * 一致した定義の識別子を返します
	 */
	//------------------------------------------------------------------------------
	pub fn policy_root_id(&self) -> &str {
		&self.policy_root_id
	}

	//------------------------------------------------------------------------------
	/**
	 * 一致した証明書を含む全別名の一つを返します
	 */
	//------------------------------------------------------------------------------
	pub fn alias(&self) -> &str {
		&self.alias
	}

	//------------------------------------------------------------------------------
	/**
	 * チェーン内の 0 始まりの位置を返します
	 */
	//------------------------------------------------------------------------------
	pub fn certificate_index(&self) -> usize {
		self.certificate_index
	}

	//------------------------------------------------------------------------------
	/**
	 * 一致した DER 全体の SHA-256 を返します
	 */
	//------------------------------------------------------------------------------
	pub fn sha256(&self) -> &str {
		&self.sha256
	}
}

/// 一つのストアに対する診断です。可変参照を公開せず、計画の検証を迂回できなくします
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanReport {
	/// 検証済みの定義 ID
	policy_id: String,
	/// 完全に読めた場合の全エントリ
	inventory: Option<StoreInventory>,
	/// 別名およびチェーン位置を省略しない検出一覧
	targets: Vec<TargetMatch>,
	/// 一件でもある場合に群全体の計画を拒否する理由
	issues: Vec<IssueCode>,
}

impl ScanReport {
	//------------------------------------------------------------------------------
	/**
	 * 全件 inventory を評価します。外部検査で判明した `issues` の所有権も受け取ります。
	 * DER 一致だけを対象にし、同名別 DER と鍵の混在は追加の抑止理由にします。
	 * 不完全な外部検査を空の issues として渡してはいけません
	 *
	 * # Arguments
	 *
	 * - `policy`: DER ハッシュと名称の照合に使う検証済み定義
	 * - `inventory`: 完全に取得した一覧。返す診断が所有します
	 * - `issues`: 外部検査で判明した抑止理由。評価で見つけた理由を追加します
	 *
	 * # Returns
	 *
	 * DER の全一致位置と全抑止理由を保持する診断。名称だけの一致では削除対象にしません
	 */
	//------------------------------------------------------------------------------
	pub fn evaluate(
		policy: &Policy,
		inventory: StoreInventory,
		mut issues: Vec<IssueCode>,
	) -> Self {
		let mut targets = Vec::new();
		// 全別名・全チェーン位置を列挙し、同一 DER の二つ目以降も省略しない
		for entry in inventory.entries() {
			// 鍵を含むストアは、証明書だけ一致していても自動変更へ進めない
			if entry.kind() != EntryKind::TrustedCertificate {
				issues.push(IssueCode::KeyMaterial);
			}
			// 名称は曖昧さの検出にだけ使用し、対象の正判定は DER の一致だけに限定する
			for (certificate_index, certificate) in entry.certificates().iter().enumerate() {
				// 定義四件をすべて照合し、名称から対象を推測しない
				for root in policy.roots() {
					// DER の完全一致だけを対象とし、名称だけの衝突は抑止理由に残す
					if root.sha256() == certificate.sha256() {
						targets.push(TargetMatch {
							policy_root_id: root.id().to_owned(),
							alias: entry.alias().to_owned(),
							certificate_index,
							sha256: certificate.sha256().to_owned(),
						});
					}
					// DER が異なる名称一致は曖昧さの警告に留め、削除対象には加えない
					else if certificate
						.common_names()
						.iter()
						.any(|name| name.eq_ignore_ascii_case(root.name()))
						|| entry.alias().eq_ignore_ascii_case(root.id())
						|| entry
							.alias()
							.eq_ignore_ascii_case(&format!("{} [jdk]", root.id()))
					{
						issues.push(IssueCode::NameCollision);
					}
				}
			}
		}
		issues.dedup();
		Self {
			policy_id: policy.id().to_owned(),
			inventory: Some(inventory),
			targets,
			issues,
		}
	}

	//------------------------------------------------------------------------------
	/**
	 * 途中の inventory を返さず、診断失敗と構造化した理由を保持します
	 *
	 * # Arguments
	 *
	 * - `policy`: 失敗した診断に結び付ける定義
	 * - `issue`: 群全体の計画を止める失敗理由
	 *
	 * # Returns
	 *
	 * inventory と対象を持たない診断失敗
	 */
	//------------------------------------------------------------------------------
	pub fn failed(policy: &Policy, issue: IssueCode) -> Self {
		Self {
			policy_id: policy.id().to_owned(),
			inventory: None,
			targets: Vec::new(),
			issues: vec![issue],
		}
	}

	//------------------------------------------------------------------------------
	/**
	 * inventory の有無・全抑止理由・対象数から表示状態を返します
	 */
	//------------------------------------------------------------------------------
	pub fn status(&self) -> ScanStatus {
		// 一覧不在・抑止理由・対象数の順で判定し、失敗を未検出と混同しない
		if self.inventory.is_none() {
			ScanStatus::Failed
		}
		// 一覧を取得できても抑止理由があれば、全群の変更を許可しない
		else if !self.issues.is_empty() {
			ScanStatus::NotModifiable
		}
		// 全件の診断に合格した後でだけ、対象ゼロを変更不要として返す
		else if self.targets.is_empty() {
			ScanStatus::NoTargets
		} else {
			ScanStatus::TargetsFound
		}
	}

	//------------------------------------------------------------------------------
	/**
	 * 診断時の定義 ID を返します
	 */
	//------------------------------------------------------------------------------
	pub fn policy_id(&self) -> &str {
		&self.policy_id
	}

	//------------------------------------------------------------------------------
	/**
	 * 完全に解析できた場合だけ、形式と全エントリを返します
	 */
	//------------------------------------------------------------------------------
	pub fn inventory(&self) -> Option<&StoreInventory> {
		self.inventory.as_ref()
	}

	//------------------------------------------------------------------------------
	/**
	 * 定義と DER が一致した全出現位置を返します。削除可能とは限りません
	 */
	//------------------------------------------------------------------------------
	pub fn targets(&self) -> &[TargetMatch] {
		&self.targets
	}

	//------------------------------------------------------------------------------
	/**
	 * 群全体の適用を禁止する理由を返します
	 */
	//------------------------------------------------------------------------------
	pub fn issues(&self) -> &[IssueCode] {
		&self.issues
	}
}

/// 後続 transaction が削除前に snapshot と照合すべき、一つのストアの予定です
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedStore {
	/// 診断されたストア群内の位置
	report_index: usize,
	/// 正確な DER が一致する trustedCertEntry の全別名
	deletions: Vec<TargetMatch>,
	/// 変更前の全エントリ。非対象保持と形式維持の照合に使用します
	original: StoreInventory,
}

impl PlannedStore {
	//------------------------------------------------------------------------------
	/**
	 * scan 結果と snapshot を結び付ける 0 始まりの位置を返します
	 */
	//------------------------------------------------------------------------------
	pub fn report_index(&self) -> usize {
		self.report_index
	}

	//------------------------------------------------------------------------------
	/**
	 * 同じ証明書の複数別名を含む、削除予定の全別名を返します
	 */
	//------------------------------------------------------------------------------
	pub fn deletions(&self) -> &[TargetMatch] {
		&self.deletions
	}

	//------------------------------------------------------------------------------
	/**
	 * 非対象・形式の保持を再検証するための元 inventory を返します
	 */
	//------------------------------------------------------------------------------
	pub fn original(&self) -> &StoreInventory {
		&self.original
	}
}

/// 全ストアの診断が合格した場合だけ作成できる、未適用の変更計画です
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangePlan {
	/// この計画を作成した定義版
	policy_id: String,
	/// 削除対象のあるストアだけの予定
	stores: Vec<PlannedStore>,
}

/// 変更計画を作成できない理由です
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanError {
	/// 選択されたストアがありません
	EmptySelection,
	/// 一つ以上の診断が失敗・要確認です
	Blocked {
		/// 元のストア群内の 0 始まりの位置
		report_index: usize,
	},
	/// 異なる定義で診断された結果が混在しています
	PolicyMismatch,
	/// 群全体に削除対象がなく、変更不要です
	NoTargets,
}

impl ChangePlan {
	//------------------------------------------------------------------------------
	/**
	 * 群全体に警告・失敗・鍵・曖昧な証明書がないことを確認して計画を作ります。
	 * 一部だけの成功から計画を作りません。ファイルの hash/ID/metadata と定義の
	 * 実行直前の照合、lock、backup、作業コピーと適用後検証は transaction の責務です
	 *
	 * # Arguments
	 *
	 * - `policy`: 全診断と一致しなければならない対策定義
	 * - `reports`: 入力順を維持する、今回の全ストアの診断
	 *
	 * # Returns
	 *
	 * 削除対象のあるストアだけを含む計画。元診断の位置と inventory を所有します
	 *
	 * # Errors
	 *
	 * 空の群、診断失敗/変更不可、定義差、対象ゼロでは [`PlanError`] を返します
	 */
	//------------------------------------------------------------------------------
	pub fn build(policy: &Policy, reports: &[ScanReport]) -> Result<Self, PlanError> {
		// 空の入力範囲を、対象証明書がない診断成功と混同しない
		if reports.is_empty() {
			return Err(PlanError::EmptySelection);
		}
		let mut stores = Vec::new();
		// 全ストアを検査し、最初の失敗時点で部分計画も破棄する
		for (report_index, report) in reports.iter().enumerate() {
			// 別の対策定義で得た診断を、現在の変更計画へ流用しない
			if report.policy_id != policy.id() {
				return Err(PlanError::PolicyMismatch);
			}
			// 一ストアの抑止理由でも全群の部分適用を防ぐ
			if !report.issues.is_empty() {
				return Err(PlanError::Blocked { report_index });
			}
			let original = report
				.inventory
				.as_ref()
				.ok_or(PlanError::Blocked { report_index })?;
			// 対象のあるストアだけを計画へ含め、元の群内位置を保持する
			if !report.targets.is_empty() {
				stores.push(PlannedStore {
					report_index,
					deletions: report.targets.clone(),
					original: original.clone(),
				});
			}
		}
		// 全件の診断に合格してから、対象ゼロを変更不要として区別する
		if stores.is_empty() {
			return Err(PlanError::NoTargets);
		}
		Ok(Self {
			policy_id: policy.id().to_owned(),
			stores,
		})
	}

	//------------------------------------------------------------------------------
	/**
	 * 計画の再照合に必要な定義 ID を返します
	 */
	//------------------------------------------------------------------------------
	pub fn policy_id(&self) -> &str {
		&self.policy_id
	}

	//------------------------------------------------------------------------------
	/**
	 * 削除対象のあるストアとその予定を返します
	 */
	//------------------------------------------------------------------------------
	pub fn stores(&self) -> &[PlannedStore] {
		&self.stores
	}
}
