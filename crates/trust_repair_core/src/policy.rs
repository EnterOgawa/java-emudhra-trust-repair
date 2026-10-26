//------------------------------------------------------------------------------
/*!
 * - ファイル: policy.rs
 * - 概要: 埋込み対策定義を検証し、変更できない参照として提供します。
 * - バージョン: 01.00.00
 * - 作成日: 2026/10/26
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
 * Ver.01.00.00  Shunji Ogawa  2026/10/26  4 ルートの埋込み定義と不正定義の拒否を追加。
 * ```
 *
 * 備考:
 *
 * 定義の URL は出典の表示用です。読込み時に通信しません。
 * 定義の検証成功は、Java や信頼ストアの診断・対策完了を表しません。
 */
//------------------------------------------------------------------------------

use std::error::Error;
use std::fmt;

use serde::Deserialize;

// 定義を実行ファイルに含め、外部ファイルの読込みや更新を要求しない
const EMBEDDED_POLICY_JSON: &str = include_str!("../../../data/policy.json");
// Oracle の今回の回避策で対象とするルート数
const POLICY_ROOT_COUNT: usize = 4;

/// ルートを今回の不信頼化対象へ含める根拠を区別します。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RootRelation {
	/// 問題の中間 CA に関連するチェーンのルートです。
	AffectedChain,
	/// 追加の不信頼化対象として指定されたルートです。
	AdditionalDistrust,
}

/// 出典と DER 全体の SHA-256 が定義された一つのルートです。
#[derive(Debug)]
pub struct RootCertificate {
	/// 定義内で重複しない ASCII 識別子。
	id: String,
	/// 表示用の証明書名。削除対象の識別には使用しません。
	name: String,
	/// DER 全体の SHA-256。大文字 ASCII 十六進数 64 桁。
	sha256: String,
	/// 証明書の取得元を示す HTTPS URL。
	source: String,
	/// 今回の不信頼化との関係。
	relation: RootRelation,
}

impl RootCertificate {
	//------------------------------------------------------------------------------
	/**
	 * 定義内で一意の識別子を返します。
	 *
	 * # Returns
	 *
	 * `self` の借用中だけ有効な識別子。証明書の一致判定には使いません。
	 */
	//------------------------------------------------------------------------------
	pub fn id(&self) -> &str {
		&self.id
	}

	//------------------------------------------------------------------------------
	/**
	 * 表示用の証明書名を返します。
	 *
	 * # Returns
	 *
	 * `self` の借用中だけ有効な名称。対象識別や別名の一致条件には使いません。
	 */
	//------------------------------------------------------------------------------
	pub fn name(&self) -> &str {
		&self.name
	}

	//------------------------------------------------------------------------------
	/**
	 * 対象 DER 全体の SHA-256 定義を返します。
	 *
	 * # Returns
	 *
	 * `self` の借用中だけ有効な、大文字 ASCII 十六進数 64 桁の文字列。
	 */
	//------------------------------------------------------------------------------
	pub fn sha256(&self) -> &str {
		&self.sha256
	}

	//------------------------------------------------------------------------------
	/**
	 * 証明書の取得元を返します。
	 *
	 * # Returns
	 *
	 * `self` の借用中だけ有効な表示用 HTTPS URL。アクセスは行いません。
	 */
	//------------------------------------------------------------------------------
	pub fn source(&self) -> &str {
		&self.source
	}

	//------------------------------------------------------------------------------
	/**
	 * ルートを対象へ含める根拠を返します。
	 *
	 * # Returns
	 *
	 * 影響チェーンへの関連、または追加の不信頼化を表す値。
	 */
	//------------------------------------------------------------------------------
	pub fn relation(&self) -> RootRelation {
		self.relation
	}
}

/// 埋込み JSON の構造・必須項目・4 ルートの一意性を検証した対策定義です。
#[derive(Debug)]
pub struct Policy {
	/// 対策定義の識別子。transaction へ記録する定義版を識別します。
	id: String,
	/// 定義を確認した日付の表示文字列。
	reviewed_on: String,
	/// Oracle の案内元を示す HTTPS URL。
	advisory: String,
	/// 定義順を保持した、重複しない 4 ルート。
	roots: Vec<RootCertificate>,
}

impl Policy {
	//------------------------------------------------------------------------------
	/**
	 * 対策定義の識別子を返します。
	 *
	 * # Returns
	 *
	 * `self` の借用中だけ有効な定義 ID。
	 */
	//------------------------------------------------------------------------------
	pub fn id(&self) -> &str {
		&self.id
	}

	//------------------------------------------------------------------------------
	/**
	 * 定義の確認日を返します。
	 *
	 * # Returns
	 *
	 * `self` の借用中だけ有効な確認日の表示文字列。
	 */
	//------------------------------------------------------------------------------
	pub fn reviewed_on(&self) -> &str {
		&self.reviewed_on
	}

	//------------------------------------------------------------------------------
	/**
	 * Oracle の案内元を返します。
	 *
	 * # Returns
	 *
	 * `self` の借用中だけ有効な HTTPS URL。アクセスは行いません。
	 */
	//------------------------------------------------------------------------------
	pub fn advisory(&self) -> &str {
		&self.advisory
	}

	//------------------------------------------------------------------------------
	/**
	 * 定義済みの 4 ルートを順序を保って返します。
	 *
	 * # Returns
	 *
	 * `self` の借用中だけ有効な、不変のルート一覧。
	 */
	//------------------------------------------------------------------------------
	pub fn roots(&self) -> &[RootCertificate] {
		&self.roots
	}
}

/// 埋込み定義を利用できない理由です。
#[derive(Debug)]
pub enum PolicyError {
	/// JSON 構文、必須項目、未知項目、列挙値、件数に不整合があります。
	Json {
		/// 位置情報を含む元の JSON エラー。
		source: serde_json::Error,
	},
	/// 値の書式、識別子、SHA-256 の一意性に不整合があります。
	InvalidDefinition {
		/// 不整合を検出した項目。利用者の入力内容は含めません。
		field: &'static str,
	},
}

impl fmt::Display for PolicyError {
	//------------------------------------------------------------------------------
	/**
	 * [`fmt::Display`] に従い、不正な定義の項目または JSON の原因を表示します。
	 *
	 * # Arguments
	 *
	 * - `formatter`: 本呼出し中だけ可変借用する出力先。
	 *
	 * # Errors
	 *
	 * 出力先が失敗した場合、その `fmt::Error` を返します。
	 */
	//------------------------------------------------------------------------------
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		// 構文エラーと意味上の不整合を区別し、定義を補正して続行しない
		match self {
			Self::Json { source } => write!(formatter, "対策定義の JSON が不正です: {source}"),
			Self::InvalidDefinition { field } => {
				write!(
					formatter,
					"対策定義の項目が不正または重複しています: {field}"
				)
			}
		}
	}
}

impl Error for PolicyError {
	//------------------------------------------------------------------------------
	/**
	 * [`Error::source`] に従い、保持した JSON エラーを返します。
	 *
	 * # Returns
	 *
	 * JSON エラーなら借用した原因、それ以外は `None`。
	 */
	//------------------------------------------------------------------------------
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		// JSON の元のエラー連鎖だけを公開する
		match self {
			Self::Json { source } => Some(source),
			Self::InvalidDefinition { .. } => None,
		}
	}
}

/// JSON の外形だけを受け取り、検証済みの型と分離する内部データです。
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct RawPolicy {
	/// 未検証の定義 ID。
	id: String,
	/// 未検証の確認日表示。
	reviewed_on: String,
	/// 未検証の案内元 URL。
	advisory: String,
	/// 件数を JSON 境界で固定した未検証のルート。
	roots: [RawRoot; POLICY_ROOT_COUNT],
}

/// 一つのルートの JSON 入力を保持します。
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct RawRoot {
	/// 未検証のルート ID。
	id: String,
	/// 未検証の表示名。
	name: String,
	/// 未検証の DER SHA-256。
	sha256: String,
	/// 未検証の取得元 URL。
	source: String,
	/// JSON 境界で既知の値へ限定する関係。
	relation: RootRelation,
}

//------------------------------------------------------------------------------
/**
 * 実行ファイルへ埋め込んだ対策定義を読み込み、検証した値を返します。
 *
 * # Returns
 *
 * 必須項目、4 件のルート、ID と SHA-256 の書式・一意性を確認した定義。
 * 呼出し元へ所有権を移し、変更用の参照は公開しません。
 *
 * # Errors
 *
 * 埋込み JSON の構文・構造または値が不正なら [`PolicyError`] を返します。
 * 不完全な定義を返しません。修正には製品の更新が必要です。
 *
 * # Notes
 *
 * 外部ファイルとネットワークを使用せず、共有状態を持ちません。
 *
 * # Examples
 *
 * ```
 * let policy = trust_repair_core::embedded_policy()?;
 * assert_eq!(policy.roots().len(), 4);
 * # Ok::<(), trust_repair_core::PolicyError>(())
 * ```
 */
//------------------------------------------------------------------------------
pub fn embedded_policy() -> Result<Policy, PolicyError> {
	parse_policy(EMBEDDED_POLICY_JSON)
}

//------------------------------------------------------------------------------
/**
 * JSON の外形を読み込み、検証を完了してから公開型へ移します。
 *
 * # Arguments
 *
 * - `input`: 本呼出し中だけ借用する内部 JSON。参照を結果へ保持しません。
 *
 * # Returns
 *
 * 入力の順序を保持する、検証済みの定義。
 *
 * # Errors
 *
 * JSON の不整合、表示不能な項目、ID/ハッシュの不正・重複で失敗します。
 * 構造、metadata、先頭からの各ルートの順に検査し、最初の失敗を返します。
 */
//------------------------------------------------------------------------------
fn parse_policy(input: &str) -> Result<Policy, PolicyError> {
	let raw: RawPolicy =
		serde_json::from_str(input).map_err(|source| PolicyError::Json { source })?;

	// 空や制御文字を含む metadata を表示へ渡さない
	if !is_identifier(&raw.id)
		|| !is_display_text(&raw.reviewed_on)
		|| !is_https_reference(&raw.advisory)
	{
		return Err(PolicyError::InvalidDefinition { field: "metadata" });
	}

	let mut roots: Vec<RootCertificate> = Vec::with_capacity(POLICY_ROOT_COUNT);

	// 先頭から全ルートを検査し、全件合格するまで Policy を作らない
	for root in raw.roots {
		// 対象を特定するハッシュの欠落・小文字・短縮表記を許可しない
		if !is_identifier(&root.id)
			|| !is_display_text(&root.name)
			|| !is_https_reference(&root.source)
			|| root.sha256.len() != 64
			|| !root
				.sha256
				.bytes()
				.all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
		{
			return Err(PolicyError::InvalidDefinition { field: "root" });
		}

		// 同じ ID または DER を複数の定義として数えない
		if roots
			.iter()
			.any(|existing| existing.id == root.id || existing.sha256 == root.sha256)
		{
			return Err(PolicyError::InvalidDefinition {
				field: "root uniqueness",
			});
		}

		roots.push(RootCertificate {
			id: root.id,
			name: root.name,
			sha256: root.sha256,
			source: root.source,
			relation: root.relation,
		});
	}

	Ok(Policy {
		id: raw.id,
		reviewed_on: raw.reviewed_on,
		advisory: raw.advisory,
		roots,
	})
}

//------------------------------------------------------------------------------
/**
 * 空白や制御文字を含まない定義 ID か調べます。
 *
 * # Arguments
 *
 * - `value`: 本呼出し中だけ借用する ID 候補。
 *
 * # Returns
 *
 * 1～128 byte の ASCII 英小文字・数字・ハイフンだけなら `true`。
 */
//------------------------------------------------------------------------------
fn is_identifier(value: &str) -> bool {
	!value.is_empty()
		&& value.len() <= 128
		&& value
			.bytes()
			.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

//------------------------------------------------------------------------------
/**
 * 表示に使う定義文字列の最小条件を確認します。
 *
 * # Arguments
 *
 * - `value`: 本呼出し中だけ借用する表示文字列。
 *
 * # Returns
 *
 * 1～2048 byte で、制御文字と前後の空白を含まなければ `true`。
 * 日付や証明書名の意味までは検査しません。
 */
//------------------------------------------------------------------------------
fn is_display_text(value: &str) -> bool {
	!value.is_empty()
		&& value.len() <= 2048
		&& value.trim() == value
		&& !value.chars().any(char::is_control)
}

//------------------------------------------------------------------------------
/**
 * 表示用の出典が HTTPS 参照の形を持つことを確認します。
 *
 * # Arguments
 *
 * - `value`: 本呼出し中だけ借用する出典文字列。
 *
 * # Returns
 *
 * `https://` に続く文字があり、制御文字・空白を含まなければ `true`。
 * URL の到達性や出典内容の正しさは判定しません。
 */
//------------------------------------------------------------------------------
fn is_https_reference(value: &str) -> bool {
	is_display_text(value)
		&& value.starts_with("https://")
		&& value.len() > "https://".len()
		&& !value.chars().any(char::is_whitespace)
}

/// 埋込み定義の契約と、危険な定義を拒否する条件を確認します。
#[cfg(test)]
mod tests {
	use super::{EMBEDDED_POLICY_JSON, RootRelation, embedded_policy, parse_policy};

	//------------------------------------------------------------------------------
	/**
	 * 既知の対策 ID と 4 ルート、および根拠の区別が埋込み資材から復元されるか確認します。
	 *
	 * # Panics
	 *
	 * 定義が読めない、または必須のルート集合・関係が変化した場合に失敗します。
	 */
	//------------------------------------------------------------------------------
	#[test]
	fn embedded_policy_contains_reviewed_root_set() {
		let policy = embedded_policy().expect("埋込み定義は常に検証に合格する必要があります");
		assert_eq!(policy.id(), "oracle-emudhra-2026-10-24");
		assert_eq!(policy.reviewed_on(), "2026-10-26");
		assert_eq!(policy.advisory(), "https://ops.java/emudhra");
		let ids: Vec<&str> = policy.roots().iter().map(|root| root.id()).collect();
		assert_eq!(
			ids,
			[
				"emsignrootcag1",
				"emsignrootcag2",
				"emsigneccrootcag3",
				"comodoaaaca"
			]
		);
		assert_eq!(
			policy.roots()[0].relation(),
			RootRelation::AdditionalDistrust
		);
		assert_eq!(policy.roots()[2].relation(), RootRelation::AffectedChain);
	}

	//------------------------------------------------------------------------------
	/**
	 * 件数不足・未知項目・重複・ハッシュ不正などを有効な定義として返さないことを確認します。
	 *
	 * # Panics
	 *
	 * 不正な定義が一件でも受理された場合に失敗します。
	 */
	//------------------------------------------------------------------------------
	#[test]
	fn rejects_incomplete_unknown_and_ambiguous_definitions() {
		let invalid_inputs = [
			"{}".to_owned(),
			r#"{"Id":"valid","ReviewedOn":"2026-10-26","Advisory":"https://ops.java/emudhra","Roots":[]}"#.to_owned(),
			EMBEDDED_POLICY_JSON.replacen("\"Id\":", "\"Unknown\": 1, \"Id\":", 1),
			EMBEDDED_POLICY_JSON.replace("additional-distrust", "unknown-relation"),
			EMBEDDED_POLICY_JSON.replace("emsignrootcag2", "emsignrootcag1"),
			EMBEDDED_POLICY_JSON.replace(
				"1AA0C2709E831BD6E3B5129A00BA41F7EEEF020872F1E6504BF0F6C3F24F3AF3",
				"40F6AF0346A99AA1CD1D555A4E9CCE62C7F9634603EE406615833DC8C8D00367",
			),
			EMBEDDED_POLICY_JSON.replace(
				"40F6AF0346A99AA1CD1D555A4E9CCE62C7F9634603EE406615833DC8C8D00367",
				"40F6",
			),
			EMBEDDED_POLICY_JSON.replace("AAA Certificate Services", "AAA\\nCertificate Services"),
		];

		// すべての不正入力で、不完全な Policy の生成を拒否する
		for input in invalid_inputs {
			assert!(parse_policy(&input).is_err(), "不正定義を受理しました");
		}
	}
}
