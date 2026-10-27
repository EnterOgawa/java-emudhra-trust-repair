//------------------------------------------------------------------------------
/*!
 * - ファイル: inventory.rs
 * - 概要: keytool RFC 一覧を厳密に解析し、DER 全体から不変の inventory を作ります
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
 * 署名や信頼チェーンの検証は行いません。ハッシュは PEM でなく DER 全体の値です
 */
//------------------------------------------------------------------------------

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use base64::Engine;
use sha2::{Digest, Sha256};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;
use x509_parser::x509::X509Name;

/// ストアとプロセスの各出力に許す最大 byte 数です
pub const MAX_INPUT_BYTES: usize = 32 * 1024 * 1024;
// 大量の空エントリによる CPU/メモリ消費も制限する
const MAX_ENTRIES: usize = 100_000;
// 一つのエントリの証明書チェーンの長さ上限
const MAX_CHAIN_LENGTH: usize = 256;
// 空行だけの異常出力でも行参照の allocation を制限する
const MAX_LINES: usize = 1_000_000;
// OpenJDK の -list -rfc が各エントリの後へ出力する二重の区切り
const SEPARATOR: &str = "*******************************************";

/// 自動変更で形式を保持する二つのストア形式です
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreFormat {
	/// Java KeyStore 形式です
	Jks,
	/// PKCS #12 形式です
	Pkcs12,
}

/// エントリの種別です。鍵を含むものは自動変更できません
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
	/// 一つの信頼済み証明書です
	TrustedCertificate,
	/// 秘密鍵と順序付きの証明書チェーンです
	PrivateKey,
	/// 証明書を持たない対称鍵です
	SecretKey,
}

/// 一つの DER 証明書から取得した、比較と表示に必要な情報です
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateInventory {
	/// DER 全体の SHA-256。大文字十六進数 64 桁
	sha256: String,
	/// DER subject の CN。複数の RDN/属性があれば順序を保ちます
	common_names: Vec<String>,
}

impl CertificateInventory {
	//------------------------------------------------------------------------------
	/**
	 * DER 全体のハッシュを返します。戻り値は `self` に借用されます
	 */
	//------------------------------------------------------------------------------
	pub fn sha256(&self) -> &str {
		&self.sha256
	}

	//------------------------------------------------------------------------------
	/**
	 * 表示用 CN の一覧を返します。名称を削除条件には使用しません
	 */
	//------------------------------------------------------------------------------
	pub fn common_names(&self) -> &[String] {
		&self.common_names
	}
}

/// 検証した別名・種別と、順序付き証明書チェーンです
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryInventory {
	/// 制御文字・改行を含まない別名。補正せず keytool へ渡せます
	alias: String,
	/// 既知の種別
	kind: EntryKind,
	/// trustedCertEntry は 1 件、秘密鍵はチェーン順、対称鍵は 0 件
	certificates: Vec<CertificateInventory>,
}

impl EntryInventory {
	//------------------------------------------------------------------------------
	/**
	 * 元の別名を返します。空白や Unicode を正規化しません
	 */
	//------------------------------------------------------------------------------
	pub fn alias(&self) -> &str {
		&self.alias
	}

	//------------------------------------------------------------------------------
	/**
	 * 鍵の混在判定に用いる種別を返します
	 */
	//------------------------------------------------------------------------------
	pub fn kind(&self) -> EntryKind {
		self.kind
	}

	//------------------------------------------------------------------------------
	/**
	 * 証明書をチェーン順で返します。対称鍵は空の slice です
	 */
	//------------------------------------------------------------------------------
	pub fn certificates(&self) -> &[CertificateInventory] {
		&self.certificates
	}
}

/// 全件の構造・件数・DER の解析に合格したストアの内容です
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreInventory {
	/// 一覧に表示された元形式
	format: StoreFormat,
	/// JKS/PKCS12 の provider。解析時に SUN に限定します
	provider: String,
	/// 別名順に並べた全エントリ。証明書チェーン内の順序は保持します
	entries: Vec<EntryInventory>,
}

impl StoreInventory {
	//------------------------------------------------------------------------------
	/**
	 * 形式を保持するための識別値を返します
	 */
	//------------------------------------------------------------------------------
	pub fn format(&self) -> StoreFormat {
		self.format
	}

	//------------------------------------------------------------------------------
	/**
	 * 検査済み provider 名を返します
	 */
	//------------------------------------------------------------------------------
	pub fn provider(&self) -> &str {
		&self.provider
	}

	//------------------------------------------------------------------------------
	/**
	 * 重複しない全別名を返します。返す順序は一覧表示順に依存しません
	 */
	//------------------------------------------------------------------------------
	pub fn entries(&self) -> &[EntryInventory] {
		&self.entries
	}
}

/// RFC 出力を受理できない理由です。未検証の外部文字列は保持しません
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InventoryErrorCode {
	/// 入力容量が上限を超えています
	InputLimit,
	/// 厳密な UTF-8 ではありません
	Encoding,
	/// 既知の構造・件数・表示文字・DER として完全に解析できません
	Structure,
}

/// RFC の失敗位置と分類です。reason は開発診断用で GUI は code を翻訳します
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InventoryError {
	/// 日英 UI が分類を翻訳する識別値
	pub code: InventoryErrorCode,
	/// LF を基準とする 1 始まりの行番号。入力全体の問題では 0
	pub line: usize,
	/// 入力を含まない固定の失敗分類
	pub reason: &'static str,
}

impl fmt::Display for InventoryError {
	//------------------------------------------------------------------------------
	/**
	 * [`fmt::Display`] に従い、秘密や出力本文を含まない位置と理由を表示します
	 *
	 * # Returns
	 *
	 * 出力先の書込みに成功すれば `Ok(())`
	 *
	 * # Errors
	 *
	 * 出力先の `fmt::Error` を伝播します。途中までの出力は取り消しません
	 */
	//------------------------------------------------------------------------------
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(formatter, "RFC 一覧の行 {}: {}", self.line, self.reason)
	}
}

impl Error for InventoryError {}

/// 行を先頭から消費する内部 cursor です
struct Lines<'a> {
	/// CRLF を除いた各行
	values: Vec<&'a str>,
	/// 次に消費する添字
	next: usize,
}

impl<'a> Lines<'a> {
	//------------------------------------------------------------------------------
	/**
	 * 次の非空行を返します。末尾では入力を含まない解析エラーを返します
	 *
	 * # Returns
	 *
	 * 空行を読み飛ばした次の行を入力から借用して返し、読み取り位置を一行進めます
	 *
	 * # Errors
	 *
	 * 入力末尾の場合に、入力本文を含まない行位置付きエラーを返します
	 */
	//------------------------------------------------------------------------------
	fn take(&mut self) -> Result<&'a str, InventoryError> {
		self.skip_blank();
		let result = self
			.values
			.get(self.next)
			.copied()
			.ok_or(self.error("必須行の欠落"))?;
		self.next += 1;
		Ok(result)
	}

	//------------------------------------------------------------------------------
	/**
	 * 空行のみを読み飛ばします。空白だけの行は未知構造として保持します
	 */
	//------------------------------------------------------------------------------
	fn skip_blank(&mut self) {
		// 次の内容または末尾に達するまで、OpenJDK の改行差だけを吸収する
		while self.values.get(self.next) == Some(&"") {
			self.next += 1;
		}
	}

	//------------------------------------------------------------------------------
	/**
	 * 必須の固定行を消費します。不一致または末尾では失敗します
	 *
	 * # Arguments
	 *
	 * - `expected`: 次の非空行に要求する固定文字列
	 *
	 * # Errors
	 *
	 * 次の行が存在しない、または固定文字列と一致しない場合に失敗します。
	 * 読み取った行の位置は巻き戻しません
	 */
	//------------------------------------------------------------------------------
	fn expect(&mut self, expected: &str) -> Result<(), InventoryError> {
		// 必須行を補正して受け入れず、構造が一致しなければ解析を止める
		if self.take()? != expected {
			return Err(self.error("未知の構造または境界"));
		}
		Ok(())
	}

	//------------------------------------------------------------------------------
	/**
	 * 名前付き行の値を返します。prefix の欠落と空値は失敗します
	 *
	 * # Arguments
	 *
	 * - `prefix`: 行頭に要求する項目名と区切り
	 *
	 * # Returns
	 *
	 * 接頭辞を除いた非空の値を元の入力から借用して返します
	 *
	 * # Errors
	 *
	 * 行の欠落、接頭辞の不一致、空の値の場合に失敗します。
	 * 読み取った行の位置は巻き戻しません
	 */
	//------------------------------------------------------------------------------
	fn field(&mut self, prefix: &str) -> Result<&'a str, InventoryError> {
		self.take()?
			.strip_prefix(prefix)
			.filter(|value| !value.is_empty())
			.ok_or(self.error("必須項目の欠落"))
	}

	//------------------------------------------------------------------------------
	/**
	 * 直前の行位置と静的な理由だけを保持するエラーを作ります
	 *
	 * # Arguments
	 *
	 * - `reason`: 入力本文を含めない、固定された失敗理由
	 */
	//------------------------------------------------------------------------------
	fn error(&self, reason: &'static str) -> InventoryError {
		InventoryError {
			code: InventoryErrorCode::Structure,
			line: self.next,
			reason,
		}
	}
}

//------------------------------------------------------------------------------
/**
 * 成功終了した英語 `keytool -list -rfc` の stdout 全体を解析します
 *
 * # Arguments
 *
 * - `input`: 32 MiB 以下の stdout。UTF-8 は置換せず厳密に検査します
 *
 * # Returns
 *
 * 全別名・種別・証明書チェーンを持つ不変の inventory。入力への参照は残しません
 *
 * # Errors
 *
 * 件数差、重複別名、未知行/種別/provider、境界違反、不正 DER/CN で失敗します。
 * stderr、終了コード、password 検証の成功は呼出し側が確認する必要があります。
 * 解析途中の一覧を返さず、外部状態は変更しません
 */
//------------------------------------------------------------------------------
pub fn parse_keytool_rfc(input: &[u8]) -> Result<StoreInventory, InventoryError> {
	let invalid = |reason| InventoryError {
		code: InventoryErrorCode::Structure,
		line: 0,
		reason,
	};
	// 外部出力の容量を先に制限し、過大な入力を行分割へ渡さない
	if input.len() > MAX_INPUT_BYTES {
		return Err(InventoryError {
			code: InventoryErrorCode::InputLimit,
			line: 0,
			reason: "出力上限超過",
		});
	}
	let text = std::str::from_utf8(input).map_err(|_| InventoryError {
		code: InventoryErrorCode::Encoding,
		line: 0,
		reason: "UTF-8 でない出力",
	})?;
	// 改行以外の制御文字、Bidi 制御、孤立 CR は alias/表示の偽装を防ぐため拒否する
	if text
		.chars()
		.any(|value| is_unsafe_character(value) && value != '\n' && value != '\r')
	{
		return Err(invalid("制御文字を含む出力"));
	}
	let values: Vec<_> = text
		.split('\n')
		.map(|line| line.strip_suffix('\r').unwrap_or(line))
		.take(MAX_LINES + 1)
		.collect();
	// 改行構造と行ごとの上限を確認し、不完全な解析を成功へ変換しない
	if values.len() > MAX_LINES
		|| values
			.iter()
			.any(|line| line.contains('\r') || line.len() > 16 * 1024)
	{
		return Err(invalid("不正な行境界または行長"));
	}
	let mut lines = Lines { values, next: 0 };
	// 対応する二形式だけを受理し、未知形式を既知形式へ推測しない
	let format = match lines.field("Keystore type: ")? {
		"JKS" => StoreFormat::Jks,
		"PKCS12" => StoreFormat::Pkcs12,
		_ => return Err(lines.error("非対応のストア形式")),
	};
	let provider = lines.field("Keystore provider: ")?;
	// 既知の provider 以外は出力構造の保証対象に含めない
	if provider != "SUN" {
		return Err(lines.error("非対応の provider"));
	}
	let count_line = lines.take()?;
	let count_text = count_line
		.strip_prefix("Your keystore contains ")
		.and_then(|value| {
			value
				.strip_suffix(" entries")
				.or_else(|| value.strip_suffix(" entry"))
		})
		.ok_or(lines.error("件数行が不正"))?;
	let count = parse_count(count_text).ok_or(lines.error("件数が不正"))?;
	// 宣言件数と単複形を整合させ、後続の反復範囲を確定する
	if count > MAX_ENTRIES || (count == 1) != count_line.ends_with(" entry") {
		return Err(lines.error("件数の範囲または単複が不正"));
	}
	let mut aliases = BTreeSet::new();
	let mut entries = Vec::with_capacity(count);
	// 宣言件数だけ完全なエントリを読み、少ない場合も余剰の場合も拒否する
	for _ in 0..count {
		let alias = lines.field("Alias name: ")?.to_owned();
		// 過大な別名と大小文字だけ異なる重複を拒否し、一意の対象を保つ
		if alias.len() > 4096 || !aliases.insert(alias.to_lowercase()) {
			return Err(lines.error("別名が重複または長すぎる"));
		}
		// 日付は識別情報に使わないが、必須行と表示文字列の条件は維持する
		let date = lines.field("Creation date: ")?;
		// 日付行の余分な空白を暗黙に補正せず、既知の出力構造だけを受理する
		if date.trim() != date {
			return Err(lines.error("日付行が不正"));
		}
		// 鍵の種類を保持し、証明書だけのエントリと混同しない
		let kind = match lines.field("Entry type: ")? {
			"trustedCertEntry" => EntryKind::TrustedCertificate,
			"PrivateKeyEntry" => EntryKind::PrivateKey,
			"SecretKeyEntry" => EntryKind::SecretKey,
			_ => return Err(lines.error("未知のエントリ種別")),
		};
		// エントリ種別に応じた証明書数を確定し、チェーンを省略しない
		let chain_length = match kind {
			EntryKind::TrustedCertificate => 1,
			EntryKind::PrivateKey => parse_count(lines.field("Certificate chain length: ")?)
				.filter(|length| *length > 0 && *length <= MAX_CHAIN_LENGTH)
				.ok_or(lines.error("チェーン件数が不正"))?,
			EntryKind::SecretKey => 0,
		};
		let mut certificates = Vec::with_capacity(chain_length);
		// 秘密鍵チェーンは Certificate[n] も順序と件数を照合する
		for index in 0..chain_length {
			// 秘密鍵では宣言された順番の証明書だけを取り込み、途中欠落を検出する
			if kind == EntryKind::PrivateKey {
				lines.expect(&format!("Certificate[{}]:", index + 1))?;
			}
			certificates.push(parse_certificate(&mut lines)?);
		}
		lines.expect(SEPARATOR)?;
		lines.expect(SEPARATOR)?;
		entries.push(EntryInventory {
			alias,
			kind,
			certificates,
		});
	}
	lines.skip_blank();
	// 宣言件数の後に残る未知行を捨てず、全体を不完全な出力として拒否する
	if lines.next != lines.values.len() {
		return Err(lines.error("宣言件数後の未知出力"));
	}
	entries.sort_by(|left, right| left.alias.cmp(&right.alias));
	Ok(StoreInventory {
		format,
		provider: provider.to_owned(),
		entries,
	})
}

//------------------------------------------------------------------------------
/**
 * ASCII 十進数だけを受理します。空・符号・overflow・空白では `None` を返します
 *
 * # Returns
 *
 * 全体が ASCII 十進数字で `usize` に収まる場合は値、それ以外は `None`
 */
//------------------------------------------------------------------------------
fn parse_count(input: &str) -> Option<usize> {
	// 符号や空白を数値へ補正せず、ASCII 数字列だけを後段へ渡す
	if input.is_empty() || !input.bytes().all(|byte| byte.is_ascii_digit()) {
		return None;
	}
	input.parse().ok()
}

//------------------------------------------------------------------------------
/**
 * PEM 一つを DER へ復号し、全 byte の SHA-256 と subject CN を取得します。
 * 不正 PEM/DER、DER 後の余剰 byte、表示できない CN では失敗します
 *
 * # Arguments
 *
 * - `lines`: BEGIN 行から読み進める解析位置。成功時は END 行まで消費します
 *
 * # Returns
 *
 * DER 全体のハッシュと、復号した subject CN の一覧
 *
 * # Errors
 *
 * PEM 境界・Base64・X.509 DER・CN の不正、または DER の余剰 byte で失敗します。
 * 失敗時も読み取り位置は巻き戻さず、不完全な証明書を返しません
 */
//------------------------------------------------------------------------------
fn parse_certificate(lines: &mut Lines<'_>) -> Result<CertificateInventory, InventoryError> {
	lines.expect("-----BEGIN CERTIFICATE-----")?;
	let mut encoded = String::new();
	// END まで Base64 のみを受理し、空行/入れ子/別種 PEM は拒否する
	loop {
		let line = lines
			.values
			.get(lines.next)
			.copied()
			.ok_or(lines.error("PEM 終端の欠落"))?;
		lines.next += 1;
		// 対応する END 行へ到達した時点で、一証明書分の収集を終える
		if line == "-----END CERTIFICATE-----" {
			break;
		}
		// 入れ子や未知行を Base64 の一部として読み飛ばさない
		if line.is_empty()
			|| line.len() > 76
			|| !line
				.bytes()
				.all(|value| value.is_ascii_alphanumeric() || b"+/=".contains(&value))
		{
			return Err(lines.error("PEM 内の未知の行"));
		}
		encoded.push_str(line);
	}
	let der = base64::engine::general_purpose::STANDARD
		.decode(encoded)
		.map_err(|_| lines.error("不正な Base64"))?;
	let (remaining, certificate) =
		X509Certificate::from_der(&der).map_err(|_| lines.error("不正な X.509 DER"))?;
	// 一証明書の後に余分な DER がある場合、全 byte を識別できたと扱わない
	if !remaining.is_empty() {
		return Err(lines.error("DER 後の余剰 byte"));
	}
	let common_names =
		common_names(certificate.subject()).map_err(|_| lines.error("表示できない subject CN"))?;
	Ok(CertificateInventory {
		sha256: sha256_hex(&der),
		common_names,
	})
}

//------------------------------------------------------------------------------
/**
 * CN の型を UTF8/Printable/IA5/Numeric 等または BMP に限定して復号します
 *
 * # Arguments
 *
 * - `subject`: 解析済み X.509 証明書の subject
 *
 * # Returns
 *
 * subject に現れる順序の CN。一つもない場合は空の一覧
 *
 * # Errors
 *
 * CN の ASN.1 型・文字コード・長さ、または表示用文字の条件に不整合があれば `Err(())`
 */
//------------------------------------------------------------------------------
fn common_names(subject: &X509Name<'_>) -> Result<Vec<String>, ()> {
	let mut names = Vec::new();
	// subject の CN 属性をすべて列挙し、型を推測せず失敗を伝播する
	for attribute in subject.iter_common_name() {
		let value = attribute.attr_value();
		// BMPString は UTF-16 BE として読み、他の既知文字列型とは復号方法を分ける
		let name = if value.tag().0 == 30 {
			// 不完全な UTF-16 code unit を補正して表示名を作らない
			if value.data.len() % 2 != 0 {
				return Err(());
			}
			let words: Vec<u16> = value
				.data
				.as_chunks::<2>()
				.0
				.iter()
				.map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
				.collect();
			String::from_utf16(&words).map_err(|_| ())?
		} else {
			attribute.as_str().map_err(|_| ())?.to_owned()
		};
		// 表示を崩す CN を記録へ持ち込まず、空や過大な名称も拒否する
		if name.is_empty() || name.len() > 4096 || name.chars().any(is_unsafe_character) {
			return Err(());
		}
		names.push(name);
	}
	Ok(names)
}

//------------------------------------------------------------------------------
/**
 * 任意 byte 列の SHA-256 を大文字 ASCII 十六進数 64 桁で返します。副作用はありません
 */
//------------------------------------------------------------------------------
pub fn sha256_hex(input: &[u8]) -> String {
	format!("{:X}", Sha256::digest(input))
}

//------------------------------------------------------------------------------
/**
 * ログ/表示の構造を変える制御文字と双方向表示の制御を判定します
 *
 * # Returns
 *
 * 制御文字または表示方向を操作する文字なら `true`、通常の表示文字なら `false`
 */
//------------------------------------------------------------------------------
fn is_unsafe_character(value: char) -> bool {
	value.is_control()
		|| matches!(value, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}
