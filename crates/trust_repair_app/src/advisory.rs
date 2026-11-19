//------------------------------------------------------------------------------
/*!
 * - ファイル: advisory.rs
 * - 概要: 選択した Java の実行時ビルドを、製品別の公式勧告と照合します
 * - バージョン: 01.06.00
 * - 作成日: 2026/11/19
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
 * Ver.01.00.00  Shunji Ogawa  2026/11/19  Java の公式勧告との照合を追加
 * Ver.01.01.00  Shunji Ogawa  2026/11/19  配布元と Java 系列に対応する公式配布先を追加
 * Ver.01.02.00  Shunji Ogawa  2026/11/19  OpenJDK 勧告の参照と「以前」のバージョン範囲に対応
 * Ver.01.03.00  Shunji Ogawa  2026/11/19  対処方法を CVE ごとの照合結果に集約
 * Ver.01.04.00  Shunji Ogawa  2026/11/19  CVE ごとの CVSS 版と基本値を検証して取り込む
 * Ver.01.05.00  Shunji Ogawa  2026/11/19  取得した定義と保存済み定義を同じ規則で検証
 * Ver.01.06.00  Shunji Ogawa  2026/11/19  公式勧告の確認日と OpenJDK 情報による要確認判定を追加
 * ```
 *
 * 備考:
 *
 * Windows x64 の選択済み Java を対象とし、判定時の通信や Java の設定変更は行いません
 */
//------------------------------------------------------------------------------

use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::sync::OnceLock;

use serde::Deserialize;
use trust_repair_core::SUPPORTED_JAVA_MAJORS;
use trust_repair_windows::{JavaEnvironment, JavaRuntime};

/// 同梱定義を公式勧告と照合した日
pub(super) const CATALOG_DATE: &str = "2026-11-19";

// 外部定義の読み込み量を、配布される定義と同じ上限に収める
const MAX_CATALOG_BYTES: usize = 1024 * 1024;
const BUNDLED_CATALOG: &str = include_str!("../../../data/java-advisories.json");

/// 勧告との照合に使用できる配布元と製品です
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Product {
	/// Oracle Java SE の Oracle 配布バイナリ
	OracleJavaSe,
	/// Eclipse Adoptium による Eclipse Temurin バイナリ
	Temurin,
}

impl Product {
	//------------------------------------------------------------------------------
	/**
	 * 両言語共通の正式な製品名を返します
	 */
	//------------------------------------------------------------------------------
	pub(super) fn name(self) -> &'static str {
		match self {
			Self::OracleJavaSe => "Oracle Java SE",
			Self::Temurin => "Eclipse Temurin",
		}
	}

	//------------------------------------------------------------------------------
	/**
	 * 対応する Java 系列の Windows x64 向け公式配布ページを返します
	 *
	 * # Returns
	 *
	 * 対応系列の配布先。公式ページを案内できない系列では `None`
	 */
	//------------------------------------------------------------------------------
	fn download_page(self, major: u16) -> Option<String> {
		// 検証済みの配布元と系列から構成し、外部定義の入力は URL に使わない
		match (self, major) {
			(Self::OracleJavaSe, 11 | 17 | 21) => Some(format!(
				"https://www.oracle.com/java/technologies/downloads/#java{major}-windows"
			)),
			(Self::OracleJavaSe, 25) => {
				Some("https://www.oracle.com/java/technologies/downloads/#jdk25-windows".to_owned())
			}
			(Self::Temurin, _) if SUPPORTED_JAVA_MAJORS.contains(&major) => Some(format!(
				"https://adoptium.net/temurin/releases/?arch=x64&mode=filter&os=windows&version={major}"
			)),
			_ => None,
		}
	}
}

/// 勧告に収録した CVE の版照合結果です。全脆弱性の評価には使用しません
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Status {
	/// 勧告がこの系列を明示的に影響対象外としています
	NotAffected,
	/// この勧告の修正ビルドと同等以上です
	Fixed,
	/// 製品または系列の勧告を収録していません
	Unsupported,
	/// 実行時情報が欠落しているか、配布版と照合できません
	UnknownVersion,
	/// 修正を確認できず、影響版として明示されていないビルドです
	PotentiallyAffected,
	/// 勧告の影響版または影響範囲に該当します。実行条件は別途確認が必要です
	AffectedVersion,
}

/// 表示する日本語と英語の文です
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Localized {
	/// 日本語の文
	pub(super) ja: String,
	/// 英語の文
	pub(super) en: String,
}

/// 公式に案内された修正版と対処です
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Guidance {
	/// 同じ Java 系列で公表された最初の修正ビルド
	pub(super) fixed_build: Option<String>,
	/// 公式の更新案内または配布状況
	pub(super) updates_url: String,
	/// 公式に案内された暫定対処の表示文
	pub(super) workaround: Option<Localized>,
}

/// 選択した Java 系列に関する CVE の表示情報です
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Finding {
	/// ASCII の CVE 識別子
	pub(super) cve: String,
	/// 公式の CVSS 基本値。定義に収録していない場合は `None`
	pub(super) cvss: Option<Cvss>,
	/// コンポーネントと影響の概要
	pub(super) summary: Localized,
	/// 勧告に記載された実行構成、CPU 等の条件
	pub(super) condition: Localized,
	/// 影響と対象版を記載した公式勧告
	pub(super) details_url: String,
	/// この CVE に限定した版の判定
	pub(super) status: Status,
	/// この CVE と Java 系列に対応する更新案内
	pub(super) guidance: Option<Guidance>,
}

/// 選択時の Java と、使用した定義で照合した結果です
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Report {
	/// release と実行結果で照合された配布者
	pub(super) vendor: String,
	/// 取得できた実行時版。欠けている場合は release と照合された版
	pub(super) version: String,
	/// 製品メタデータを収録対象と照合できたときの製品
	pub(super) product: Option<Product>,
	/// 選択した製品・系列に対応する公式配布ページ
	pub(super) download_page: Option<String>,
	/// 要確認の項目を優先した全体の表示状態
	pub(super) status: Status,
	/// 収録中の CVE ごとの版判定と条件
	pub(super) findings: Vec<Finding>,
	/// 使用した定義が公式勧告と照合された日
	pub(super) catalog_date: String,
}

/// Java 勧告の同梱定義と外部定義に共通の構造です
#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Catalog {
	/// この実装で読み込める JSON 形式の版
	schema_version: u8,
	/// 公式資料を確認した日
	verified_on: String,
	/// 自動取得した公式勧告を配布元ごとに確認できた最終日
	#[serde(default)]
	official_through: std::collections::BTreeMap<String, String>,
	/// 勧告ごとの出典、修正ビルド、CVE の一覧
	advisories: Vec<Advisory>,
}

/// 定義全体を使用できない理由です
#[derive(Debug)]
pub(super) enum CatalogError {
	/// 外部ファイルの読み取りに失敗したときの OS の分類
	Io(io::ErrorKind),
	/// 読み取り上限を超過
	TooLarge,
	/// JSON、文字コード、型または項目名がスキーマに適合しない
	InvalidJson,
	/// 対象版、出典、CVE ID または日付が無効か曖昧
	InvalidData,
	/// 同梱定義より確認日が古い
	Outdated,
}

/// 公式勧告に共通する条件と Java 系列ごとの修正版です
#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Advisory {
	/// 勧告を出した製品
	product: Product,
	/// 公式勧告
	details_url: String,
	/// 公式の更新案内または配布状況
	updates_url: String,
	/// 確認済みの暫定対処。表示文としてのみ使用する
	workaround: Option<Localized>,
	/// Java 系列ごとの対象範囲
	series: Vec<Series>,
	/// この勧告に含まれる CVE と影響条件
	findings: Vec<AdvisoryFinding>,
}

/// 単一の Java 系列に対する勧告の照合規則です
#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Series {
	/// Java の先頭の版番号
	major: u16,
	/// 勧告が列挙する影響版。未指定の場合はすべての修正前の版が影響範囲
	listed_release: Option<String>,
	/// 勧告が列挙した影響バージョン以前も対象であることを示す
	#[serde(default)]
	includes_earlier: bool,
	/// 勧告から配布元の影響範囲を確定できず、個別確認が必要な情報
	#[serde(default)]
	requires_review: bool,
	/// 公表された修正ビルド。未公表なら未指定
	fixed_build: Option<String>,
	/// 公式に当系列が影響対象外と明示されたことを示す
	#[serde(default)]
	not_affected: bool,
}

/// 定義内の CVE と、その勧告が扱う系列です
#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdvisoryFinding {
	/// ASCII の CVE ID
	cve: String,
	/// 勧告に記載された CVSS 基本値
	cvss: Option<Cvss>,
	/// コンポーネントと影響の要約
	summary: Localized,
	/// 勧告に示された影響条件
	condition: Localized,
	/// この CVE の照合に使う系列
	majors: Vec<u16>,
}

/// 対応する CVSS の版と、比較に使う 0～100 の基本値です
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Cvss {
	/// 公式資料が採用した CVSS の版
	pub(super) version: &'static str,
	/// 基本値を 10 倍した整数
	pub(super) tenths: u8,
}

/// JSON で受け取る公式の CVSS データです
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CvssInput {
	/// CVSS の版番号
	version: String,
	/// 0.0～10.0 の基本値
	score: f64,
}

impl<'de> Deserialize<'de> for Cvss {
	//------------------------------------------------------------------------------
	/**
	 * 版と基本値を検証し、深刻度表示とソートで使う整数に変換します
	 *
	 * # Errors
	 *
	 * 未対応の版、範囲外の基本値、小数第 2 位以下を持つ基本値は受理しません
	 */
	//------------------------------------------------------------------------------
	fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		let input = CvssInput::deserialize(deserializer)?;
		let version = match input.version.as_str() {
			"3.0" => "3.0",
			"3.1" => "3.1",
			"4.0" => "4.0",
			_ => return Err(serde::de::Error::custom("Unsupported CVSS version")),
		};
		let tenths = input.score * 10.0;
		if !(0.0..=100.0).contains(&tenths) || tenths.fract() != 0.0 {
			return Err(serde::de::Error::custom(
				"CVSS score must be in the range 0.0 to 10.0 with one decimal place",
			));
		}
		Ok(Self {
			version,
			tenths: tenths as u8,
		})
	}
}

/// GA 版の版番号とビルド番号。順序は同一系列内の比較に使用します
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Version {
	/// JEP 322 に従う可変長の VNUM
	numbers: Vec<i32>,
	/// 十進のビルド番号
	build: i32,
}

impl Version {
	//------------------------------------------------------------------------------
	/**
	 * VNUM とビルドを読み取ります。比較用の任意情報 OPT は読み飛ばします
	 *
	 * # Returns
	 *
	 * Java Runtime.Version 形式の GA ビルド。先行版、不明な版、ビルド省略は None
	 */
	//------------------------------------------------------------------------------
	pub(super) fn parse(value: &str) -> Option<Self> {
		let (number, build) = value.split_once('+')?;
		let numbers = number.split('.').map(decimal).collect::<Option<Vec<_>>>()?;
		// Runtime.Version が要求する VNUM の先頭と末尾の非ゼロを確認する
		if numbers.first() == Some(&0) || numbers.last() == Some(&0) {
			return None;
		}
		// ハイフンがビルドに続く場合は、OPT として許される文字だけを受け付ける
		let build = if let Some((build, optional)) = build.split_once('-') {
			// 正規の先行版表記に加え、任意欄に付いた開発版の印も照合から外す
			if optional.is_empty()
				|| !optional
					.bytes()
					.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
				|| optional.split(['-', '.']).any(|word| {
					["ea", "internal", "beta", "rc", "snapshot"]
						.iter()
						.any(|marker| word.eq_ignore_ascii_case(marker))
				}) {
				return None;
			}
			build
		} else {
			build
		};
		Some(Self {
			numbers,
			build: decimal(build)?,
		})
	}
}

impl Catalog {
	//------------------------------------------------------------------------------
	/**
	 * EXE と同じフォルダ等の定義を読み取ります。パスは呼び出し元が指定します
	 *
	 * # Errors
	 *
	 * 読み取り、上限超過、文字コード、形式または内容の失敗。部分的な定義は返しません
	 */
	//------------------------------------------------------------------------------
	pub(super) fn load(path: &Path) -> Result<Self, CatalogError> {
		Self::from_bytes(&Self::read_bytes(path)?)
	}

	//------------------------------------------------------------------------------
	/**
	 * 定義ファイルを上限を設けて読み込み、検証前のバイト列を返します
	 */
	//------------------------------------------------------------------------------
	pub(super) fn read_bytes(path: &Path) -> Result<Vec<u8>, CatalogError> {
		let file = File::open(path).map_err(|error| CatalogError::Io(error.kind()))?;
		let mut bytes = Vec::new();
		file.take((MAX_CATALOG_BYTES + 1) as u64)
			.read_to_end(&mut bytes)
			.map_err(|error| CatalogError::Io(error.kind()))?;
		Ok(bytes)
	}

	//------------------------------------------------------------------------------
	/**
	 * 保存済みまたは取得したバイト列の大きさと UTF-8 を確認し、定義を検証します
	 */
	//------------------------------------------------------------------------------
	pub(super) fn from_bytes(bytes: &[u8]) -> Result<Self, CatalogError> {
		// 定義の byte 数を文字コード検証前にも制限する
		if bytes.len() > MAX_CATALOG_BYTES {
			return Err(CatalogError::TooLarge);
		}
		let input = std::str::from_utf8(bytes).map_err(|_| CatalogError::InvalidJson)?;
		Self::from_json(input)
	}

	//------------------------------------------------------------------------------
	/**
	 * 定義を読み取り、すべての規則が適合する場合に限り返します
	 *
	 * # Errors
	 *
	 * 形式不一致、公式リンク以外の URL、無効または重複した規則、古い確認日を拒否します
	 */
	//------------------------------------------------------------------------------
	pub(super) fn from_json(input: &str) -> Result<Self, CatalogError> {
		// メモリ上の入力にもファイルと同じ上限を適用する
		if input.len() > MAX_CATALOG_BYTES {
			return Err(CatalogError::TooLarge);
		}
		let catalog: Self = serde_json::from_str(input).map_err(|_| CatalogError::InvalidJson)?;
		// 既知のスキーマの実在日を確認してから同梱定義の確認日と比較する
		if catalog.schema_version != 1
			|| !valid_date(&catalog.verified_on)
			|| !catalog.official_through.iter().all(|(product, date)| {
				matches!(product.as_str(), "oracle_java_se" | "temurin")
					&& valid_date(date)
					&& date <= &catalog.verified_on
			}) || catalog.advisories.is_empty()
		{
			return Err(CatalogError::InvalidData);
		}
		if catalog.verified_on.as_str() < CATALOG_DATE {
			return Err(CatalogError::Outdated);
		}

		let mut rules = HashSet::new();
		// 曖昧な製品・CVE・major の組は勧告をまたいでも受け付けない
		for advisory in &catalog.advisories {
			// 出典と対処を検査し、照合に使う系列が重複しないことを確認する
			if !official_url(advisory.product, &advisory.details_url)
				|| !official_url(advisory.product, &advisory.updates_url)
				|| advisory
					.workaround
					.as_ref()
					.is_some_and(|text| !valid_localized(text))
				|| advisory.series.is_empty()
				|| advisory.findings.is_empty()
			{
				return Err(CatalogError::InvalidData);
			}
			let mut majors = HashSet::new();
			for series in &advisory.series {
				// 同じ勧告内で一つの系列に複数の修正水準を指定させない
				if !valid_series(series) || !majors.insert(series.major) {
					return Err(CatalogError::InvalidData);
				}
			}
			for finding in &advisory.findings {
				// 各 CVE に説明と、その勧告内で定義された Java 系列が必要
				if !valid_cve(&finding.cve)
					|| !valid_localized(&finding.summary)
					|| !valid_localized(&finding.condition)
					|| finding.majors.is_empty()
					|| finding.majors.iter().any(|major| {
						!majors.contains(major)
							|| !rules.insert((advisory.product, finding.cve.as_str(), *major))
					}) {
					return Err(CatalogError::InvalidData);
				}
			}
		}
		Ok(catalog)
	}

	//------------------------------------------------------------------------------
	/**
	 * 日付が検証済みの定義から確認日を返します
	 */
	//------------------------------------------------------------------------------
	pub(super) fn date(&self) -> &str {
		&self.verified_on
	}

	//------------------------------------------------------------------------------
	/**
	 * 検証済みの定義で、選択済み Java を照合します
	 *
	 * # Returns
	 *
	 * 収録中の勧告に限定した結果。Java の再起動、通信、設定変更は行いません
	 */
	//------------------------------------------------------------------------------
	pub(super) fn assess(&self, java: &JavaEnvironment) -> Report {
		self.assess_runtime(java.vendor(), java.version(), java.major(), java.runtime())
	}

	//------------------------------------------------------------------------------
	/**
	 * Java 選択時に取得した情報と公式勧告の規則から表示結果を生成します
	 *
	 * # Returns
	 *
	 * GUI が保管できる所有型の照合結果。版は安全性全般の判定には使いません
	 */
	//------------------------------------------------------------------------------
	pub(super) fn assess_runtime(
		&self,
		vendor: &str,
		release: &str,
		major: u16,
		runtime: Option<&JavaRuntime>,
	) -> Report {
		let mut report = empty_report(vendor, release, runtime, &self.verified_on);
		// ビルド属性を照合できなかった場合は判定根拠を補わない
		let Some(runtime) = runtime else {
			return report;
		};
		let product = identify_product(vendor, runtime);
		report.product = product;
		report.download_page = product.and_then(|product| product.download_page(major));
		// release・実行時版・VM ビルドの食い違いを修正済みとして扱わない
		let vm = Version::parse(&runtime.vm_version);
		let installed = runtime
			.version
			.split_once('+')
			.filter(|(number, _)| *number == release)
			.and_then(|_| Version::parse(&runtime.version))
			.filter(|version| {
				version.numbers[0] == i32::from(major) && Some(version) == vm.as_ref()
			});
		for advisory in self
			.advisories
			.iter()
			.filter(|advisory| Some(advisory.product) == product)
		{
			// 勧告がこの系列を扱う場合だけ CVE の表示行を作る
			let Some(series) = advisory.series.iter().find(|series| series.major == major) else {
				continue;
			};
			let status = series_status(series, installed.as_ref(), release);
			let guidance = (!series.not_affected).then(|| Guidance {
				fixed_build: series.fixed_build.clone(),
				updates_url: advisory.updates_url.clone(),
				workaround: advisory.workaround.clone(),
			});
			report.findings.extend(
				advisory
					.findings
					.iter()
					.filter(|finding| finding.majors.contains(&major))
					.map(|finding| Finding {
						cve: finding.cve.clone(),
						cvss: finding.cvss,
						summary: finding.summary.clone(),
						condition: finding.condition.clone(),
						details_url: advisory.details_url.clone(),
						status,
						guidance: guidance.clone(),
					}),
			);
		}
		// 複数の勧告を取り込んだ場合も、要確認の状態を優先して表示する
		report.status = report
			.findings
			.iter()
			.map(|finding| finding.status)
			.max()
			.unwrap_or(Status::Unsupported);
		report
	}
}

//------------------------------------------------------------------------------
/**
 * 初回の同梱勧告を用いて選択済みの Java を照合します
 */
//------------------------------------------------------------------------------
pub(super) fn assess(java: &JavaEnvironment) -> Report {
	static CATALOG: OnceLock<Result<Catalog, CatalogError>> = OnceLock::new();
	// 同梱定義の欠陥があっても修正済み判定を行わず、既存の証明書診断を続行する
	match CATALOG.get_or_init(|| Catalog::from_json(BUNDLED_CATALOG)) {
		Ok(catalog) => catalog.assess(java),
		Err(_) => empty_report(java.vendor(), java.version(), java.runtime(), CATALOG_DATE),
	}
}

//------------------------------------------------------------------------------
/**
 * 比較に使う規則が未確定の状態で、識別用の情報を設定します
 */
//------------------------------------------------------------------------------
fn empty_report(
	vendor: &str,
	release: &str,
	runtime: Option<&JavaRuntime>,
	verified_on: &str,
) -> Report {
	Report {
		vendor: vendor.to_owned(),
		version: runtime
			.map_or(release, |runtime| runtime.version.as_str())
			.to_owned(),
		product: None,
		download_page: None,
		status: Status::UnknownVersion,
		findings: Vec::new(),
		catalog_date: verified_on.to_owned(),
	}
}

//------------------------------------------------------------------------------
/**
 * 公式の勧告対象と対応する版を、Java の配布者と複数の製品属性から識別します
 *
 * # Returns
 *
 * Oracle Java SE または Temurin と判断できる場合の製品。署名検証は行いません
 */
//------------------------------------------------------------------------------
fn identify_product(vendor: &str, runtime: &JavaRuntime) -> Option<Product> {
	// Oracle Java SE と同じ企業名や実行時名を持つ GraalVM は別の勧告対象
	if runtime.has_graalvm_marker {
		return None;
	}
	match (vendor, runtime.name.as_str(), runtime.vm_name.as_str()) {
		(
			"Oracle Corporation",
			"Java(TM) SE Runtime Environment",
			"Java HotSpot(TM) 64-Bit Server VM",
		) if runtime.vendor_version.as_deref().is_none_or(|version| {
			// 旧 Oracle Java 11 の YY.M 形式の配布識別子も受け付ける
			version.split_once('.').is_some_and(|(year, month)| {
				year.len() == 2
					&& decimal(year).is_some()
					&& decimal(month).is_some_and(|month| (1..=12).contains(&month))
			})
		}) =>
		{
			Some(Product::OracleJavaSe)
		}
		("Eclipse Adoptium", "OpenJDK Runtime Environment", "OpenJDK 64-Bit Server VM")
			if runtime
				.vendor_version
				.as_deref()
				.and_then(|value| value.strip_prefix("Temurin-"))
				.is_some_and(|value| !value.is_empty()) =>
		{
			Some(Product::Temurin)
		}
		// 汎用 OpenJDK 名や配布者の一致だけでは製品を特定しない
		_ => None,
	}
}

//------------------------------------------------------------------------------
/**
 * 同系列の修正ビルドと勧告が明示する版から、CVE の版判定を返します
 */
//------------------------------------------------------------------------------
fn series_status(series: &Series, installed: Option<&Version>, release: &str) -> Status {
	// ビルドの欠落、不一致、非 GA などがあれば修正済み扱いにしない
	let Some(installed) = installed else {
		return Status::UnknownVersion;
	};
	// 未公表と区別し、系列自体が対象外との明示がある場合だけ適用する
	if series.not_affected {
		return Status::NotAffected;
	}
	if series.requires_review {
		return Status::PotentiallyAffected;
	}
	if series
		.fixed_build
		.as_deref()
		.and_then(Version::parse)
		.is_some_and(|fixed| installed >= &fixed)
	{
		return Status::Fixed;
	}
	// 影響版を列挙した勧告では、明示されない修正前ビルドを影響ありと断定しない
	match series.listed_release.as_deref() {
		Some(listed) if listed != release => {
			if series.includes_earlier
				&& Version::parse(&format!("{listed}+0"))
					.is_some_and(|affected| installed.numbers <= affected.numbers)
			{
				Status::AffectedVersion
			} else {
				Status::PotentiallyAffected
			}
		}
		_ => Status::AffectedVersion,
	}
}

//------------------------------------------------------------------------------
/**
 * Java の数値項目を先頭ゼロなしの ASCII 十進数として読み取ります
 */
//------------------------------------------------------------------------------
fn decimal(value: &str) -> Option<i32> {
	// Java の非負 int の範囲内か、符号や余分なゼロがないかを検査する
	if !value.bytes().all(|byte| byte.is_ascii_digit())
		|| (value.len() > 1 && value.starts_with('0'))
	{
		return None;
	}
	value.parse().ok()
}

//------------------------------------------------------------------------------
/**
 * 系列番号と正規表記の版の対応を検証します
 */
//------------------------------------------------------------------------------
fn valid_series(series: &Series) -> bool {
	// 数値が解釈できても、このプログラムが対象とする系列だけを登録する
	if !SUPPORTED_JAVA_MAJORS.contains(&series.major) {
		return false;
	}
	// 影響対象外と、影響のあるビルドを同時に指定させない
	if series.not_affected {
		return series.listed_release.is_none()
			&& series.fixed_build.is_none()
			&& !series.includes_earlier
			&& !series.requires_review;
	}
	if series.requires_review && (series.listed_release.is_none() || series.fixed_build.is_some()) {
		return false;
	}
	let major = i32::from(series.major);
	let fixed = match series.fixed_build.as_deref() {
		Some(build) => {
			// 修正式の先頭に別の系列番号を書けないようにする
			let Some(version) = Version::parse(build).filter(|version| version.numbers[0] == major)
			else {
				return false;
			};
			Some(version)
		}
		None => None,
	};
	// 影響版の数値部にはビルド情報や先行版識別子を書かない
	match series.listed_release.as_deref() {
		Some(listed) => {
			!listed.contains('+')
				&& Version::parse(&format!("{listed}+0")).is_some_and(|affected| {
					affected.numbers[0] == major && fixed.is_none_or(|fixed| affected < fixed)
				})
		}
		// 影響版の明示がなければ、影響範囲の上端となる修正ビルドが必要
		None => fixed.is_some() && !series.includes_earlier,
	}
}

//------------------------------------------------------------------------------
/**
 * 許可した公式 HTTPS ホストと、ブラウザーで正規化しても同じ出典となる path を検証します
 */
//------------------------------------------------------------------------------
pub(super) fn official_url(product: Product, url: &str) -> bool {
	// ホストの一致で判定できる HTTPS リンクだけをブラウザーへ渡す
	if url.len() > 2048
		|| !url
			.bytes()
			.all(|byte| byte.is_ascii_alphanumeric() || b":/.-_~?#&=+".contains(&byte))
	{
		return false;
	}
	let Some((host, path)) = url
		.strip_prefix("https://")
		.and_then(|rest| rest.split_once('/'))
	else {
		return false;
	};
	let path = path.split(['?', '#']).next().unwrap_or_default();
	// 曖昧なドット項目や先頭の追加スラッシュを拒否する
	if path.is_empty()
		|| path.starts_with('/')
		|| path.split('/').any(|part| matches!(part, "." | ".."))
	{
		return false;
	}
	match (product, host) {
		(Product::OracleJavaSe, "www.oracle.com" | "docs.oracle.com" | "support.oracle.com")
		| (Product::Temurin, "adoptium.net" | "www.adoptium.net") => true,
		// GitHub には第三者の領域があるため、公式の組織名を path にも求める
		(Product::Temurin, "github.com") => path.starts_with("adoptium/"),
		// OpenJDK の公開勧告は日付で特定できるページのみ参照する
		(Product::Temurin, "openjdk.org") => path
			.strip_prefix("groups/vulnerability/advisories/")
			.is_some_and(valid_date),
		_ => false,
	}
}

//------------------------------------------------------------------------------
/**
 * 固定幅の ISO 日付と西暦の月末を確認します
 */
//------------------------------------------------------------------------------
pub(super) fn valid_date(date: &str) -> bool {
	let Some((year, rest)) = date.split_once('-') else {
		return false;
	};
	let Some((month, day)) = rest.split_once('-') else {
		return false;
	};
	// 比較順と日付順が同じになる幅と文字種を要求する
	if year.len() != 4
		|| month.len() != 2
		|| day.len() != 2
		|| !year
			.bytes()
			.chain(month.bytes())
			.chain(day.bytes())
			.all(|byte| byte.is_ascii_digit())
	{
		return false;
	}
	let (Ok(year), Ok(month), Ok(day)) =
		(year.parse::<u16>(), month.parse::<u8>(), day.parse::<u8>())
	else {
		return false;
	};
	let days = match month {
		2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
			29
		}
		2 => 28,
		4 | 6 | 9 | 11 => 30,
		1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
		_ => return false,
	};
	year > 0 && (1..=days).contains(&day)
}

//------------------------------------------------------------------------------
/**
 * CVE の年と通番が固定の区切りと ASCII 数字で記載されているか返します
 */
//------------------------------------------------------------------------------
pub(super) fn valid_cve(cve: &str) -> bool {
	cve.strip_prefix("CVE-")
		.and_then(|rest| rest.split_once('-'))
		.is_some_and(|(year, number)| {
			year.len() == 4
				&& (4..=16).contains(&number.len())
				&& year
					.bytes()
					.chain(number.bytes())
					.all(|digit| digit.is_ascii_digit())
		})
}

//------------------------------------------------------------------------------
/**
 * 二言語の概要または条件を、画面に表示できる短いテキストとして検証します
 */
//------------------------------------------------------------------------------
fn valid_localized(text: &Localized) -> bool {
	[&text.ja, &text.en].into_iter().all(|value| {
		!value.trim().is_empty()
			&& value.chars().count() <= 600
			&& !value.chars().any(char::is_control)
	})
}

/// 製品識別、勧告のビルドの境界、外部定義の受理条件を確認します
#[cfg(test)]
mod tests {
	use super::{
		BUNDLED_CATALOG, CATALOG_DATE, Catalog, CatalogError, Cvss, Product, Status, Version,
		official_url, valid_date,
	};
	use trust_repair_windows::JavaRuntime;

	//------------------------------------------------------------------------------
	/**
	 * JEP 322 に沿う多段の数値と任意欄を扱い、曖昧な GA の判定を防ぎます
	 */
	//------------------------------------------------------------------------------
	#[test]
	fn parses_only_complete_ga_builds() {
		assert!(Version::parse("21.0.13.0.3+10-LTS-vendor") > Version::parse("21.0.13.0.3+4"));
		assert!(Version::parse("21.0.13.1+1") > Version::parse("21.0.13.0.3+100"));
		assert_eq!(
			Version::parse("21.0.13.1+4-LTS-2.1"),
			Version::parse("21.0.13.1+4")
		);
		// 数値版、先行版、ビルドのみの異常、仕様上の範囲外を検査する
		for invalid in [
			"21.0.13.1",
			"21.0.13.1-ea+4",
			"21.0.13.1+4-ea",
			"21.0.13.1+04",
			"21.0.13.1+4?",
			"021.0.13.1+4",
			"21.0.13.1.0+4",
			"21..13.1+4",
			"21.0.2147483648.1+4",
		] {
			assert_eq!(Version::parse(invalid), None, "{invalid}");
		}
	}

	//------------------------------------------------------------------------------
	/**
	 * 公式の Oracle 勧告の系列ごとの明示影響版と修正ビルドを照合します
	 */
	//------------------------------------------------------------------------------
	#[test]
	fn oracle_uses_row_membership_and_fixed_build() {
		let catalog = Catalog::from_json(BUNDLED_CATALOG).expect("同梱定義は検証済み");
		assert_eq!(catalog.verified_on, CATALOG_DATE);
		// リスク表の明示された版と、各系列で対象となる CVE の集合を比較する
		for (major, release, cves) in [
			(11, "11.0.33.0.3", &[939, 940, 943, 944, 946][..]),
			(17, "17.0.21.0.3", &[938, 939, 940, 943, 944, 946][..]),
			(
				21,
				"21.0.13.0.3",
				&[938, 939, 940, 941, 942, 943, 944, 945, 946][..],
			),
			(
				25,
				"25.0.5.0.3",
				&[938, 939, 940, 941, 942, 943, 944, 945, 946, 947][..],
			),
		] {
			let report = catalog.assess_runtime(
				"Oracle Corporation",
				release,
				major,
				Some(&oracle_runtime(&format!("{release}+5-LTS"))),
			);
			assert_eq!(report.status, Status::AffectedVersion);
			assert_eq!(
				report
					.findings
					.into_iter()
					.map(|finding| finding.cve)
					.collect::<Vec<_>>(),
				cves.iter()
					.map(|id| format!("CVE-2026-114{id}"))
					.collect::<Vec<_>>()
			);
		}
		// 明示版より古い版や修正ビルドより小さい同一数値版を修正済みとしない
		for (release, build, expected) in [
			("21.0.12", "21.0.12+9-LTS", Status::PotentiallyAffected),
			("21.0.13.1", "21.0.13.1+3-LTS", Status::PotentiallyAffected),
			("21.0.13.1", "21.0.13.1+4-LTS", Status::Fixed),
			("21.0.14", "21.0.14+1-LTS-vendor", Status::Fixed),
			("21.0.13.1", "21.0.13.1", Status::UnknownVersion),
			("21.0.13.1", "21.0.14+1", Status::UnknownVersion),
		] {
			let report = catalog.assess_runtime(
				"Oracle Corporation",
				release,
				21,
				Some(&oracle_runtime(build)),
			);
			assert_eq!(report.status, expected, "{release} {build}");
		}
	}

	//------------------------------------------------------------------------------
	/**
	 * Temurin だけに該当する修正水準と、Java 11 の明示された例外を確認します
	 */
	//------------------------------------------------------------------------------
	#[test]
	fn temurin_assessment_keeps_product_and_execution_conditions() {
		let catalog = Catalog::from_json(BUNDLED_CATALOG).expect("同梱定義は検証済み");
		let mut runtime = JavaRuntime {
			version: "21.0.13.1+1".to_owned(),
			name: "OpenJDK Runtime Environment".to_owned(),
			vm_name: "OpenJDK 64-Bit Server VM".to_owned(),
			vm_version: "21.0.13.1+1-LTS".to_owned(),
			vendor_version: Some("Temurin-21.0.13.1+1".to_owned()),
			has_graalvm_marker: false,
		};
		let report = catalog.assess_runtime("Eclipse Adoptium", "21.0.13.1", 21, Some(&runtime));
		assert_eq!(report.product, Some(Product::Temurin));
		assert_eq!(report.status, Status::AffectedVersion);
		assert_eq!(report.findings[0].cve, "CVE-2026-114938");
		assert!(report.findings[0].condition.ja.contains("AVX-512 VBMI"));
		assert!(
			report.findings[0]
				.guidance
				.as_ref()
				.and_then(|guidance| guidance.workaround.as_ref())
				.is_some_and(
					|workaround| workaround.ja.contains("-XX:-UseBASE64Intrinsics")
						&& workaround.en.contains("-XX:-UseBASE64Intrinsics")
				)
		);
		runtime.version = "21.0.13.1+2".to_owned();
		runtime.vendor_version = Some("Temurin-21.0.13.1+2".to_owned());
		assert_eq!(
			catalog
				.assess_runtime("Eclipse Adoptium", "21.0.13.1", 21, Some(&runtime))
				.status,
			Status::UnknownVersion
		);
		runtime.vm_version = "21.0.13.1+2-LTS".to_owned();
		assert_eq!(
			catalog
				.assess_runtime("Eclipse Adoptium", "21.0.13.1", 21, Some(&runtime))
				.status,
			Status::Fixed
		);
		runtime.version = "11.0.33+2".to_owned();
		runtime.vm_version = "11.0.33+2-LTS".to_owned();
		runtime.vendor_version = Some("Temurin-11.0.33+2".to_owned());
		assert_eq!(
			catalog
				.assess_runtime("Eclipse Adoptium", "11.0.33", 11, Some(&runtime))
				.status,
			Status::NotAffected
		);
		runtime.vendor_version = None;
		assert_eq!(
			catalog
				.assess_runtime("Eclipse Adoptium", "11.0.33", 11, Some(&runtime))
				.status,
			Status::Unsupported
		);
	}

	//------------------------------------------------------------------------------
	/**
	 * Temurin 21.0.6 の照合で、収録した CVE をすべて表示対象に含めます
	 */
	//------------------------------------------------------------------------------
	#[test]
	fn temurin_21_keeps_full_advisory_history_and_fix_boundaries() {
		let catalog = Catalog::from_json(BUNDLED_CATALOG).expect("同梱定義は検証済み");
		for (release, build, affected) in
			[("21.0.6", 7, 83), ("21.0.13", 9, 9), ("21.0.13.1", 2, 0)]
		{
			let version = format!("{release}+{build}");
			let runtime = JavaRuntime {
				name: "OpenJDK Runtime Environment".to_owned(),
				vm_name: "OpenJDK 64-Bit Server VM".to_owned(),
				vm_version: format!("{version}-LTS"),
				vendor_version: Some(format!("Temurin-{version}")),
				has_graalvm_marker: false,
				version,
			};
			let report = catalog.assess_runtime("Eclipse Adoptium", release, 21, Some(&runtime));
			assert_eq!(report.findings.len(), 83);
			let matching = report
				.findings
				.iter()
				.filter(|finding| finding.status == Status::AffectedVersion)
				.count();
			let fixed = report
				.findings
				.iter()
				.filter(|finding| finding.status == Status::Fixed)
				.count();
			assert_eq!(matching, affected, "{release}+{build}");
			assert_eq!(fixed, 83 - affected, "{release}+{build}");
		}
	}

	//------------------------------------------------------------------------------
	/**
	 * Oracle という配布者名を共有する GraalVM と Oracle OpenJDK を識別範囲から外します
	 */
	//------------------------------------------------------------------------------
	#[test]
	fn oracle_vendor_name_alone_does_not_identify_product() {
		let catalog = Catalog::from_json(BUNDLED_CATALOG).expect("同梱定義は検証済み");
		let mut legacy = oracle_runtime("11+28");
		legacy.vendor_version = Some("18.9".to_owned());
		let legacy_report = catalog.assess_runtime("Oracle Corporation", "11", 11, Some(&legacy));
		assert_eq!(legacy_report.product, Some(Product::OracleJavaSe));
		assert_eq!(legacy_report.status, Status::PotentiallyAffected);
		let mut runtime = oracle_runtime("21.0.13.1+4");
		runtime.has_graalvm_marker = true;
		assert_eq!(
			catalog
				.assess_runtime("Oracle Corporation", "21.0.13.1", 21, Some(&runtime))
				.status,
			Status::Unsupported
		);
		runtime.has_graalvm_marker = false;
		runtime.name = "OpenJDK Runtime Environment".to_owned();
		assert_eq!(
			catalog
				.assess_runtime("Oracle Corporation", "21.0.13.1", 21, Some(&runtime))
				.product,
			None
		);
		let missing = catalog.assess_runtime("Oracle Corporation", "21.0.13.1", 21, None);
		assert_eq!(missing.status, Status::UnknownVersion);
		assert_eq!(missing.version, "21.0.13.1");
	}

	//------------------------------------------------------------------------------
	/**
	 * 外部の新しい CVE を取り込み、既存勧告と異なる修正ビルドで評価します
	 */
	//------------------------------------------------------------------------------
	#[test]
	fn new_catalog_rows_keep_their_own_fix_and_status() {
		let mut json: serde_json::Value = serde_json::from_str(BUNDLED_CATALOG).expect("JSON");
		let mut newer = json["advisories"][0].clone();
		newer["findings"] = serde_json::json!([{
			"cve": "CVE-2027-12345",
			"summary": { "ja": "追加勧告", "en": "Additional advisory" },
			"condition": { "ja": "追加条件", "en": "Additional condition" },
			"majors": [21]
		}]);
		newer["series"] = serde_json::json!([{
			"major": 21, "listed_release": "21.0.14", "fixed_build": "21.0.14.1+4"
		}]);
		json["advisories"]
			.as_array_mut()
			.expect("advisories")
			.push(newer);
		json["verified_on"] = "2027-01-19".into();
		let outside = Catalog::from_json(&json.to_string()).expect("追加した同系列の勧告");
		let report = outside.assess_runtime(
			"Oracle Corporation",
			"21.0.14",
			21,
			Some(&oracle_runtime("21.0.14+4")),
		);
		assert_eq!(report.status, Status::AffectedVersion);
		assert_eq!(report.catalog_date, "2027-01-19");
		assert_eq!(report.findings[0].status, Status::Fixed);
		assert_eq!(
			report.findings.last().expect("追加 CVE").cve,
			"CVE-2027-12345"
		);
		assert_eq!(
			report
				.findings
				.last()
				.and_then(|finding| finding.guidance.as_ref())
				.and_then(|guidance| guidance.fixed_build.as_deref()),
			Some("21.0.14.1+4")
		);
		json["advisories"]
			.as_array_mut()
			.and_then(|advisories| advisories.last_mut())
			.expect("追加勧告")["series"][0]
			.as_object_mut()
			.expect("系列規則")
			.remove("fixed_build");
		let without_fix = Catalog::from_json(&json.to_string()).expect("修正版未公表の勧告");
		let report = without_fix.assess_runtime(
			"Oracle Corporation",
			"21.0.14",
			21,
			Some(&oracle_runtime("21.0.14+4")),
		);
		let finding = report.findings.last().expect("修正版未公表の CVE");
		assert_eq!(finding.status, Status::AffectedVersion);
		assert!(finding.cvss.is_none());
		assert!(
			finding
				.guidance
				.as_ref()
				.is_some_and(|guidance| guidance.fixed_build.is_none())
		);
	}

	//------------------------------------------------------------------------------
	/**
	 * 古い定義、重複する規則、外部ホストへのリンクを一括で拒否します
	 */
	//------------------------------------------------------------------------------
	#[test]
	fn validates_external_catalog_before_use() {
		for (score, tenths) in [(0.0, 0), (3.9, 39), (7.4, 74), (10.0, 100)] {
			let rating: Cvss =
				serde_json::from_str(&format!(r#"{{"version":"3.1","score":{score}}}"#))
					.expect("公式 CVSS 基本値");
			assert_eq!(rating.tenths, tenths);
		}
		for invalid in [
			r#"{"version":"3.1","score":-0.1}"#,
			r#"{"version":"3.1","score":10.1}"#,
			r#"{"version":"3.1","score":8.12}"#,
			r#"{"version":"5.0","score":8.1}"#,
		] {
			assert!(serde_json::from_str::<Cvss>(invalid).is_err());
		}
		assert!(matches!(
			Catalog::from_json(&BUNDLED_CATALOG.replace(CATALOG_DATE, "2026-11-18")),
			Err(CatalogError::Outdated)
		));
		assert!(matches!(
			Catalog::from_json(&BUNDLED_CATALOG.replace(CATALOG_DATE, "2026-11-31")),
			Err(CatalogError::InvalidData)
		));
		assert!(valid_date("2028-02-29"));
		assert!(!valid_date("2100-02-29"));
		assert!(matches!(
			Catalog::from_json(&BUNDLED_CATALOG.replace("CVE-2026-114940", "CVE-2026-114939")),
			Err(CatalogError::InvalidData)
		));
		assert!(matches!(
			Catalog::from_json(
				&BUNDLED_CATALOG.replace("www.oracle.com", "www.oracle.com.invalid")
			),
			Err(CatalogError::InvalidData)
		));
		assert!(matches!(
			Catalog::from_json(&BUNDLED_CATALOG.replace(
				"\"schema_version\": 1",
				"\"schema_version\": 1, \"schema_version\": 1"
			)),
			Err(CatalogError::InvalidJson)
		));
		assert!(!official_url(
			Product::Temurin,
			"https://github.com/adoptium/../others"
		));
	}

	//------------------------------------------------------------------------------
	/**
	 * Oracle Java SE の実行時プロパティを組み立てます
	 */
	//------------------------------------------------------------------------------
	fn oracle_runtime(version: &str) -> JavaRuntime {
		JavaRuntime {
			version: version.to_owned(),
			name: "Java(TM) SE Runtime Environment".to_owned(),
			vm_name: "Java HotSpot(TM) 64-Bit Server VM".to_owned(),
			vm_version: version.to_owned(),
			vendor_version: None,
			has_graalvm_marker: false,
		}
	}
}
