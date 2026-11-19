//------------------------------------------------------------------------------
/*!
 * - ファイル: oracle_advisory.rs
 * - 概要: Oracle の公式 RSS と CSAF から Java SE の勧告を取り込みます
 * - バージョン: 01.00.00
 * - 作成日: 2026/11/19
 * - 制作者: Shunji Ogawa
 * - 著作権: Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * ライセンス:
 *
 * SPDX-License-Identifier: Apache-2.0
 * 本ファイルには Apache License, Version 2.0 が適用されます
 * ライセンス全文はプロジェクトルートの LICENSE を参照してください
 * <https://www.apache.org/licenses/LICENSE-2.0>
 *
 * 会社名: EnterSystem
 *
 * 更新履歴:
 *
 * ```text
 * VerNo.        author        update      comment
 * Ver.01.00.00  Shunji Ogawa  2026/11/19  新規作成
 * ```
 */
//------------------------------------------------------------------------------

use std::collections::{BTreeMap, BTreeSet};
use std::io;

use quick_xml::{Reader, events::Event};
use serde_json::{Value, json};
use trust_repair_core::SUPPORTED_JAVA_MAJORS;

use crate::advisory::{Cvss, Product, Version, official_url, valid_cve, valid_date};

const DOCUMENTS: &str = "https://www.oracle.com/a/tech/docs/security-alerts/";
const LEGACY_DOCUMENTS: &str = "https://www.oracle.com/docs/tech/security-alerts/";
const ALERTS: &str = "https://www.oracle.com/security-alerts/";
const RSS_URL: &str = "https://www.oracle.com/a/tech/docs/security-alerts/oracle-cpu-csaf-rss.xml";
const MONTHS: [&str; 12] = [
	"jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
];

/// 公式 RSS の項目から、取得と照合に必要な値だけを保持します
#[derive(Default)]
struct RssItem {
	link: Option<String>,
	guid: Option<String>,
	date: Option<String>,
}

/// 対象の製品 ID が明示する Java SE の版です
struct JavaVersion<'a> {
	major: u16,
	number: &'a str,
	build: Option<&'a str>,
	version: Version,
}

//------------------------------------------------------------------------------
/**
 * 指定日以降の公式勧告と、最後に確認した RSS の公開日を返します
 *
 * # Errors
 *
 * 取得または対象資料の検証に失敗した場合は公開日も勧告も返しません
 */
//------------------------------------------------------------------------------
pub(super) fn collect(
	mut fetch: impl FnMut(&str) -> io::Result<Vec<u8>>,
	since: &str,
) -> io::Result<(String, Vec<Value>)> {
	if !valid_date(since) {
		return Err(invalid("Invalid Oracle advisory date"));
	}
	let mut documents = BTreeSet::new();
	let mut covered = since.to_owned();
	for item in read_rss(&fetch(RSS_URL)?)? {
		let date = rss_date(item.date.as_deref().unwrap_or_default())
			.ok_or_else(|| invalid("Invalid Oracle RSS publication date"))?;
		if date.as_str() >= since {
			let id = rss_id(&item, &date)
				.ok_or_else(|| invalid("Invalid Oracle RSS advisory identifier"))?;
			covered = covered.max(date.clone());
			documents.insert((date, id));
		}
	}

	// 同じ CVE が複数の勧告にある場合に備え、公開日の新しい資料を先に返す
	let mut advisories = Vec::new();
	let mut seen = BTreeSet::new();
	for (_, id) in documents.into_iter().rev() {
		if seen.insert(id.clone()) {
			let bytes = fetch(&format!("{DOCUMENTS}{id}csaf.json"))?;
			advisories.extend(read_csaf(&bytes, &id)?);
		}
	}
	Ok((covered, advisories))
}

//------------------------------------------------------------------------------
/**
 * RSS 2.0 の channel 直下から、公開日、リンク、GUID を読み取ります
 */
//------------------------------------------------------------------------------
fn read_rss(bytes: &[u8]) -> io::Result<Vec<RssItem>> {
	let mut reader = Reader::from_reader(bytes);
	let mut items = Vec::new();
	let mut current = None;
	let mut depth = 0;
	let mut seen_root = false;
	let mut seen_channel = false;
	let mut in_channel = false;
	loop {
		match reader.read_event().map_err(io::Error::other)? {
			Event::Start(tag) => {
				depth += 1;
				match (depth, tag.name().as_ref()) {
					(1, b"rss") if !seen_root => seen_root = true,
					(1, _) => return Err(invalid("Invalid Oracle RSS root")),
					(2, b"channel") if !seen_channel => {
						seen_channel = true;
						in_channel = true;
					}
					(3, b"item") if in_channel => current = Some(RssItem::default()),
					(4, b"link" | b"guid" | b"pubDate") if let Some(item) = current.as_mut() => {
						let field = match tag.name().as_ref() {
							b"link" => &mut item.link,
							b"guid" => &mut item.guid,
							_ => &mut item.date,
						};
						let value = reader.read_text(tag.name()).map_err(io::Error::other)?;
						let value = value.decode().map_err(io::Error::other)?;
						if field.replace(value.trim().to_owned()).is_some() {
							return Err(invalid("Duplicate Oracle RSS field"));
						}
						depth -= 1;
					}
					_ => {}
				}
			}
			Event::End(tag) => {
				if depth == 3
					&& let Some(item) = current.take()
				{
					items.push(item);
				}
				if depth == 2 && tag.name().as_ref() == b"channel" {
					in_channel = false;
				}
				depth -= 1;
			}
			Event::Empty(tag) if depth == 2 && in_channel && tag.name().as_ref() == b"item" => {
				return Err(invalid("Oracle RSS includes an empty item"));
			}
			Event::DocType(_) => return Err(invalid("Oracle RSS includes a document type")),
			Event::Eof if depth == 0 && !items.is_empty() => return Ok(items),
			Event::Eof => return Err(invalid("Oracle RSS has no complete channel or items")),
			_ => {}
		}
	}
}

//------------------------------------------------------------------------------
/**
 * RSS の現地公開日を、時差による日付の繰り上げをせずに ISO 日付へ変換します
 */
//------------------------------------------------------------------------------
fn rss_date(value: &str) -> Option<String> {
	let value = value.split_once(',').map_or(value, |(_, date)| date);
	let mut fields = value.split_ascii_whitespace();
	let day = fields.next()?;
	if !day.bytes().all(|byte| byte.is_ascii_digit()) {
		return None;
	}
	let day = day.parse::<u8>().ok()?;
	let month = fields.next()?.to_ascii_lowercase();
	let month = MONTHS.iter().position(|&name| name == month)? + 1;
	let year = fields.next()?;
	let date = format!("{year}-{month:02}-{day:02}");
	valid_date(&date).then_some(date)
}

//------------------------------------------------------------------------------
/**
 * Oracle の公式リンクと GUID から、資料を特定できる識別子を返します
 */
//------------------------------------------------------------------------------
fn rss_id(item: &RssItem, date: &str) -> Option<String> {
	let link = csaf_id(item.link.as_deref()?)?;
	let guid = item.guid.as_deref()?.to_ascii_lowercase();
	if let Some(cve) = link.strip_prefix("cve-") {
		// 単独の Security Alert はリンクにある CVE と GUID の一致を確認する
		return (guid == format!("alertcve{}", cve.replace('-', ""))).then(|| link.to_owned());
	}

	// リンクの月が誤っていても、同じ種類の勧告の GUID が公開年月と一致すれば取得できる
	let (kind, _) = scheduled_id(link)?;
	let (guid_kind, _) = scheduled_id(&guid)?;
	let month_index = date.get(5..7)?.parse::<usize>().ok()?.checked_sub(1)?;
	let expected = format!("{kind}{}{}", MONTHS.get(month_index)?, date.get(..4)?);
	(kind == guid_kind && guid == expected).then_some(guid)
}

//------------------------------------------------------------------------------
/**
 * 公式 CSAF URL が示す資料名を取得します
 */
//------------------------------------------------------------------------------
fn csaf_id(url: &str) -> Option<&str> {
	let id = url
		.strip_prefix(DOCUMENTS)
		.or_else(|| url.strip_prefix(LEGACY_DOCUMENTS))?
		.strip_suffix("csaf.json")?;
	(scheduled_id(id).is_some() || valid_cve(&id.to_ascii_uppercase())).then_some(id)
}

//------------------------------------------------------------------------------
/**
 * 定期勧告の識別子を種類と公開月に分けます
 */
//------------------------------------------------------------------------------
fn scheduled_id(id: &str) -> Option<(&'static str, &str)> {
	let (kind, date) = if let Some(date) = id.strip_prefix("cspu") {
		("cspu", date)
	} else {
		("cpu", id.strip_prefix("cpu")?)
	};
	let month = date.get(..3)?;
	let year = date.get(3..)?;
	(MONTHS.contains(&month) && year.len() == 4 && year.bytes().all(|b| b.is_ascii_digit()))
		.then_some((kind, month))
}

//------------------------------------------------------------------------------
/**
 * CSAF の出典、文書番号と製品を確認し、製品別の CVE レコードを作ります
 */
//------------------------------------------------------------------------------
fn read_csaf(bytes: &[u8], id: &str) -> io::Result<Vec<Value>> {
	let data: Value = serde_json::from_slice(bytes).map_err(io::Error::other)?;
	let document = &data["document"];
	let tracking = &document["tracking"];
	let html_id = if id.starts_with("cve-") {
		format!("alert-{id}")
	} else {
		id.to_owned()
	};
	let expected_url = format!("{ALERTS}{html_id}.html");
	let alternate_url = (id != html_id).then(|| format!("{ALERTS}{id}.html"));
	let references = array(&document["references"]);
	let advisory_url = references
		.iter()
		.filter_map(|reference| reference["url"].as_str())
		.find(|&url| url == expected_url || alternate_url.as_deref() == Some(url))
		.ok_or_else(|| invalid("Invalid Oracle CSAF advisory URL"))?;
	let expected_id = format!("{id}csaf");
	// 一部の CSPU では CPU の文書番号が残っているため、同月の番号を公式参照先と照合する
	let alternate_id = id
		.strip_prefix("cspu")
		.map(|month| format!("cpu{month}csaf"));
	if document["publisher"]["name"] != "Oracle"
		|| document["publisher"]["namespace"] != "https://www.oracle.com"
		|| document["csaf_version"] != "2.0"
		|| !matches!(
			document["category"].as_str(),
			Some("csaf_security_advisory" | "csaf_vex")
		) || tracking["status"] != "final"
		|| !tracking["id"].as_str().is_some_and(|key| {
			key.eq_ignore_ascii_case(&expected_id)
				|| alternate_id
					.as_ref()
					.is_some_and(|id| key.eq_ignore_ascii_case(id))
		}) || !references.iter().any(|reference| {
		reference["category"] == "self" && reference["url"].as_str().and_then(csaf_id) == Some(id)
	}) {
		return Err(invalid("Invalid Oracle CSAF document identity"));
	}
	let branches = data["product_tree"]["branches"]
		.as_array()
		.ok_or_else(|| invalid("Oracle CSAF has no product tree"))?;
	let vulnerabilities = data["vulnerabilities"]
		.as_array()
		.ok_or_else(|| invalid("Oracle CSAF has no vulnerabilities"))?;
	let mut products = BTreeMap::new();
	java_products(branches, &mut products)?;
	let details_url = if scheduled_id(id).is_some() {
		format!("{advisory_url}#AppendixJAVA")
	} else {
		advisory_url.to_owned()
	};
	let mut advisories = Vec::new();
	for row in vulnerabilities {
		advisories.extend(read_vulnerability(
			row,
			&products,
			&details_url,
			advisory_url,
		)?);
	}
	Ok(advisories)
}

//------------------------------------------------------------------------------
/**
 * Oracle Java SE の製品名直下にある明示版から、照合対象の製品 ID を作ります
 */
//------------------------------------------------------------------------------
fn java_products<'a>(
	branches: &'a [Value],
	products: &mut BTreeMap<&'a str, JavaVersion<'a>>,
) -> io::Result<()> {
	for branch in branches {
		let children = array(&branch["branches"]);
		if branch["category"] != "product_name" || branch["name"] != "Oracle Java SE" {
			java_products(children, products)?;
			continue;
		}
		for child in children {
			let product = &child["product"];
			let Some(name) = product["name"]
				.as_str()
				.and_then(|value| value.strip_prefix("Oracle Java SE Version "))
			else {
				continue;
			};
			let (number, build) = name
				.split_once('+')
				.map_or((name, None), |(number, build)| (number, Some(build)));
			let Some(major) = number
				.split('.')
				.next()
				.and_then(|major| major.parse::<u16>().ok())
				.filter(|major| SUPPORTED_JAVA_MAJORS.contains(major))
			else {
				continue;
			};
			let (Some(version), Some(id)) = (
				Version::parse(&format!("{number}+{}", build.unwrap_or("0"))),
				product["product_id"].as_str(),
			) else {
				return Err(invalid("Unsupported Oracle Java SE version in CSAF"));
			};
			if child["category"] != "product_version"
				|| build.is_some_and(|value| !value.bytes().all(|b| b.is_ascii_digit()))
				|| products
					.insert(
						id,
						JavaVersion {
							major,
							number,
							build,
							version,
						},
					)
					.is_some()
			{
				return Err(invalid("Ambiguous Oracle Java SE product in CSAF"));
			}
		}
	}
	Ok(())
}

//------------------------------------------------------------------------------
/**
 * 影響版と CVSS が同じ製品を参照することを確認し、修正ビルドは明記された場合だけ使います
 */
//------------------------------------------------------------------------------
fn read_vulnerability(
	row: &Value,
	products: &BTreeMap<&str, JavaVersion<'_>>,
	details_url: &str,
	advisory_url: &str,
) -> io::Result<Vec<Value>> {
	let status = &row["product_status"];
	let mut majors: BTreeMap<_, BTreeMap<_, _>> = BTreeMap::new();
	for id in array(&status["known_affected"])
		.iter()
		.filter_map(Value::as_str)
	{
		let Some(affected) = products.get(id) else {
			continue;
		};
		majors
			.entry(affected.major)
			.or_default()
			.insert(id, affected);
	}
	let mut groups: BTreeMap<_, Vec<_>> = BTreeMap::new();
	for (major, affected_products) in majors {
		let (&id, &affected) = affected_products
			.first_key_value()
			.expect("affected products are not empty");
		// 同じ系列の複数版や特定ビルドへの限定は、単一のバージョンに丸めて断定しない
		let requires_review = affected_products.len() > 1 || affected.build.is_some();
		let score = if affected_products.len() == 1 {
			cvss(row, id)?
		} else {
			None
		};
		let updates_url = array(&row["remediations"])
			.iter()
			.filter(|remediation| {
				remediation["category"] == "vendor_fix"
					&& array(&remediation["product_ids"])
						.iter()
						.any(|value| value == id)
			})
			.filter_map(|remediation| remediation["url"].as_str())
			.find(|url| official_url(Product::OracleJavaSe, url))
			.filter(|_| affected_products.len() == 1)
			.unwrap_or(advisory_url);
		let mut series = json!({ "major": major, "listed_release": affected.number });
		if requires_review {
			series["requires_review"] = json!(true);
		} else if let Some(fixed) = array(&status["fixed"])
			.iter()
			.filter_map(|id| products.get(id.as_str()?))
			.filter(|fixed| fixed.major == affected.major && fixed.version > affected.version)
			.filter(|fixed| fixed.build.is_some())
			.min_by_key(|fixed| &fixed.version)
			.and_then(|fixed| fixed.build.map(|build| format!("{}+{build}", fixed.number)))
		{
			series["fixed_build"] = json!(fixed);
		}
		groups
			.entry((
				score.map(|score| (score.version, score.tenths)),
				updates_url,
			))
			.or_default()
			.push((major, series));
	}
	if groups.is_empty() {
		return Ok(Vec::new());
	}
	let cve = row["cve"]
		.as_str()
		.filter(|cve| valid_cve(cve))
		.ok_or_else(|| invalid("Invalid Oracle Java SE CVE identifier"))?;
	let (summary, condition) = finding_text(row);
	let mut advisories = Vec::new();
	for ((score, updates_url), mut series) in groups {
		series.sort_by_key(|(major, _)| *major);
		let (majors, series): (Vec<_>, Vec<_>) = series.into_iter().unzip();
		advisories.push(json!({
			"product": "oracle_java_se",
			"details_url": details_url,
			"updates_url": updates_url,
			"series": series,
			"findings": [{
				"cve": cve,
				"cvss": score.map(|(version, tenths)| json!({ "version": version, "score": f64::from(tenths) / 10.0 })),
				"summary": summary,
				"condition": condition,
				"majors": majors,
			}],
		}));
	}
	Ok(advisories)
}

//------------------------------------------------------------------------------
/**
 * 製品 ID が明記された公式スコアだけを取り込みます
 */
//------------------------------------------------------------------------------
fn cvss(row: &Value, id: &str) -> io::Result<Option<Cvss>> {
	let mut result = None;
	for score in array(&row["scores"]) {
		if !array(&score["products"])
			.iter()
			.any(|product| product == id)
		{
			continue;
		}
		let input = score.get("cvss_v3").or_else(|| score.get("cvss_v4"));
		let Some(input) = input else {
			continue;
		};
		let current = serde_json::from_value(json!({
			"version": input["version"],
			"score": input["baseScore"],
		}))
		.map_err(io::Error::other)?;
		if result
			.replace(current)
			.is_some_and(|previous| previous != current)
		{
			return Err(invalid("Conflicting Oracle Java SE CVSS scores"));
		}
	}
	Ok(result)
}

//------------------------------------------------------------------------------
/**
 * 公式の説明にあるコンポーネントと条件を使い、欠落時は出典を案内します
 */
//------------------------------------------------------------------------------
fn finding_text(row: &Value) -> (Value, Value) {
	let description = array(&row["notes"])
		.iter()
		.find(|note| note["category"] == "description")
		.and_then(|note| note["text"].as_str())
		.unwrap_or_default();
	let component = description
		.split_once("(component: ")
		.and_then(|(_, rest)| rest.split_once(")."))
		.map(|(component, _)| component)
		.filter(|component| {
			!component.is_empty()
				&& component.chars().count() <= 100
				&& !component.chars().any(char::is_control)
		});
	let summary = match component {
		Some(component) => json!({
			"ja": format!("Oracle Java SE の {component} に影響する脆弱性です。"),
			"en": format!("Oracle reports a vulnerability in the {component} component of Oracle Java SE."),
		}),
		None => json!({
			"ja": "Oracle が Oracle Java SE への影響を公表しています。",
			"en": "Oracle reports that this vulnerability affects Oracle Java SE.",
		}),
	};
	let note = description
		.split_once("Note: ")
		.map(|(_, note)| note.split_once(" CVSS ").map_or(note, |(text, _)| text))
		.map(|note| note.split_whitespace().collect::<Vec<_>>().join(" "))
		.filter(|note| !note.is_empty() && note.chars().count() <= 600)
		.filter(|note| !note.chars().any(char::is_control));
	let condition = json!({
		"ja": "影響条件は Oracle の公式勧告をご確認ください。",
		"en": note.as_deref().unwrap_or("See the official Oracle advisory for applicability details."),
	});
	(summary, condition)
}

//------------------------------------------------------------------------------
/**
 * CSAF の省略できる配列項目を参照します
 */
//------------------------------------------------------------------------------
fn array(value: &Value) -> &[Value] {
	value.as_array().map_or(&[], Vec::as_slice)
}

//------------------------------------------------------------------------------
/**
 * 出典または内容の照合に失敗したことを返します
 */
//------------------------------------------------------------------------------
fn invalid(message: &'static str) -> io::Error {
	io::Error::new(io::ErrorKind::InvalidData, message)
}

/// 取得先と、CSAF に明記された製品別の根拠を検証します
#[cfg(test)]
mod tests {
	use super::{DOCUMENTS, RSS_URL, collect, read_csaf};
	use serde_json::{Value, json};

	const RSS: &[u8] = br#"<rss version="2.0"><channel>
		<item>
			<link>https://www.oracle.com/a/tech/docs/security-alerts/cspuoct2026csaf.json </link>
			<pubDate>Tue, 17 Nov 2026 13:00:00 -0700</pubDate>
			<guid isPermaLink="false">CSPUNov2026</guid>
		</item>
		<item>
			<link>https://www.oracle.com/docs/tech/security-alerts/cpuoct2026csaf.json</link>
			<pubDate>Tue, 20 Oct 2026 13:00:00 -0700</pubDate>
			<guid isPermaLink="false">CPUOct2026</guid>
		</item>
	</channel></rss>"#;

	fn csaf() -> Value {
		let product = |id, name: &str| {
			json!({
				"category": "product_version",
				"product": { "name": format!("Oracle Java SE Version {name}"), "product_id": id },
			})
		};
		json!({
			"document": {
				"category": "csaf_security_advisory",
				"csaf_version": "2.0",
				"publisher": { "name": "Oracle", "namespace": "https://www.oracle.com" },
				"tracking": { "id": "CSPUNov2026csaf", "status": "final" },
				"references": [
					{ "url": "https://www.oracle.com/security-alerts/cspunov2026.html" },
					{ "category": "self", "url": format!("{DOCUMENTS}cspunov2026csaf.json") },
				],
			},
			"product_tree": { "branches": [{
				"category": "product_family",
				"name": "Oracle Java SE",
				"branches": [
					{
						"category": "product_name",
						"name": "Oracle Java SE",
						"branches": [
							product("jdk21", "21.0.13"),
							product("jdk21-fixed", "21.0.13.1+4"),
							product("jdk25", "25.0.5"),
							product("jdk25-fixed", "25.0.6"),
							product("jdk27", "27.0.1"),
						],
					},
					{
						"category": "product_name",
						"name": "Oracle GraalVM for JDK",
						"branches": [product("graal17", "17.0.21")],
					},
				],
			}]},
			"vulnerabilities": [{
				"cve": "CVE-2026-99999",
				"product_status": {
					"known_affected": ["jdk21", "jdk25", "jdk27", "graal17"],
					"fixed": ["jdk21-fixed", "jdk25-fixed"],
				},
				"scores": [
					{ "products": ["graal17"], "cvss_v3": { "version": "3.1", "baseScore": 9.1 } },
					{ "products": ["jdk21", "jdk25"], "cvss_v3": { "version": "3.1", "baseScore": 7.4 } },
				],
				"remediations": [{
					"product_ids": ["jdk21", "jdk25"],
					"category": "vendor_fix",
					"url": "https://support.oracle.com/support/?documentId=CPU000",
				}],
			}],
		})
	}

	#[test]
	fn corrects_rss_document_link_and_observes_inclusive_publication_date() {
		let mut urls = Vec::new();
		let (covered, advisories) = collect(
			|url| {
				urls.push(url.to_owned());
				Ok(if url == RSS_URL {
					RSS.to_vec()
				} else {
					serde_json::to_vec(&csaf()).unwrap()
				})
			},
			"2026-11-17",
		)
		.unwrap();
		assert_eq!(
			urls,
			[
				RSS_URL.to_owned(),
				format!("{DOCUMENTS}cspunov2026csaf.json")
			]
		);
		assert_eq!(covered, "2026-11-17");
		assert_eq!(advisories.len(), 1);
		assert_eq!(advisories[0]["findings"][0]["majors"], json!([21, 25]));
		assert_eq!(advisories[0]["findings"][0]["cvss"]["score"], 7.4);
		assert_eq!(advisories[0]["series"][0]["fixed_build"], "21.0.13.1+4");
		assert!(advisories[0]["series"][1].get("fixed_build").is_none());
	}

	#[test]
	fn rejects_document_identity_and_preserves_unscored_findings() {
		let mut data = csaf();
		assert!(read_csaf(&serde_json::to_vec(&data).unwrap(), "cspudec2026").is_err());
		data["document"]["tracking"]["id"] = json!("CPUNov2026csaf");
		assert!(read_csaf(&serde_json::to_vec(&data).unwrap(), "cspunov2026").is_ok());
		data["vulnerabilities"][0]["scores"][1]["products"] = json!(["jdk21"]);
		let advisories = read_csaf(&serde_json::to_vec(&data).unwrap(), "cspunov2026").unwrap();
		assert!(
			advisories
				.iter()
				.any(|advisory| advisory["findings"][0]["majors"] == json!([25])
					&& advisory["findings"][0]["cvss"].is_null())
		);
	}
}
