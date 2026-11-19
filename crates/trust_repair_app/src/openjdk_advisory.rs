//------------------------------------------------------------------------------
/*!
 * - ファイル: openjdk_advisory.rs
 * - 概要: OpenJDK の公式勧告から Temurin の照合候補を作ります
 * - バージョン: 01.00.00
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
 * Ver.01.00.00  Shunji Ogawa  2026/11/19  新規作成
 * ```
 *
 * 備考:
 *
 * OpenJDK の公開情報は Temurin の修正版として記録せず、要確認の根拠に使います
 */
//------------------------------------------------------------------------------

use std::collections::BTreeMap;
use std::io;

use scraper::{ElementRef, Html, Selector};
use serde_json::{Value, json};
use trust_repair_core::SUPPORTED_JAVA_MAJORS;

use crate::advisory::{Version, valid_cve, valid_date};

// 取得先は固定の公式索引と、公表日から組み立てた同じ配下のページに限定する
const INDEX: &str = "https://openjdk.org/groups/vulnerability/advisories/";
const UPDATES: &str = "https://adoptium.net/temurin/release-notes/";

//------------------------------------------------------------------------------
/**
 * 公式索引から確認対象の勧告を取得し、確認できた日付と定義を新しい順に返します
 */
//------------------------------------------------------------------------------
pub(super) fn collect(
	mut fetch: impl FnMut(&str) -> io::Result<Vec<u8>>,
	since: &str,
) -> io::Result<(String, Vec<Value>)> {
	let index = fetch(INDEX)?;
	let index = Html::parse_document(std::str::from_utf8(&index).map_err(io::Error::other)?);
	let links = Selector::parse("h2#advisories + ul a[href]").expect("static selector");
	let mut dates: Vec<_> = index
		.select(&links)
		.filter_map(|link| link.attr("href"))
		.filter(|date| valid_date(date))
		.collect();
	if dates.is_empty() {
		return Err(invalid("OpenJDK の勧告索引を確認できません"));
	}
	dates.sort_unstable();
	dates.dedup();
	let mut checked_through = since.to_owned();
	let mut advisories = Vec::new();
	// 久しぶりの起動でも少数の公表日から処理し、次回は確認できた日から続ける
	for date in dates.into_iter().filter(|date| *date >= since).take(8) {
		let url = format!("{INDEX}{date}");
		let document = fetch(&url)?;
		if let Some(advisory) = parse(&document, &url)? {
			advisories.push(advisory);
		}
		checked_through = date.to_owned();
	}
	advisories.reverse();
	Ok((checked_through, advisories))
}

//------------------------------------------------------------------------------
/**
 * OpenJDK の表だけを読み、OpenJFX など別製品の表を照合候補から除きます
 */
//------------------------------------------------------------------------------
fn parse(bytes: &[u8], url: &str) -> io::Result<Option<Value>> {
	let document = Html::parse_document(std::str::from_utf8(bytes).map_err(io::Error::other)?);
	let paragraph = Selector::parse("p").expect("static selector");
	let affected = document
		.select(&paragraph)
		.map(visible_text)
		.find_map(|text| {
			let (_, versions) = text.split_once("affected versions are ")?;
			let (versions, _) = versions.split_once(". ").unwrap_or((versions, ""));
			Some(versions.to_owned())
		})
		.ok_or_else(|| invalid("OpenJDK の勧告から対象バージョンを確認できません"))?;
	let releases = affected_versions(&affected);
	let matrix = Selector::parse("h2#risk-matrix + table.risk-matrix tr").expect("static selector");
	let header_cell = Selector::parse("th").expect("static selector");
	let data_cell = Selector::parse("td").expect("static selector");
	let mut rows = document.select(&matrix);
	let headers = rows
		.by_ref()
		.map(|row| {
			row.select(&header_cell)
				.map(visible_text)
				.collect::<Vec<_>>()
		})
		.find(|cells| cells.first().is_some_and(|first| first == "CVE ID"))
		.ok_or_else(|| invalid("OpenJDK のリスクマトリックスを確認できません"))?;
	if headers
		.get(1)
		.is_none_or(|component| component != "Component")
		|| headers
			.get(2)
			.is_none_or(|score| !score.starts_with("CVSS"))
	{
		return Err(invalid(
			"OpenJDK のリスクマトリックスの列が変更されています",
		));
	}
	let version = ["3.0", "3.1", "4.0"]
		.into_iter()
		.find(|version| headers[2].contains(version));
	let columns: Vec<_> = headers
		.iter()
		.enumerate()
		.skip(3)
		.filter_map(|(column, name)| {
			let major: u16 = name.parse().ok()?;
			SUPPORTED_JAVA_MAJORS
				.contains(&major)
				.then_some((column, major))
		})
		.collect();
	let mut included = BTreeMap::new();
	let mut findings = Vec::new();
	for row in rows {
		let cells: Vec<_> = row.select(&data_cell).collect();
		if cells.len() != headers.len() {
			return Err(invalid(
				"OpenJDK のリスクマトリックスの行が変更されています",
			));
		}
		let cve = visible_text(cells[0]);
		if !valid_cve(&cve) {
			return Err(invalid("OpenJDK が掲載した CVE 番号を確認できません"));
		}
		let mut majors = Vec::new();
		for &(column, major) in &columns {
			match visible_text(cells[column]).as_str() {
				"" => (),
				"•" => {
					let release = releases
						.get(&major)
						.ok_or_else(|| invalid("CVE の対象バージョンが勧告に記載されていません"))?;
					included.insert(major, release);
					majors.push(major);
				}
				_ => return Err(invalid("OpenJDK の対象系列の記号が変更されています")),
			}
		}
		if majors.is_empty() {
			continue;
		}
		let component = visible_text(cells[1]).replace("/ ", "/");
		let score = cells[2]
			.text()
			.next()
			.and_then(|value| value.trim().parse::<f64>().ok());
		let cvss = version
			.zip(score)
			.map(|(version, score)| json!({"version": version, "score": score}));
		findings.push(json!({
			"cve": cve, "cvss": cvss, "majors": majors,
			"summary": {
				"ja": format!("OpenJDK {component} の脆弱性"),
				"en": format!("Vulnerability in OpenJDK {component}"),
			},
			"condition": {
				"ja": "OpenJDK の勧告に掲載されています。Temurin の影響範囲と修正ビルドは公式の配布情報で確認してください。",
				"en": "OpenJDK lists this issue. Check the official Temurin release information for affected and fixed builds.",
			},
		}));
	}
	if findings.is_empty() {
		return Ok(None);
	}
	let series: Vec<_> = included
		.into_iter()
		.map(|(major, release)| {
			json!({
				"major": major, "listed_release": release, "requires_review": true,
				"includes_earlier": affected.contains("and earlier"),
			})
		})
		.collect();
	Ok(Some(json!({
		"product": "temurin", "details_url": url, "updates_url": UPDATES,
		"series": series, "findings": findings,
	})))
}

//------------------------------------------------------------------------------
/**
 * 勧告本文の対象バージョンを系列ごとに取り出し、複数あれば最も新しいものを残します
 */
//------------------------------------------------------------------------------
fn affected_versions(text: &str) -> BTreeMap<u16, &str> {
	let mut versions = BTreeMap::<u16, &str>::new();
	for release in text.split(|character: char| !character.is_ascii_digit() && character != '.') {
		let Some(major) = release
			.split('.')
			.next()
			.and_then(|part| part.parse::<u16>().ok())
		else {
			continue;
		};
		if !SUPPORTED_JAVA_MAJORS.contains(&major) {
			continue;
		}
		let Some(version) = Version::parse(&format!("{release}+0")) else {
			continue;
		};
		if versions
			.get(&major)
			.and_then(|current| Version::parse(&format!("{current}+0")))
			.is_none_or(|current| version > current)
		{
			versions.insert(major, release);
		}
	}
	versions
}

//------------------------------------------------------------------------------
/**
 * HTML の子要素をまたぐ空白を整理し、表示用の文字を取り出します
 */
//------------------------------------------------------------------------------
fn visible_text(element: ElementRef<'_>) -> String {
	element
		.text()
		.flat_map(str::split_whitespace)
		.collect::<Vec<_>>()
		.join(" ")
}

//------------------------------------------------------------------------------
/**
 * 公式勧告の構造を解釈できない場合のエラーを作ります
 */
//------------------------------------------------------------------------------
fn invalid(message: &'static str) -> io::Error {
	io::Error::new(io::ErrorKind::InvalidData, message)
}
