//------------------------------------------------------------------------------
/*!
 * - ファイル: advisory_update.rs
 * - 概要: アプリの起動時に勧告定義を取得し、検証済みの定義を保存します
 * - バージョン: 01.01.01
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
 * Ver.01.01.00  Shunji Ogawa  2026/11/19  公式勧告から配布元ごとの追加定義を作り保存
 * Ver.01.01.01  Shunji Ogawa  2026/11/19  管理者権限では取得した定義をメモリ内で利用
 * ```
 *
 * 備考:
 *
 * 通信と保存はバックグラウンドで行い、選択した Java の情報を送信しません
 */
//------------------------------------------------------------------------------

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant};

use eframe::egui;
use serde_json::{Value, json};
use tempfile::NamedTempFile;

use crate::advisory::{Catalog, valid_date};
use crate::advisory_file::{AdvisoryResult, FILE_NAME, cache_directory};
use crate::{openjdk_advisory, oracle_advisory};

// 内蔵定義の対象期間に重なる最終勧告から、初回確認を始める
const STARTING_ADVISORY_DATE: &str = "2026-11-17";
// Oracle の CSAF は Java 以外も含むため、取り込む定義とは別の容量上限を設ける
const MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;
const BUNDLED: &[u8] = include_bytes!("../../../data/java-advisories.json");

/// 検証済み定義の取得結果と、未確認の配布元があるかを保持します
type CheckedCatalog = (Catalog, bool);

/// 起動時の確認と、現在のウィンドウで再照合に使える保存済み定義です
pub(super) enum StartupUpdate {
	/// 更新を開始していない状態
	Idle,
	/// 更新用スレッドの結果を待っている状態
	Checking(Receiver<io::Result<(CheckedCatalog, Option<Instant>)>>),
	/// 検証済みの有効な定義を確認した状態
	Ready {
		/// 確認した検証済み定義
		catalog: Catalog,
		/// キャッシュへ保存した時刻。メモリ内でだけ使う場合は `None`
		stored_at: Option<Instant>,
		/// 片方の配布元の勧告を確認できなかったか
		incomplete: bool,
	},
	/// 通信、検証または保存に失敗した状態
	Unavailable,
}

impl StartupUpdate {
	//------------------------------------------------------------------------------
	/**
	 * 起動直後に一度だけ定義の確認を開始します
	 *
	 * # Notes
	 *
	 * ウィンドウの終了時は通信を待ちません。未確定の書込みは一時ファイルに留めます
	 */
	//------------------------------------------------------------------------------
	pub(super) fn start(context: &egui::Context) -> Self {
		let directory = cache_directory();
		let context = context.clone();
		let (sender, receiver) = mpsc::channel();
		let spawned = std::thread::Builder::new()
			.name("java-advisory-update".to_owned())
			.spawn(move || {
				let deadline = Instant::now() + Duration::from_secs(60);
				let collect = |input: &[u8]| {
					collect_sources(input, |url| {
						if Instant::now() >= deadline {
							return Err(io::ErrorKind::TimedOut.into());
						}
						trust_repair_windows::fetch_official_advisory(url, MAX_DOCUMENT_BYTES)
					})
				};
				let result = if let Some(directory) = directory {
					synchronize(&directory, collect).map(|catalog| (catalog, Some(Instant::now())))
				} else {
					collect(BUNDLED)
						.and_then(|(bytes, incomplete)| Ok(((validate(&bytes)?, incomplete), None)))
				};
				let _ = sender.send(result);
				context.request_repaint();
			});
		if spawned.is_ok() {
			Self::Checking(receiver)
		} else {
			Self::Unavailable
		}
	}

	//------------------------------------------------------------------------------
	/**
	 * 待機せずに更新結果を回収します。検証済み定義が利用可能になった直後は `true` を返します
	 */
	//------------------------------------------------------------------------------
	pub(super) fn poll(&mut self, context: &egui::Context) -> bool {
		let Self::Checking(receiver) = self else {
			return false;
		};
		match receiver.try_recv() {
			Ok(Ok(((catalog, incomplete), stored_at))) => {
				*self = Self::Ready {
					catalog,
					stored_at,
					incomplete,
				}
			}
			Ok(Err(_)) | Err(TryRecvError::Disconnected) => *self = Self::Unavailable,
			Err(TryRecvError::Empty) => {
				// スレッドが通知前に終了しても切断を回収できるようにする
				context.request_repaint_after(Duration::from_millis(500));
				return false;
			}
		}
		matches!(self, Self::Ready { .. })
	}

	//------------------------------------------------------------------------------
	/**
	 * 以前の定義を読んだ場合、またはメモリ内にだけ定義を保持する場合に再照合します
	 */
	//------------------------------------------------------------------------------
	pub(super) fn apply_to(&self, result: &mut AdvisoryResult) -> bool {
		matches!(self, Self::Ready { catalog, stored_at, .. }
			if stored_at.is_none_or(|time| result.read_started_at <= time) && result.apply_download(catalog))
	}
}

//------------------------------------------------------------------------------
/**
 * 一つのプロセスだけが取得から保存までを行い、検証済みの最新定義を返します
 *
 * # Errors
 *
 * 取得、検証、保存または排他取得のいずれかが失敗した場合。既存の定義を保持します
 */
//------------------------------------------------------------------------------
fn synchronize(
	directory: &Path,
	collect: impl FnOnce(&[u8]) -> io::Result<(Vec<u8>, bool)>,
) -> io::Result<CheckedCatalog> {
	fs::create_dir_all(directory)?;
	let lock = File::options()
		.read(true)
		.write(true)
		.create(true)
		.truncate(false)
		.open(directory.join("update.lock"))?;
	lock.try_lock().map_err(io::Error::from)?;
	let path = directory.join(FILE_NAME);
	let saved = Catalog::read_bytes(&path).ok().and_then(|bytes| {
		Catalog::from_bytes(&bytes)
			.ok()
			.map(|catalog| (bytes, catalog))
	});
	let baseline = saved
		.as_ref()
		.map_or(BUNDLED, |(bytes, _)| bytes.as_slice());
	let (bytes, incomplete) = collect(baseline)?;
	let catalog = validate(&bytes)?;
	if let Some((_, current)) = saved
		&& (current.date() > catalog.date() || current == catalog)
	{
		return Ok((current, incomplete));
	}
	let mut staged = NamedTempFile::new_in(directory)?;
	staged.write_all(&bytes)?;
	staged.as_file().sync_all()?;
	staged.persist(&path).map_err(|error| error.error)?;
	Ok((catalog, incomplete))
}

//------------------------------------------------------------------------------
/**
 * 公式勧告を配布元別に確認し、成功した配布元の候補だけを定義へ反映します
 */
//------------------------------------------------------------------------------
fn collect_sources(
	input: &[u8],
	mut fetch: impl FnMut(&str) -> io::Result<Vec<u8>>,
) -> io::Result<(Vec<u8>, bool)> {
	let mut merged: Value = serde_json::from_slice(input).map_err(io::Error::other)?;
	let mut successes = 0;
	let mut last_error = None;
	for product in ["temurin", "oracle_java_se"] {
		let since = merged["official_through"][product]
			.as_str()
			.unwrap_or(STARTING_ADVISORY_DATE);
		let result = if product == "temurin" {
			openjdk_advisory::collect(&mut fetch, since)
		} else {
			oracle_advisory::collect(&mut fetch, since)
		};
		let combined = result
			.and_then(|(date, additions)| add_verified(&merged, product, since, &date, additions));
		match combined {
			Ok(document) => {
				merged = document;
				successes += 1;
			}
			Err(error) => last_error = Some(error),
		}
	}
	if successes == 0 {
		return Err(last_error.unwrap_or_else(|| io::Error::other("公式勧告の確認に失敗しました")));
	}
	let bytes = serde_json::to_vec(&merged).map_err(io::Error::other)?;
	Ok((bytes, last_error.is_some()))
}

//------------------------------------------------------------------------------
/**
 * 収録済みの勧告を保持し、まだ収録していない製品・CVE・系列だけを追加します
 */
//------------------------------------------------------------------------------
fn add_verified(
	base: &Value,
	product: &str,
	since: &str,
	date: &str,
	additions: Vec<Value>,
) -> io::Result<Value> {
	if !valid_date(date) || date < since {
		return Err(io::Error::new(
			io::ErrorKind::InvalidData,
			"公式勧告の確認日が無効です",
		));
	}
	let mut candidate = base.clone();
	let records = candidate["advisories"]
		.as_array_mut()
		.expect("validated base catalog");
	let mut covered = HashSet::new();
	for record in records
		.iter()
		.filter(|record| record["product"].as_str() == Some(product))
	{
		for finding in record["findings"].as_array().expect("validated findings") {
			let cve = finding["cve"].as_str().expect("validated CVE");
			for major in finding["majors"].as_array().expect("validated major list") {
				covered.insert((cve.to_owned(), major.as_u64()));
			}
		}
	}
	for mut advisory in additions {
		if advisory["product"].as_str() != Some(product) {
			return Err(io::Error::new(
				io::ErrorKind::InvalidData,
				"公式勧告の製品が一致しません",
			));
		}
		let mut included = HashSet::new();
		let findings = advisory["findings"].as_array_mut().ok_or_else(|| {
			io::Error::new(io::ErrorKind::InvalidData, "公式勧告の CVE が無効です")
		})?;
		for finding in findings.iter_mut() {
			let cve = finding["cve"].as_str().unwrap_or_default().to_owned();
			let majors = finding["majors"].as_array_mut().ok_or_else(|| {
				io::Error::new(io::ErrorKind::InvalidData, "公式勧告の対象系列が無効です")
			})?;
			majors.retain(|major| covered.insert((cve.clone(), major.as_u64())));
			included.extend(majors.iter().map(Value::as_u64));
		}
		findings.retain(|finding| {
			finding["majors"]
				.as_array()
				.is_some_and(|majors| !majors.is_empty())
		});
		if included.is_empty() {
			continue;
		}
		advisory["series"]
			.as_array_mut()
			.ok_or_else(|| {
				io::Error::new(io::ErrorKind::InvalidData, "公式勧告の対象系列が無効です")
			})?
			.retain(|series| included.contains(&series["major"].as_u64()));
		records.push(advisory);
	}
	if candidate["verified_on"]
		.as_str()
		.is_some_and(|verified| date > verified)
	{
		candidate["verified_on"] = json!(date);
	}
	candidate["official_through"][product] = json!(date);
	validate(&serde_json::to_vec(&candidate).map_err(io::Error::other)?)?;
	Ok(candidate)
}

//------------------------------------------------------------------------------
/**
 * 定義の検証結果を起動時の確認処理で扱う I/O の結果に変換します
 */
//------------------------------------------------------------------------------
fn validate(bytes: &[u8]) -> io::Result<Catalog> {
	Catalog::from_bytes(bytes)
		.map_err(|error| io::Error::new(io::ErrorKind::InvalidData, format!("{error:?}")))
}

/// 起動時の取得結果による保存と既存定義の保持を確認します
#[cfg(test)]
mod tests {
	use super::{Catalog, FILE_NAME, MAX_DOCUMENT_BYTES, collect_sources, fs, io, synchronize};
	use crate::advisory::{CATALOG_DATE, Status};
	use trust_repair_windows::{JavaRuntime, fetch_official_advisory};

	//------------------------------------------------------------------------------
	/**
	 * 新しい有効な定義を保存し、古い候補・不正な JSON・通信失敗では保存済み定義を保持します
	 */
	//------------------------------------------------------------------------------
	#[test]
	fn preserves_the_latest_valid_download() {
		let directory = tempfile::tempdir().expect("isolated catalog cache");
		let path = directory.path().join(FILE_NAME);
		let bundled = include_str!("../../../data/java-advisories.json");
		let newer = bundled.replace(CATALOG_DATE, "2099-01-02");
		let (first, _) = synchronize(directory.path(), |_| {
			Ok((bundled.as_bytes().to_vec(), false))
		})
		.unwrap();
		assert_eq!(first.date(), CATALOG_DATE);
		let (updated, _) =
			synchronize(directory.path(), |_| Ok((newer.as_bytes().to_vec(), false))).unwrap();
		assert_eq!(updated.date(), "2099-01-02");
		let (retained, _) = synchronize(directory.path(), |_| {
			Ok((bundled.as_bytes().to_vec(), false))
		})
		.unwrap();
		assert_eq!(retained, updated);
		assert!(synchronize(directory.path(), |_| Ok((b"{broken json".to_vec(), false))).is_err());
		assert!(synchronize(directory.path(), |_| Err(io::ErrorKind::TimedOut.into())).is_err());
		assert_eq!(fs::read(&path).unwrap(), newer.as_bytes());
		assert_eq!(Catalog::load(&path).unwrap(), updated);
	}

	//------------------------------------------------------------------------------
	/**
	 * OpenJDK から新しい CVE を加え、配布元不明の修正版を判定せず、Oracle の失敗と独立して保存します
	 */
	//------------------------------------------------------------------------------
	#[test]
	fn adds_openjdk_findings_when_the_oracle_source_is_unavailable() {
		let index =
			br#"<h2 id="advisories">Advisories</h2><ul><li><a href="2099-01-07">New</a></li></ul>"#;
		let page = br#"
			<p>The affected versions are 21.0.25, and earlier. Please note that issues are described below.</p>
			<h2 id="risk-matrix">OpenJDK Risk matrix</h2>
			<table class="risk-matrix">
			<tr><th>CVE ID</th><th>Component</th><th>CVSSv3.1<br>Vector</th><th>21</th><th>27</th></tr>
			<tr><td>CVE-2099-0001</td><td>security-libs/<br>javax.net.ssl</td><td>7.4<br>Vector</td><td>&#8226;</td><td>&#8226;</td></tr>
			<tr><td>CVE-2026-114938</td><td>hotspot/compiler</td><td>8.1<br>Vector</td><td>&#8226;</td><td>&#8226;</td></tr>
			</table>
			<h2 id="jfx-risk-matrix">OpenJFX Risk matrix</h2>
			<table class="risk-matrix"><tr><td>CVE-2099-0002</td></tr></table>"#;
		let directory = tempfile::tempdir().unwrap();
		let (catalog, incomplete) = synchronize(directory.path(), |input| {
			collect_sources(input, |url| {
				if url.ends_with("/advisories/") {
					Ok(index.to_vec())
				} else if url.ends_with("/2099-01-07") {
					Ok(page.to_vec())
				} else {
					Err(io::ErrorKind::TimedOut.into())
				}
			})
		})
		.expect("OpenJDK can be updated independently");
		assert!(incomplete);
		assert_eq!(catalog.date(), "2099-01-07");
		let runtime = JavaRuntime {
			version: "21.0.6+7".to_owned(),
			name: "OpenJDK Runtime Environment".to_owned(),
			vm_name: "OpenJDK 64-Bit Server VM".to_owned(),
			vm_version: "21.0.6+7-LTS".to_owned(),
			vendor_version: Some("Temurin-21.0.6+7".to_owned()),
			has_graalvm_marker: false,
		};
		let report = catalog.assess_runtime("Eclipse Adoptium", "21.0.6", 21, Some(&runtime));
		assert_eq!(report.findings.len(), 84);
		let added = report
			.findings
			.iter()
			.find(|finding| finding.cve == "CVE-2099-0001")
			.unwrap();
		assert_eq!(added.status, Status::PotentiallyAffected);
		assert_eq!(added.cvss.unwrap().tenths, 74);
		assert!(added.guidance.as_ref().unwrap().fixed_build.is_none());
		assert_eq!(
			Catalog::load(&directory.path().join(FILE_NAME)).unwrap(),
			catalog
		);
	}

	//------------------------------------------------------------------------------
	/**
	 * Windows の通信経路で現在の公式索引と勧告を取得し、両配布元の定義を組み立てます
	 */
	//------------------------------------------------------------------------------
	#[test]
	#[ignore = "公式の公開サイトに HTTPS で接続できる場合に実行"]
	fn checks_live_official_sources() {
		let directory = tempfile::tempdir().expect("isolated live catalog cache");
		let (catalog, incomplete) = synchronize(directory.path(), |input| {
			collect_sources(input, |url| {
				fetch_official_advisory(url, MAX_DOCUMENT_BYTES)
			})
		})
		.expect("能動更新用の公式勧告");
		assert!(!incomplete, "両方の公式勧告を確認");
		let path = directory.path().join(FILE_NAME);
		let value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
		assert!(value["official_through"]["temurin"].is_string());
		assert!(value["official_through"]["oracle_java_se"].is_string());
		assert_eq!(Catalog::load(&path).unwrap(), catalog);
	}
}
