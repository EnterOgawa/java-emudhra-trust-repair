//------------------------------------------------------------------------------
/*!
 * - ファイル: advisory_file.rs
 * - 概要: 内蔵・手動配置・自動更新の勧告定義を使って Java を照合します
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
 * Ver.01.01.00  Shunji Ogawa  2026/11/19  取得済み定義の選択と実行中の再照合を追加
 * Ver.01.01.01  Shunji Ogawa  2026/11/19  ユーザー領域の定義キャッシュを通常権限に限定
 * ```
 *
 * 備考:
 *
 * 定義を Java フォルダやカレントディレクトリから読み込みません
 */
//------------------------------------------------------------------------------

use std::io::ErrorKind;
use std::path::{Component, PathBuf, Prefix};
use std::time::Instant;

use trust_repair_windows::{JavaEnvironment, JavaRuntime};

use crate::advisory::{self, Catalog, CatalogError, Report};

// 手動配置とユーザー別の更新領域でファイル名を共用する
pub(super) const FILE_NAME: &str = "java-advisories.json";

/// 照合に使った勧告定義の取得元です
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Source {
	/// 外部定義がないため、アプリに含まれる定義を使用した
	Embedded,
	/// 実行ファイルの隣にある検証済みの定義を使用した
	External,
	/// 公式勧告を確認して作った定義を使用した
	Downloaded,
	/// 保存済み定義を利用できず、内蔵定義を使用した
	Fallback,
}

/// 再照合に必要な、選択済み Java のプロパティです
pub(super) struct Selection {
	/// 照合済みの配布元
	vendor: String,
	/// 照合済みの Java のバージョン
	release: String,
	/// 対応 Java 系列
	major: u16,
	/// 実際に取得できた Java の実行時情報
	runtime: Option<JavaRuntime>,
}

/// Java と収録勧告を照合した結果および定義の取得元です
pub(super) struct AdvisoryResult {
	/// 選択 Java の版情報と勧告ごとの判定
	pub(super) report: Report,
	/// 読み取った定義の出所
	pub(super) source: Source,
	/// 同じ Java を読み込み直さずに定義のみ変えて再照合するための情報
	pub(super) selection: Option<Box<Selection>>,
	/// 選択 worker が保存済み定義を読み始めた時刻
	pub(super) read_started_at: Instant,
}

impl AdvisoryResult {
	//------------------------------------------------------------------------------
	/**
	 * 配布された定義が現在の定義と同日以降なら、取得済みの Java 情報と再照合します
	 *
	 * # Returns
	 *
	 * 定義を差し替えて再照合した場合は `true`。同日の手動配置を優先します
	 */
	//------------------------------------------------------------------------------
	pub(super) fn apply_download(&mut self, catalog: &Catalog) -> bool {
		let Some(selection) = &self.selection else {
			return false;
		};
		let date = self.report.catalog_date.as_str();
		if catalog.date() < date || (catalog.date() == date && self.source == Source::External) {
			return false;
		}
		self.report = catalog.assess_runtime(
			&selection.vendor,
			&selection.release,
			selection.major,
			selection.runtime.as_ref(),
		);
		self.source = Source::Downloaded;
		true
	}
}

//------------------------------------------------------------------------------
/**
 * ユーザー別の自動更新領域を返します。この時点ではフォルダを作りません
 */
//------------------------------------------------------------------------------
pub(super) fn cache_directory() -> Option<PathBuf> {
	if !trust_repair_windows::can_use_advisory_cache() {
		return None;
	}
	std::env::var_os("LOCALAPPDATA")
		.map(PathBuf::from)
		.filter(|path| path.is_absolute())
		.filter(|path| {
			matches!(path.components().next(), Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_)))
				&& !path.components().any(|component| component == Component::ParentDir)
		})
		.map(|path| path.join("EnterSystem/JavaTrustRepair/advisories"))
}

//------------------------------------------------------------------------------
/**
 * Java の確認ごとに勧告定義を読み、利用できない外部定義は判定に混ぜません
 *
 * # Arguments
 *
 * - `environment`: 選択した Java の照合済み情報
 *
 * # Returns
 *
 * 読み取った定義の取得元と、選択した Java に対する判定
 */
//------------------------------------------------------------------------------
pub(super) fn assess(environment: &JavaEnvironment) -> AdvisoryResult {
	let read_started_at = Instant::now();
	let external = std::env::current_exe()
		.map_err(|error| CatalogError::Io(error.kind()))
		.and_then(|exe| Catalog::load(&exe.with_file_name(FILE_NAME)));
	let downloaded = cache_directory()
		.ok_or(CatalogError::Io(ErrorKind::NotFound))
		.and_then(|path| Catalog::load(&path.join(FILE_NAME)));
	// 両方を検証し、最も新しい定義を使う。当日分が同じ日付なら手動配置を優先する
	let (source, report) = match (external, downloaded) {
		(Ok(manual), Ok(cache)) if cache.date() > manual.date() => {
			(Source::Downloaded, cache.assess(environment))
		}
		(Ok(manual), _) => (Source::External, manual.assess(environment)),
		(_, Ok(cache)) => (Source::Downloaded, cache.assess(environment)),
		(
			Err(CatalogError::Io(ErrorKind::NotFound)),
			Err(CatalogError::Io(ErrorKind::NotFound)),
		) => (Source::Embedded, advisory::assess(environment)),
		_ => (Source::Fallback, advisory::assess(environment)),
	};
	AdvisoryResult {
		report,
		source,
		selection: Some(Box::new(Selection {
			vendor: environment.vendor().to_owned(),
			release: environment.version().to_owned(),
			major: environment.major(),
			runtime: environment.runtime().cloned(),
		})),
		read_started_at,
	}
}
