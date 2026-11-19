//------------------------------------------------------------------------------
/*!
 * - ファイル: advisory_view.rs
 * - 概要: 選択した Java の勧告、対応方法、参照先を表示します
 * - バージョン: 01.05.01
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
 * Ver.01.01.00  Shunji Ogawa  2026/11/19  ダウンロードリンクの追加とバージョン表記の統一
 * Ver.01.02.00  Shunji Ogawa  2026/11/19  CVE の照合件数を表示し、勧告に共通する案内をまとめる
 * Ver.01.03.00  Shunji Ogawa  2026/11/19  CVE の表と選択行の詳細ダイアログを表示
 * Ver.01.03.01  Shunji Ogawa  2026/11/19  詳細ダイアログの表示幅を拡大し、更新リンクを独立させる
 * Ver.01.03.02  Shunji Ogawa  2026/11/19  CVE の表を対応と確認が必要な項目に絞る
 * Ver.01.04.00  Shunji Ogawa  2026/11/19  CVSS の深刻度列と見出しによる並べ替えを追加
 * Ver.01.04.01  Shunji Ogawa  2026/11/19  初期表示を CVSS 基本値の降順にし、表の下の案内を削除
 * Ver.01.05.00  Shunji Ogawa  2026/11/19  起動時の定義確認と自動更新の出所を表示
 * Ver.01.05.01  Shunji Ogawa  2026/11/19  公式勧告の一部を確認できた場合の案内を追加
 * ```
 *
 * 備考:
 *
 * 勧告データを表示します。リンクは利用者が押したときだけ既定ブラウザーで開きます
 */
//------------------------------------------------------------------------------

use std::cmp::Reverse;

use eframe::egui;

use crate::advisory::{Cvss, Finding, Guidance, Status, Version};
use crate::advisory_file::{AdvisoryResult, Source};
use crate::advisory_update::StartupUpdate;
use crate::language::Language;
use crate::ui_style;

/// 並べ替えでも詳細の参照先が変わらないように元の行番号を保持します
type FindingRow<'a> = (usize, &'a Finding);

/// CVE 一覧の表示列です
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Column {
	/// 公表年と通番を含む CVE 番号
	Cve,
	/// 現在の表示言語の概要
	Summary,
	/// CVSS の深刻度と基本値
	Cvss,
	/// 選択した Java の照合結果
	Status,
	/// 修正された Java のビルド
	FixedBuild,
}

// 見出しと本文の表示順を揃える
const TABLE_COLUMNS: [Column; 5] = [
	Column::Cve,
	Column::Summary,
	Column::Cvss,
	Column::Status,
	Column::FixedBuild,
];

/// 一覧に適用する列と並べ替え方向です
#[derive(Clone, Copy)]
struct TableSort {
	/// 選択中の列
	column: Column,
	/// 降順を選択しているか
	descending: bool,
}

impl TableSort {
	//------------------------------------------------------------------------------
	/**
	 * 行を列の意味に沿って比較します。通番・基本値・ビルド番号は数値として扱います
	 */
	//------------------------------------------------------------------------------
	fn apply(self, language: Language, rows: &mut [FindingRow<'_>]) {
		match self.column {
			Column::Cve => self.by_key(rows, |finding| {
				finding
					.cve
					.rsplit_once('-')
					.and_then(|(year, sequence)| Some((year, sequence.parse::<u64>().ok()?)))
			}),
			Column::Summary => self.by_key(rows, |finding| {
				Some(language.text(&finding.summary.ja, &finding.summary.en))
			}),
			Column::Cvss => self.by_key(rows, |finding| finding.cvss.map(|cvss| cvss.tenths)),
			Column::Status => self.by_key(rows, |finding| Some(finding.status)),
			Column::FixedBuild => self.by_key(rows, |finding| {
				finding
					.guidance
					.as_ref()?
					.fixed_build
					.as_deref()
					.and_then(Version::parse)
			}),
		}
	}

	//------------------------------------------------------------------------------
	/**
	 * 比較キーを一度だけ求め、未収録の基本値や修正版を常に最後に並べます
	 */
	//------------------------------------------------------------------------------
	fn by_key<'a, K: Ord>(
		self,
		rows: &mut [FindingRow<'a>],
		key: impl Fn(&'a Finding) -> Option<K>,
	) {
		if self.descending {
			rows.sort_by_cached_key(|&(_, finding)| {
				let value = key(finding);
				(value.is_none(), Reverse(value))
			});
		} else {
			rows.sort_by_cached_key(|&(_, finding)| {
				let value = key(finding);
				(value.is_none(), value)
			});
		}
	}
}

//------------------------------------------------------------------------------
/**
 * フォルダ欄に対応する CVE と対処方法を折り畳み欄に表示します
 *
 * # Arguments
 *
 * - `ui`: 折り畳み欄を配置する画面
 * - `language`: 利用者への案内に使う表示言語
 * - `result`: 現在の入力世代に対して取得した勧告照合結果
 * - `update`: 起動時の定義確認の状態
 * - `unavailable`: 版を取得できないまま確認が終了したかどうか
 * - `selected_cve`: 表で選んだ CVE の元の行番号。詳細を閉じたら解除します
 */
//------------------------------------------------------------------------------
pub(super) fn draw(
	ui: &mut egui::Ui,
	language: Language,
	result: Option<&AdvisoryResult>,
	update: &StartupUpdate,
	unavailable: bool,
	selected_cve: &mut Option<usize>,
) {
	egui::CollapsingHeader::new(language.text("Java の脆弱性情報", "Java vulnerabilities"))
		.default_open(true)
		.show(ui, |ui| {
			if let Some(message) = match update {
				StartupUpdate::Checking(_) => Some(language.text(
					"Java の公式勧告を確認しています…",
					"Checking official Java advisories…",
				)),
				StartupUpdate::Ready {
					incomplete: true, ..
				} => Some(language.text(
					"一部の公式勧告を確認できませんでした。確認済みの情報を表示します。",
					"Some official advisories could not be checked. Showing the available results.",
				)),
				StartupUpdate::Unavailable => Some(language.text(
					"オンライン更新を確認できなかったため、手元の定義を使用します。",
					"The online update could not be checked. Using a local catalog.",
				)),
				_ => None,
			} {
				ui.small(message);
			}
			// 取得できなかった版の結果と、確認が完了した結果を区別する
			let Some(result) = result else {
				ui.label(if unavailable {
					language.text(
						"選択した Java のバージョンを確認できませんでした。",
						"Could not identify the selected Java version.",
					)
				} else {
					language.text(
						"Java のバージョンを確認しています…",
						"Checking the Java version…",
					)
				});
				return;
			};
			let report = &result.report;
			let vendor = report
				.product
				.map_or(report.vendor.as_str(), |product| product.name());
			ui.label(format!("{vendor}  {}", report.version));

			let source = match result.source {
				Source::Embedded => language.text("内蔵定義", "Built-in catalog"),
				Source::External => language.text("外部定義", "External catalog"),
				Source::Downloaded => language.text("自動更新の定義", "Downloaded catalog"),
				Source::Fallback => language.text(
					"保存済みの定義を利用できないため内蔵定義を使用",
					"The saved catalog could not be loaded. Using the built-in catalog.",
				),
			};
			ui.small(format!("{source}  {}", report.catalog_date));
			ui.small(language.text(
				"選択した Java のバージョンを収録済みの勧告と照合した結果です。",
				"Results cover the advisories in the catalog and the selected Java version.",
			));

			let mut findings: Vec<_> = report
				.findings
				.iter()
				.enumerate()
				.filter(|(_, finding)| {
					matches!(
						finding.status,
						Status::AffectedVersion
							| Status::PotentiallyAffected
							| Status::UnknownVersion
					)
				})
				.collect();
			// 定義の対象外や照合不能の状態と、照合済みで対応不要の状態を区別する
			if report.findings.is_empty() {
				ui.label(status_text(language, report.status));
			} else if findings.is_empty() {
				ui.label(language.text(
					"収録済みの勧告に、対応または確認が必要な項目はありません。",
					"No items in the catalog require action or review for this Java version.",
				));
			} else {
				let affected = findings
					.iter()
					.filter(|(_, finding)| finding.status == Status::AffectedVersion)
					.count();
				let total = findings.len();
				let review = total - affected;
				ui.label(match language {
					Language::Japanese => format!(
						"表示 {total} 件（対象バージョン {affected} 件、要確認 {review} 件）"
					),
					Language::English => format!(
						"{total} CVEs shown ({affected} affecting this version, {review} to review)"
					),
				});
				ui.small(language.text(
					"列の見出しで並べ替え、行をクリックすると詳細を表示します。",
					"Click a column header to sort. Select a row for details.",
				));
				if let Some(row) = draw_table(ui, language, &mut findings, *selected_cve) {
					*selected_cve = Some(row);
				}
				if let Some(finding) = selected_cve.and_then(|index| report.findings.get(index))
					&& draw_detail(ui.ctx(), language, finding, report.download_page.as_deref())
				{
					*selected_cve = None;
				}
			}
		});
}

//------------------------------------------------------------------------------
/**
 * 固定見出しとスクロール領域に同じ列幅を使って CVE の表を描画します
 *
 * # Returns
 *
 * 選択操作があったフレームに限り、並べ替え前の照合結果の行番号を返します
 */
//------------------------------------------------------------------------------
fn draw_table(
	ui: &mut egui::Ui,
	language: Language,
	findings: &mut [FindingRow<'_>],
	selected: Option<usize>,
) -> Option<usize> {
	let frame = egui::Frame::new()
		.fill(ui.visuals().extreme_bg_color)
		.stroke(ui.visuals().widgets.noninteractive.bg_stroke);
	frame
		.show(ui, |ui| {
			ui.spacing_mut().item_spacing.y = 0.0;
			ui.spacing_mut().scroll = egui::style::ScrollStyle::solid();
			let row_height = ui.spacing().interact_size.y;
			let width = (ui.available_width() - ui.spacing().scroll.allocated_width()).max(0.0);
			// 番号と版数の列を揃え、ウィンドウ幅の変化を概要列で吸収する
			let scale = (width / 580.0).min(1.0);
			let widths = [
				122.0 * scale,
				width - 456.0 * scale,
				130.0 * scale,
				84.0 * scale,
				120.0 * scale,
			];
			let (header, _) =
				ui.allocate_exact_size(egui::vec2(width, row_height), egui::Sense::hover());
			let sort_id = ui.make_persistent_id("java-advisory-sort");
			let previous_sort = ui
				.data(|data| data.get_temp::<TableSort>(sort_id))
				.unwrap_or(TableSort {
					column: Column::Cvss,
					descending: true,
				});
			let changed = draw_header(ui, language, header, widths, previous_sort);
			if let Some(sort) = changed {
				ui.data_mut(|data| data.insert_temp(sort_id, sort));
			}
			changed.unwrap_or(previous_sort).apply(language, findings);
			let mut scroll = egui::ScrollArea::vertical()
				.id_salt("java-advisory-findings")
				.max_height(8.0 * row_height)
				.scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
				.auto_shrink([false, true]);
			if changed.is_some() {
				scroll = scroll.vertical_scroll_offset(0.0);
			}
			scroll
				.show_rows(ui, row_height, findings.len(), |ui, rows| {
					let mut clicked = None;
					for row_number in rows {
						let (index, finding) = findings[row_number];
						let summary = language.text(&finding.summary.ja, &finding.summary.en);
						let (_, row) = ui.allocate_space(egui::vec2(width, row_height));
						let response = ui.interact(
							row,
							ui.make_persistent_id(&finding.cve),
							egui::Sense::click(),
						);
						let is_selected = selected == Some(index);
						response.widget_info(|| {
							egui::WidgetInfo::selected(
								egui::Role::Button,
								ui.is_enabled(),
								is_selected,
								format!("{} {summary}", finding.cve),
							)
						});
						if response.clicked() {
							clicked = Some(index);
						}
						let background =
							if is_selected || response.has_focus() || response.hovered() {
								ui.visuals().selection.bg_fill
							} else if row_number % 2 == 0 {
								ui.visuals().extreme_bg_color
							} else {
								ui.visuals().faint_bg_color
							};
						ui.painter().rect_filled(row, 0, background);
						if response.has_focus() {
							ui.painter().rect_stroke(
								row,
								0,
								ui.visuals().selection.stroke,
								egui::StrokeKind::Inside,
							);
						}
						let fixed = finding
							.guidance
							.as_ref()
							.and_then(|guidance| guidance.fixed_build.as_deref())
							.unwrap_or("—");
						let cvss = finding
							.cvss
							.map_or_else(|| "—".to_owned(), |cvss| cvss_text(language, cvss));
						let labels = [
							finding.cve.as_str(),
							summary,
							&cvss,
							row_status(language, finding.status),
							fixed,
						];
						for (cell, label) in cell_rects(row, widths).zip(labels) {
							draw_cell(ui, cell, egui::RichText::new(label));
						}
					}
					clicked
				})
				.inner
		})
		.inner
}

//------------------------------------------------------------------------------
/**
 * クリックできる列見出しを表示し、選んだ列と向きを返します
 */
//------------------------------------------------------------------------------
fn draw_header(
	ui: &mut egui::Ui,
	language: Language,
	row: egui::Rect,
	widths: [f32; 5],
	sort: TableSort,
) -> Option<TableSort> {
	let mut changed = None;
	let stroke = ui.visuals().widgets.noninteractive.bg_stroke;
	for (column, cell) in TABLE_COLUMNS.into_iter().zip(cell_rects(row, widths)) {
		let title = match column {
			Column::Cve => "CVE",
			Column::Summary => language.text("概要", "Summary"),
			Column::Cvss => language.text("CVSS 深刻度", "CVSS severity"),
			Column::Status => language.text("判定", "Status"),
			Column::FixedBuild => language.text("修正版", "Fixed build"),
		};
		let active = (sort.column == column).then_some(sort);
		let response = ui.interact(cell, ui.make_persistent_id(column), egui::Sense::click());
		if response.clicked() {
			changed = Some(TableSort {
				column,
				descending: active
					.map_or(matches!(column, Column::Cvss | Column::Status), |sort| {
						!sort.descending
					}),
			});
			ui.ctx().request_repaint();
		}
		let background = if response.hovered() || response.has_focus() {
			ui.visuals().selection.bg_fill
		} else {
			ui.visuals().faint_bg_color
		};
		ui.painter().rect_filled(cell, 0, background);
		ui.painter().vline(cell.right(), cell.y_range(), stroke);
		let label = match active {
			Some(sort) if sort.descending => format!("{title} ↓"),
			Some(_) => format!("{title} ↑"),
			None => title.to_owned(),
		};
		response
			.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, ui.is_enabled(), &label));
		draw_cell(ui, cell, egui::RichText::new(label).strong());
	}
	ui.painter().hline(row.x_range(), row.bottom(), stroke);
	changed
}

//------------------------------------------------------------------------------
/**
 * 固定見出しと本文に共通する列の位置を左から順に返します
 *
 * # Arguments
 *
 * - `row`: 表の行全体の描画領域
 * - `widths`: 見出しと本文で共通の列幅をポイントで指定
 */
//------------------------------------------------------------------------------
fn cell_rects(row: egui::Rect, widths: [f32; 5]) -> impl Iterator<Item = egui::Rect> {
	widths.into_iter().scan(row.left(), move |left, width| {
		let cell = egui::Rect::from_min_size(
			egui::pos2(*left, row.top()),
			egui::vec2(width, row.height()),
		);
		*left += width;
		Some(cell)
	})
}

//------------------------------------------------------------------------------
/**
 * 文字をセル幅に収めます。概要の全文は詳細に表示します
 */
//------------------------------------------------------------------------------
fn draw_cell(ui: &mut egui::Ui, cell: egui::Rect, label: egui::RichText) {
	let mut cell_ui = ui.new_child(
		egui::UiBuilder::new()
			.max_rect(cell.shrink2(egui::vec2(4.0_f32.min(cell.width() * 0.5), 0.0)))
			.layout(egui::Layout::left_to_right(egui::Align::Center)),
	);
	cell_ui.shrink_clip_rect(cell);
	cell_ui.add(
		egui::Label::new(label)
			.truncate()
			.selectable(false)
			.show_tooltip_when_elided(false),
	);
}

//------------------------------------------------------------------------------
/**
 * CVSS の基本値を FIRST の定義に沿った深刻度と小数一桁で表示します
 */
//------------------------------------------------------------------------------
fn cvss_text(language: Language, cvss: Cvss) -> String {
	let severity = match cvss.tenths {
		0 => language.text("なし", "None"),
		1..=39 => language.text("低", "Low"),
		40..=69 => language.text("中", "Medium"),
		70..=89 => language.text("高", "High"),
		_ => language.text("緊急", "Critical"),
	};
	format!("{severity} {}.{}", cvss.tenths / 10, cvss.tenths % 10)
}

//------------------------------------------------------------------------------
/**
 * 選んだ CVE の全文、利用条件、対処、公式リンクをダイアログに表示します
 *
 * # Returns
 *
 * 閉じる操作が行われた場合は `true` を返します
 */
//------------------------------------------------------------------------------
fn draw_detail(
	context: &egui::Context,
	language: Language,
	finding: &Finding,
	download_page: Option<&str>,
) -> bool {
	let available = context.content_rect().size();
	let modal = egui::Modal::new(egui::Id::unique("java-advisory-detail"))
		.backdrop_color(egui::Color32::from_black_alpha(45))
		.show(context, |ui| {
			ui.set_width((available.x - 40.0).clamp(180.0, 820.0));
			ui.heading(&finding.cve);
			ui.small(status_text(language, finding.status));
			if let Some(cvss) = finding.cvss {
				ui.small(format!(
					"CVSS {}  {}",
					cvss.version,
					cvss_text(language, cvss)
				));
			}
			ui.separator();
			egui::ScrollArea::vertical()
				.max_height((available.y - 140.0).max(80.0))
				.auto_shrink([false, true])
				.show(ui, |ui| {
					ui.label(language.text(&finding.summary.ja, &finding.summary.en));
					if !matches!(finding.status, Status::Fixed | Status::NotAffected) {
						ui.label(language.text(&finding.condition.ja, &finding.condition.en));
					}
					ui.horizontal_wrapped(|ui| {
						ui.hyperlink_to(
							language.text("CVE の詳細", "CVE record"),
							format!("https://www.cve.org/CVERecord?id={}", finding.cve),
						);
						ui.hyperlink_to(
							language.text("公式勧告", "Official advisory"),
							&finding.details_url,
						);
					});
					if let Some(guidance) = &finding.guidance {
						draw_guidance(ui, language, finding.status, guidance, download_page);
					}
				});
			ui.separator();
			ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
				ui_style::button(
					ui,
					egui::Button::new(language.text("閉じる", "Close")),
					true,
				)
				.clicked()
			})
			.inner
		});
	modal.inner || modal.should_close()
}

//------------------------------------------------------------------------------
/**
 * 勧告に記載された修正版、入手先、利用できる場合の暫定策を描画します
 *
 * # Arguments
 *
 * - `download_page`: 選択した配布元・系列の公式配布ページ
 */
//------------------------------------------------------------------------------
fn draw_guidance(
	ui: &mut egui::Ui,
	language: Language,
	status: Status,
	guidance: &Guidance,
	download_page: Option<&str>,
) {
	if let Some(build) = &guidance.fixed_build {
		let text = match (language, status) {
			(Language::Japanese, Status::AffectedVersion | Status::PotentiallyAffected) => {
				format!("対応方法　同じ Java 系列の {build} 以降へ更新してください。")
			}
			(Language::English, Status::AffectedVersion | Status::PotentiallyAffected) => {
				format!("Update to {build} or later in the same Java family.")
			}
			_ => format!(
				"{} {build}",
				language.text("修正を含むバージョン", "Fixed build")
			),
		};
		ui.label(text);
	} else {
		ui.label(language.text("修正を含むバージョンの記載なし", "No fixed build listed"));
	}
	// 長い更新案内でリンクが途中改行されないよう、専用の行に配置する
	ui.horizontal(|ui| {
		ui.hyperlink_to(
			language.text("更新情報", "Update information"),
			&guidance.updates_url,
		);
		// 対象系列を確認できたときだけ公式配布ページへ案内する
		if let Some(url) = download_page {
			ui.hyperlink_to(language.text("ダウンロード", "Download"), url)
				.on_hover_text(language.text(
					"公式配布ページで配布中のバージョンとパッケージを確認できます。",
					"See the official download page for available versions and packages.",
				));
		}
	});
	// 当該 CVE の修正後または影響範囲外では、暫定策を案内しない
	if !matches!(status, Status::Fixed | Status::NotAffected)
		&& let Some(workaround) = &guidance.workaround
	{
		ui.small(format!(
			"{} {}",
			language.text("暫定策", "Workaround"),
			language.text(&workaround.ja, &workaround.en)
		));
	}
}

//------------------------------------------------------------------------------
/**
 * 表の判定列に収まる短い表示を返します
 */
//------------------------------------------------------------------------------
fn row_status(language: Language, status: Status) -> &'static str {
	match status {
		Status::AffectedVersion => language.text("対象", "Affected"),
		Status::PotentiallyAffected => language.text("要確認", "Review"),
		Status::Fixed => language.text("修正済み", "Fixed"),
		Status::NotAffected => language.text("対象外", "Not affected"),
		Status::UnknownVersion => language.text("判定不可", "Unknown"),
		Status::Unsupported => language.text("定義対象外", "Unsupported"),
	}
}

//------------------------------------------------------------------------------
/**
 * 版の照合結果を、収録された勧告に範囲を限定して案内します
 */
//------------------------------------------------------------------------------
fn status_text(language: Language, status: Status) -> &'static str {
	// 対象版と確認の必要な版を分け、判定不能を脆弱性なしへ変換しない
	match status {
		Status::AffectedVersion => {
			language.text("勧告の対象バージョン", "Version listed as affected")
		}
		Status::PotentiallyAffected => language.text(
			"影響の可能性あり・要確認",
			"Possible impact. Review required.",
		),
		Status::Fixed => language.text(
			"収録勧告の修正を含むバージョン",
			"Version includes this fix",
		),
		Status::NotAffected => language.text("この CVE の対象外", "Not affected by this CVE"),
		Status::UnknownVersion => language.text(
			"バージョンやビルドを判定できません",
			"Version or build could not be matched",
		),
		Status::Unsupported => language.text(
			"この配布元・系列は定義の対象外です",
			"Catalog does not cover this distribution or Java family",
		),
	}
}
