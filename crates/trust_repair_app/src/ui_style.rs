//------------------------------------------------------------------------------
/*!
 * - ファイル: ui_style.rs
 * - 概要: OSのMSゴシックと従来のWindowsダイアログ風の表示を設定します。
 * - バージョン: 01.00.00
 * - 作成日: 2026/10/26
 * - 制作者: Shunji Ogawa
 * - 著作権: Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * ライセンス: SPDX-License-Identifier: Apache-2.0
 * Apache License, Version 2.0。全文はルートの LICENSE を参照してください。
 *
 * 会社名: EnterSystem
 *
 * 更新履歴:
 * ```text
 * Ver.01.00.00  Shunji Ogawa  2026/10/26  MS Gothicのface照合とfallback、四角い小型の表示を追加。
 * ```
 *
 * 備考: MSフォントはOSから読むだけです。埋込み・保存・再配布しません。
 */
//------------------------------------------------------------------------------

use eframe::egui::{self, Color32, FontFamily, FontId, Stroke};
use skrifa::{MetadataProvider, raw::FileRef, string::StringId};
use std::path::PathBuf;

// MS Gothicにない文字と未搭載時の表示を保証する既存のOFL資材
pub(super) const JAPANESE_FONT: &[u8] = include_bytes!("../../../assets/NotoSansJP.ttf");
const MS_GOTHIC: &str = "MS Gothic";

/// 設定するフォント群と、実行時に選んだ出典です。元fontのbyteを保存しません。
pub(super) struct UiFonts {
	/// eguiへ所有権を渡すfont定義。
	pub(super) definitions: egui::FontDefinitions,
	/// QAで照合する、選択したfamily/source/faceの説明。
	pub(super) source: String,
}

//------------------------------------------------------------------------------
/** TTCを含むfontのfamily名を厳密照合し、MS PGothic/MS UI Gothicを選ばずface番号を返します。 */
//------------------------------------------------------------------------------
fn ms_gothic_face(bytes: &[u8]) -> Option<u32> {
	FileRef::new(bytes)
		.ok()?
		.fonts()
		.enumerate()
		.find_map(|(index, face)| {
			let face = face.ok()?;
			face.localized_strings(StringId::FAMILY_NAME)
				.any(|name| name.to_string() == MS_GOTHIC)
				.then_some(index as u32)
		})
}

//------------------------------------------------------------------------------
/** 読み取り済みOS fontだけを優先登録します。欠落・破損・別familyは既存Notoへ戻します。 */
//------------------------------------------------------------------------------
fn fonts_with_system(system: Option<(PathBuf, Vec<u8>)>) -> UiFonts {
	let mut definitions = egui::FontDefinitions::default();
	let mut japanese = egui::FontData::from_static(JAPANESE_FONT);
	// Notoだけの可変weightを400へ固定する。MS Gothicへは適用しない
	japanese.tweak.coords = egui::epaint::text::VariationCoords::new([(b"wght", 400.0)]);
	definitions
		.font_data
		.insert("Noto Sans JP".to_owned(), japanese.into());
	for family in [FontFamily::Proportional, FontFamily::Monospace] {
		definitions
			.families
			.entry(family)
			.or_default()
			.insert(0, "Noto Sans JP".to_owned());
	}
	let mut source = "Noto Sans JP; embedded OFL fallback; face=0".to_owned();
	if let Some((path, bytes)) = system
		&& let Some(index) = ms_gothic_face(&bytes)
	{
		let mut data = egui::FontData::from_owned(bytes);
		data.index = index;
		definitions
			.font_data
			.insert(MS_GOTHIC.to_owned(), data.into());
		for family in [FontFamily::Proportional, FontFamily::Monospace] {
			definitions
				.families
				.entry(family)
				.or_default()
				.insert(0, MS_GOTHIC.to_owned());
		}
		source = format!(
			"{MS_GOTHIC}; source={}; face={index}; fallback=Noto Sans JP",
			path.display()
		);
	}
	UiFonts {
		definitions,
		source,
	}
}

//------------------------------------------------------------------------------
/** OSのWindowsディレクトリからmsgothic.ttcを読むだけで、失敗時も起動可能な定義を返します。 */
//------------------------------------------------------------------------------
pub(super) fn fonts() -> UiFonts {
	let system = trust_repair_windows::windows_fonts_directory()
		.map(|directory| directory.join("msgothic.ttc"))
		.and_then(|path| std::fs::read(&path).ok().map(|bytes| (path, bytes)));
	fonts_with_system(system)
}

//------------------------------------------------------------------------------
/** 同じeframe画面の本文・入力・ボタン・詳細・modalに、灰色背景と四角い細枠を適用します。 */
//------------------------------------------------------------------------------
pub(super) fn configure(context: &egui::Context) -> String {
	let fonts = fonts();
	context.set_fonts(fonts.definitions);
	context.set_theme(egui::Theme::Light);
	context.set_visuals(egui::Visuals::light());
	context.style_mut_of(egui::Theme::Light, |style| {
		for text_style in [
			egui::TextStyle::Body,
			egui::TextStyle::Button,
			egui::TextStyle::Monospace,
		] {
			style
				.text_styles
				.insert(text_style, FontId::new(13.0, FontFamily::Proportional));
		}
		style
			.text_styles
			.insert(egui::TextStyle::Heading, FontId::proportional(14.0));
		style
			.text_styles
			.insert(egui::TextStyle::Small, FontId::proportional(12.0));
		style.spacing.item_spacing = egui::vec2(6.0, 4.0);
		style.spacing.button_padding = egui::vec2(8.0, 3.0);
		style.spacing.interact_size = egui::vec2(72.0, 23.0);
		style.spacing.window_margin = egui::Margin::same(12);
		style.spacing.menu_margin = egui::Margin::same(8);
		let visuals = &mut style.visuals;
		let dialog = Color32::from_rgb(240, 240, 240);
		visuals.panel_fill = dialog;
		visuals.window_fill = dialog;
		visuals.extreme_bg_color = Color32::WHITE;
		visuals.text_edit_bg_color = Some(Color32::WHITE);
		visuals.faint_bg_color = Color32::from_gray(234);
		visuals.code_bg_color = dialog;
		visuals.weak_text_color = Some(Color32::from_gray(65));
		visuals.window_stroke = Stroke::new(1.0, Color32::from_gray(120));
		visuals.window_corner_radius = egui::CornerRadius::ZERO;
		visuals.menu_corner_radius = egui::CornerRadius::ZERO;
		visuals.window_shadow = egui::epaint::Shadow::NONE;
		visuals.popup_shadow = egui::epaint::Shadow::NONE;
		visuals.interact_cursor = None;
		visuals.selection.bg_fill = Color32::from_rgb(204, 228, 247);
		visuals.selection.stroke = Stroke::new(1.0, Color32::from_rgb(0, 90, 158));
		for widget in [
			&mut visuals.widgets.noninteractive,
			&mut visuals.widgets.inactive,
			&mut visuals.widgets.hovered,
			&mut visuals.widgets.active,
			&mut visuals.widgets.open,
		] {
			widget.corner_radius = egui::CornerRadius::ZERO;
			widget.bg_fill = Color32::from_gray(225);
			widget.weak_bg_fill = Color32::from_gray(225);
			widget.bg_stroke = Stroke::new(1.0, Color32::from_gray(135));
			widget.fg_stroke = Stroke::new(1.0, Color32::BLACK);
			widget.expansion = 0.0;
		}
		visuals.widgets.noninteractive.bg_stroke.color = Color32::from_gray(175);
		visuals.widgets.hovered.bg_fill = Color32::from_rgb(229, 241, 251);
		visuals.widgets.hovered.weak_bg_fill = Color32::from_rgb(229, 241, 251);
		visuals.widgets.hovered.bg_stroke.color = Color32::from_rgb(0, 120, 215);
		visuals.widgets.active.bg_fill = Color32::from_rgb(204, 228, 247);
		visuals.widgets.active.weak_bg_fill = Color32::from_rgb(204, 228, 247);
		visuals.widgets.active.bg_stroke.color = Color32::from_rgb(0, 90, 158);
	});
	fonts.source
}

//------------------------------------------------------------------------------
/** 既存widgetの意味とhit領域を変えず、内側の明暗線だけで立体枠を描きます。 */
//------------------------------------------------------------------------------
fn bevel(ui: &egui::Ui, response: &egui::Response, sunken: bool) {
	let rect = response.rect.shrink(0.5);
	let light = Color32::WHITE;
	let dark = Color32::from_gray(if response.enabled() { 110 } else { 170 });
	let (leading, trailing) = if sunken { (dark, light) } else { (light, dark) };
	ui.painter().line_segment(
		[rect.left_bottom(), rect.left_top()],
		Stroke::new(1.0, leading),
	);
	ui.painter().line_segment(
		[rect.left_top(), rect.right_top()],
		Stroke::new(1.0, leading),
	);
	ui.painter().line_segment(
		[rect.right_top(), rect.right_bottom()],
		Stroke::new(1.0, trailing),
	);
	ui.painter().line_segment(
		[rect.right_bottom(), rect.left_bottom()],
		Stroke::new(1.0, trailing),
	);
}

//------------------------------------------------------------------------------
/** 標準egui Buttonへ立体枠とfocus枠を追加します。click/keyboard/accessibilityは元の部品に任せます。 */
//------------------------------------------------------------------------------
pub(super) fn button(ui: &mut egui::Ui, button: egui::Button<'_>, enabled: bool) -> egui::Response {
	let response = ui.add_enabled(enabled, button);
	let pressed = response.is_pointer_button_down_on()
		|| (response.has_focus() && ui.input(|input| input.key_down(egui::Key::Space)));
	bevel(ui, &response, pressed);
	if response.has_focus() {
		ui.painter().rect_stroke(
			response.rect.shrink(3.0),
			egui::CornerRadius::ZERO,
			Stroke::new(1.0, Color32::from_rgb(0, 90, 158)),
			egui::StrokeKind::Inside,
		);
	}
	response
}

//------------------------------------------------------------------------------
/** 標準TextEditのresponseへ凹枠を描きます。入力・selection・IME・accessibilityを変更しません。 */
//------------------------------------------------------------------------------
pub(super) fn text_edit_frame(ui: &egui::Ui, response: &egui::Response) {
	bevel(ui, response, true);
	if response.has_focus() {
		ui.painter().rect_stroke(
			response.rect.shrink(1.5),
			egui::CornerRadius::ZERO,
			Stroke::new(1.0, Color32::from_rgb(0, 90, 158)),
			egui::StrokeKind::Inside,
		);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	//------------------------------------------------------------------------------
	/** 未搭載・不正データでもNotoを両familyの先頭に維持し、別familyをMS Gothicと誤認しません。 */
	//------------------------------------------------------------------------------
	#[test]
	fn falls_back_for_missing_invalid_or_unrelated_font() {
		for system in [
			None,
			Some((PathBuf::from("invalid"), vec![0, 1, 2])),
			Some((PathBuf::from("unrelated"), JAPANESE_FONT.to_vec())),
		] {
			let fonts = fonts_with_system(system);
			assert!(fonts.source.contains("embedded OFL fallback"));
			assert!(!fonts.definitions.font_data.contains_key(MS_GOTHIC));
			for family in [FontFamily::Proportional, FontFamily::Monospace] {
				assert_eq!(fonts.definitions.families[&family][0], "Noto Sans JP");
			}
		}
	}
}
