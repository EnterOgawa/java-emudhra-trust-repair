//------------------------------------------------------------------------------
/*!
 * - ファイル: ui_style.rs
 * - 概要: OSのMSゴシックと従来のWindowsダイアログ風の表示を設定します
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
 * MSフォントはOSから読むだけです。埋込み・保存・再配布しません
 */
//------------------------------------------------------------------------------

use eframe::egui::{self, Color32, FontFamily, FontId, Stroke};
use skrifa::{MetadataProvider, raw::FileRef, string::StringId};
use std::path::PathBuf;

// MS Gothicにない文字と未搭載時の表示を保証する既存のOFL資材
pub(super) const JAPANESE_FONT: &[u8] = include_bytes!("../../../assets/NotoSansJP.ttf");
// 比例幅の別 family を選ばないため、厳密照合する family 名を固定する
const MS_GOTHIC: &str = "MS Gothic";

/// 設定するフォント群と、実行時に選んだ出典です。元fontのbyteを保存しません
pub(super) struct UiFonts {
	/// eguiへ所有権を渡すfont定義
	pub(super) definitions: egui::FontDefinitions,
	/// QAで照合する、選択したfamily/source/faceの説明
	pub(super) source: String,
}

//------------------------------------------------------------------------------
/**
 * TTCを含むfontのfamily名を厳密照合し、MS PGothic/MS UI Gothicを選ばずface番号を返します
 *
 * # Returns
 *
 * family が MS Gothic と一致した face 番号。不正 font または該当なしなら `None`
 */
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
/**
 * 読み取り済みOS fontだけを優先登録します。欠落・破損・別familyは既存Notoへ戻します
 *
 * # Arguments
 *
 * - `system`: OS font のパスと読込み済み byte 列。`None` は埋込み font のみを使います
 *
 * # Returns
 *
 * 利用可能なフォント定義と採用元の説明。OS font が使えなければ Noto を先頭にします
 */
//------------------------------------------------------------------------------
fn fonts_with_system(system: Option<(PathBuf, Vec<u8>)>) -> UiFonts {
	let mut definitions = egui::FontDefinitions::default();
	let mut japanese = egui::FontData::from_static(JAPANESE_FONT);
	// Notoだけの可変weightを400へ固定する。MS Gothicへは適用しない
	japanese.tweak.coords = egui::epaint::text::VariationCoords::new([(b"wght", 400.0)]);
	definitions
		.font_data
		.insert("Noto Sans JP".to_owned(), japanese.into());
	// 本文と等幅の両 family に同じ埋込み fallback を登録する
	for family in [FontFamily::Proportional, FontFamily::Monospace] {
		definitions
			.families
			.entry(family)
			.or_default()
			.insert(0, "Noto Sans JP".to_owned());
	}
	let mut source = "Noto Sans JP; embedded OFL fallback; face=0".to_owned();
	// 読めた OS font の family が厳密一致する場合だけ、MS Gothic を優先する
	if let Some((path, bytes)) = system
		&& let Some(index) = ms_gothic_face(&bytes)
	{
		let mut data = egui::FontData::from_owned(bytes);
		data.index = index;
		definitions
			.font_data
			.insert(MS_GOTHIC.to_owned(), data.into());
		// 両 family の先頭へ同じ OS face を入れ、表示箇所ごとの font 差を抑える
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
/**
 * OSのWindowsディレクトリからmsgothic.ttcを読むだけで、失敗時も起動可能な定義を返します
 *
 * # Returns
 *
 * OS font の取得に失敗しても使用できる、埋込み fallback を含む定義と採用元
 */
//------------------------------------------------------------------------------
pub(super) fn fonts() -> UiFonts {
	let system = trust_repair_windows::windows_fonts_directory()
		.map(|directory| directory.join("msgothic.ttc"))
		.and_then(|path| std::fs::read(&path).ok().map(|bytes| (path, bytes)));
	fonts_with_system(system)
}

//------------------------------------------------------------------------------
/**
 * 同じeframe画面の本文・入力・ボタン・詳細・modalに、灰色背景と四角い細枠を適用します
 *
 * # Arguments
 *
 * - `context`: font と表示寸法・色を設定する対象画面
 *
 * # Returns
 *
 * 実際に採用した font の出所。通常表示には使わず QA の記録へ渡せます
 */
//------------------------------------------------------------------------------
pub(super) fn configure(context: &egui::Context) -> String {
	let fonts = fonts();
	context.set_fonts(fonts.definitions);
	context.set_theme(egui::Theme::Light);
	context.set_visuals(egui::Visuals::light());
	context.style_mut_of(egui::Theme::Light, |style| {
		// 本文・button・等幅の基本寸法を揃え、小型の Windows 表示へ合わせる
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
		// 全 widget 状態へ同じ角と細枠の規則を適用し、状態による形状の飛びを抑える
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
/**
 * 既存widgetの意味とhit領域を変えず、内側の明暗線だけで立体枠を描きます
 *
 * # Arguments
 *
 * - `ui`: 枠線を描画する標準 widget と同じ UI
 * - `response`: 枠の矩形・有効状態・focus を取得する元 widget の応答
 * - `sunken`: `true` は押し込み、`false` は盛り上がる明暗の順序
 */
//------------------------------------------------------------------------------
fn bevel(ui: &egui::Ui, response: &egui::Response, sunken: bool) {
	let rect = response.rect.shrink(0.5);
	let light = Color32::WHITE;
	// 無効 widget の明暗を弱め、操作できる状態と見分けられるようにする
	let dark = Color32::from_gray(if response.enabled() { 110 } else { 170 });
	// 押し込み状態だけは明暗の辺を反転し、元 widget の応答を描画へ反映する
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
/**
 * 標準egui Buttonへ立体枠とfocus枠を追加します。click/keyboard/accessibilityは元の部品に任せます
 *
 * # Returns
 *
 * 標準 button の元の応答。自作枠は入力判定と accessibility の契約を置き換えません
 */
//------------------------------------------------------------------------------
pub(super) fn button(ui: &mut egui::Ui, button: egui::Button<'_>, enabled: bool) -> egui::Response {
	let response = ui.add_enabled(enabled, button);
	let pressed = response.is_pointer_button_down_on()
		|| (response.has_focus() && ui.input(|input| input.key_down(egui::Key::Space)));
	bevel(ui, &response, pressed);
	// keyboard focus がある標準 button に限り、追加の focus 枠を描く
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
/**
 * 標準TextEditのresponseへ凹枠を描きます。入力・selection・IME・accessibilityを変更しません
 */
//------------------------------------------------------------------------------
pub(super) fn text_edit_frame(ui: &egui::Ui, response: &egui::Response) {
	bevel(ui, response, true);
	// 入力 focus のときだけ内側の強調枠を描き、IME や hit 領域は変更しない
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
	/**
	 * 未搭載・不正データでもNotoを両familyの先頭に維持し、別familyをMS Gothicと誤認しません
	 */
	//------------------------------------------------------------------------------
	#[test]
	fn falls_back_for_missing_invalid_or_unrelated_font() {
		// OS font の欠落・破損・別 family の全条件で、同じ埋込み fallback を検証する
		for system in [
			None,
			Some((PathBuf::from("invalid"), vec![0, 1, 2])),
			Some((PathBuf::from("unrelated"), JAPANESE_FONT.to_vec())),
		] {
			let fonts = fonts_with_system(system);
			assert!(fonts.source.contains("embedded OFL fallback"));
			assert!(!fonts.definitions.font_data.contains_key(MS_GOTHIC));
			// 本文と等幅のどちらにも Noto が先頭に残ることを確認する
			for family in [FontFamily::Proportional, FontFamily::Monospace] {
				assert_eq!(fonts.definitions.families[&family][0], "Noto Sans JP");
			}
		}
	}
}
