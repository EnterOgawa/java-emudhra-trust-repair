//------------------------------------------------------------------------------
/*!
 * - ファイル: diagnostics_tests.rs
 * - 概要: 既知 DER と異常 RFC から診断と全群計画の fail-closed 契約を検証します
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
 * 証明書は公開 root とローカル試験用の公開証明書だけです。秘密鍵は含みません
 */
//------------------------------------------------------------------------------

use crate::{
	ChangePlan, EntryKind, InventoryErrorCode, IssueCode, PlanError, ScanReport, ScanStatus,
	StoreFormat, embedded_policy, parse_keytool_rfc,
};
use base64::Engine;

// 対策定義の元である公開証明書を、そのまま解析試験にも用いる
const ROOTS: [&str; 4] = [
	include_str!("../../../data/roots/emsignrootcag1.pem"),
	include_str!("../../../data/roots/emsignrootcag2.pem"),
	include_str!("../../../data/roots/emsigneccrootcag3.pem"),
	include_str!("../../../data/roots/comodoaaaca.pem"),
];
// CN だけを対象と同じにしたローカル試験用の別証明書
const COLLISION: &str = include_str!("../testdata/same-cn-different-der.pem");
// DER の UTF8String を確認するローカル試験用の公開証明書
const UNICODE: &str = include_str!("../testdata/unicode-cn.pem");
// OpenJDK の二重エントリ終端
const END: &str = "\n*******************************************\n*******************************************\n\n";

//------------------------------------------------------------------------------
/**
 * 一つの trustedCertEntry を作ります。実証明書 PEM を補正せず中に置きます
 *
 * # Arguments
 *
 * - `alias`: 出力にそのまま埋め込む試験用別名
 * - `pem`: 境界行を含む、試験する証明書の PEM
 *
 * # Returns
 *
 * 一件の trustedCertEntry を表す RFC 形式の文字列
 */
//------------------------------------------------------------------------------
fn trusted(alias: &str, pem: &str) -> String {
	format!(
		"Alias name: {alias}\nCreation date: Oct 26, 2026\nEntry type: trustedCertEntry\n\n{pem}{END}"
	)
}

//------------------------------------------------------------------------------
/**
 * 指定形式とエントリ数を宣言する、試験用 RFC を組み立てます
 *
 * # Arguments
 *
 * - `format`: ヘッダへ記載するストア形式
 * - `entries`: 指定順に連結する、個々のエントリの文字列
 *
 * # Returns
 *
 * 配列の件数を宣言した keytool 出力の fixture
 */
//------------------------------------------------------------------------------
fn rfc(format: &str, entries: &[String]) -> String {
	format!(
		"Keystore type: {format}\nKeystore provider: SUN\n\nYour keystore contains {} {}\n\n{}",
		entries.len(),
		if entries.len() == 1 {
			"entry"
		} else {
			"entries"
		},
		entries.concat()
	)
}

//------------------------------------------------------------------------------
/**
 * 一つの一致する root を別名で登録した、完全な診断を返します
 */
//------------------------------------------------------------------------------
fn target_report() -> ScanReport {
	let policy = embedded_policy().expect("定義");
	let inventory = parse_keytool_rfc(rfc("JKS", &[trusted("other alias", ROOTS[0])]).as_bytes())
		.expect("完全な RFC");
	ScanReport::evaluate(&policy, inventory, Vec::new())
}

//------------------------------------------------------------------------------
/**
 * 両形式で 4 DER の正確な hash と CN を確認し、全別名が計画されることを検証します
 */
//------------------------------------------------------------------------------
#[test]
fn recognizes_all_four_roots_by_der_in_both_formats() {
	let policy = embedded_policy().expect("定義");
	// 形式だけを変更し、DER による一致がどちらでも同一になることを確認する
	for (format, expected) in [("JKS", StoreFormat::Jks), ("PKCS12", StoreFormat::Pkcs12)] {
		let entries: Vec<_> = ROOTS
			.iter()
			.enumerate()
			.map(|(index, pem)| trusted(&format!("renamed {index}"), pem))
			.collect();
		let inventory = parse_keytool_rfc(rfc(format, &entries).as_bytes()).expect("全件解析");
		assert_eq!(inventory.format(), expected);
		assert_eq!(inventory.provider(), "SUN");
		// 全四件の DER hash と、DER から抽出した表示名を照合する
		for (entry, root) in inventory.entries().iter().zip(policy.roots()) {
			assert_eq!(entry.certificates()[0].sha256(), root.sha256());
			assert!(
				entry.certificates()[0]
					.common_names()
					.iter()
					.any(|name| name == root.name())
			);
		}
		let report = ScanReport::evaluate(&policy, inventory, Vec::new());
		assert_eq!(report.status(), ScanStatus::TargetsFound);
		let plan = ChangePlan::build(&policy, &[report]).expect("対象計画");
		assert_eq!(plan.stores()[0].deletions().len(), 4);
		assert_eq!(plan.stores()[0].original().format(), expected);
	}
}

//------------------------------------------------------------------------------
/**
 * 同一 DER を別名で二回登録した場合、両方が予定から漏れないことを確認します
 */
//------------------------------------------------------------------------------
#[test]
fn plans_every_alias_for_duplicate_certificate() {
	let policy = embedded_policy().expect("定義");
	let inventory = parse_keytool_rfc(
		rfc(
			"JKS",
			&[trusted("alpha", ROOTS[0]), trusted("別名 二", ROOTS[0])],
		)
		.as_bytes(),
	)
	.expect("RFC");
	let report = ScanReport::evaluate(&policy, inventory, Vec::new());
	let plan = ChangePlan::build(&policy, &[report]).expect("全別名");
	let aliases: Vec<_> = plan.stores()[0]
		.deletions()
		.iter()
		.map(|entry| entry.alias())
		.collect();
	assert_eq!(aliases, ["alpha", "別名 二"]);
}

//------------------------------------------------------------------------------
/**
 * CN が同じでも別 DER なら削除せず、群全体を要確認にすることを確認します
 */
//------------------------------------------------------------------------------
#[test]
fn same_cn_different_der_is_blocked_never_deleted() {
	let policy = embedded_policy().expect("定義");
	let inventory = parse_keytool_rfc(rfc("PKCS12", &[trusted("collision", COLLISION)]).as_bytes())
		.expect("RFC");
	let report = ScanReport::evaluate(&policy, inventory, Vec::new());
	assert_eq!(report.status(), ScanStatus::NotModifiable);
	assert!(report.targets().is_empty());
	assert!(report.issues().contains(&IssueCode::NameCollision));
	assert!(ChangePlan::build(&policy, &[target_report(), report]).is_err());
}

//------------------------------------------------------------------------------
/**
 * 対象の名前を別証明書の alias に付けた場合も、名称で削除しないことを確認します
 */
//------------------------------------------------------------------------------
#[test]
fn policy_alias_different_der_is_blocked() {
	let policy = embedded_policy().expect("定義");
	let inventory = parse_keytool_rfc(rfc("JKS", &[trusted("emsignrootcag1", UNICODE)]).as_bytes())
		.expect("RFC");
	let report = ScanReport::evaluate(&policy, inventory, Vec::new());
	assert!(report.targets().is_empty());
	assert!(report.issues().contains(&IssueCode::NameCollision));
}

//------------------------------------------------------------------------------
/**
 * 日本語/空白 alias と DER の CN を損失なく取得し、RFC の改行差も吸収します
 */
//------------------------------------------------------------------------------
#[test]
fn preserves_unicode_alias_and_der_cn_with_crlf() {
	let input = rfc("PKCS12", &[trusted("空白 と 日本語", UNICODE)])
		.replace('\r', "")
		.replace('\n', "\r\n");
	let inventory = parse_keytool_rfc(input.as_bytes()).expect("Unicode RFC");
	assert_eq!(inventory.entries()[0].alias(), "空白 と 日本語");
	assert_eq!(
		inventory.entries()[0].certificates()[0].common_names(),
		["日本語テスト"]
	);
}

//------------------------------------------------------------------------------
/**
 * 秘密鍵チェーン中の全 DER を列挙してもエントリを削除できないことを確認します
 */
//------------------------------------------------------------------------------
#[test]
fn inventories_private_key_chain_but_refuses_automatic_changes() {
	let entry = format!(
		"Alias name: key\nCreation date: Oct 26, 2026\nEntry type: PrivateKeyEntry\nCertificate chain length: 2\nCertificate[1]:\n{}\nCertificate[2]:\n{}{END}",
		UNICODE, ROOTS[0]
	);
	let inventory = parse_keytool_rfc(rfc("PKCS12", &[entry]).as_bytes()).expect("チェーン");
	assert_eq!(inventory.entries()[0].kind(), EntryKind::PrivateKey);
	assert_eq!(inventory.entries()[0].certificates().len(), 2);
	let policy = embedded_policy().expect("定義");
	let report = ScanReport::evaluate(&policy, inventory, Vec::new());
	assert_eq!(report.targets()[0].certificate_index(), 1);
	assert!(report.issues().contains(&IssueCode::KeyMaterial));
	assert!(ChangePlan::build(&policy, &[report]).is_err());
}

//------------------------------------------------------------------------------
/**
 * 証明書を持たない対称鍵を inventory に含め、全群の自動変更を拒否します
 */
//------------------------------------------------------------------------------
#[test]
fn inventories_secret_keys_and_blocks_mixed_store() {
	let secret = format!(
		"Alias name: symmetric\nCreation date: Oct 26, 2026\nEntry type: SecretKeyEntry\n{END}"
	);
	let policy = embedded_policy().expect("定義");
	let inventory =
		parse_keytool_rfc(rfc("PKCS12", &[secret, trusted("root", ROOTS[0])]).as_bytes())
			.expect("対称鍵混在");
	let report = ScanReport::evaluate(&policy, inventory, Vec::new());
	assert_eq!(report.targets().len(), 1);
	assert_eq!(report.status(), ScanStatus::NotModifiable);
	assert!(ChangePlan::build(&policy, &[report]).is_err());
}

//------------------------------------------------------------------------------
/**
 * 対象 0 件は変更不要であり、空選択も同じ成功に混同しません
 */
//------------------------------------------------------------------------------
#[test]
fn distinguishes_empty_selection_and_no_targets() {
	let policy = embedded_policy().expect("定義");
	let inventory = parse_keytool_rfc(rfc("JKS", &[]).as_bytes()).expect("空ストア");
	let report = ScanReport::evaluate(&policy, inventory, Vec::new());
	assert_eq!(report.status(), ScanStatus::NoTargets);
	assert_eq!(
		ChangePlan::build(&policy, &[report]),
		Err(PlanError::NoTargets)
	);
	assert_eq!(
		ChangePlan::build(&policy, &[]),
		Err(PlanError::EmptySelection)
	);
}

//------------------------------------------------------------------------------
/**
 * 対応外版/警告/途中変化/失敗のどれでも、他の成功を部分適用へ使わない契約です
 */
//------------------------------------------------------------------------------
#[test]
fn blocks_whole_group_for_every_external_issue() {
	let policy = embedded_policy().expect("定義");
	// 外部診断で付加した全抑止理由について、一件の成功と混ぜても拒否する
	for issue in [
		IssueCode::UnsupportedJava,
		IssueCode::KeytoolWarning,
		IssueCode::ChangedDuringScan,
		IssueCode::UnsafeFile,
		IssueCode::MetadataUnavailable,
		IssueCode::Cancelled,
	] {
		let inventory = target_report().inventory().expect("inventory").clone();
		let blocked = ScanReport::evaluate(&policy, inventory, vec![issue]);
		assert_eq!(
			ChangePlan::build(&policy, &[target_report(), blocked]),
			Err(PlanError::Blocked { report_index: 1 })
		);
	}
	let failed = ScanReport::failed(&policy, IssueCode::ProcessFailure);
	assert_eq!(failed.status(), ScanStatus::Failed);
	assert_eq!(
		ChangePlan::build(&policy, &[target_report(), failed]),
		Err(PlanError::Blocked { report_index: 1 })
	);
}

//------------------------------------------------------------------------------
/**
 * 件数差・重複・未知行/型/provider・PEM の欠落を不完全成功にしません
 */
//------------------------------------------------------------------------------
#[test]
fn rejects_ambiguous_or_incomplete_structures() {
	let valid = rfc("JKS", &[trusted("one", ROOTS[0])]);
	let cases = [
		valid.replace("1 entry", "2 entries"),
		valid.replace("1 entry", "0 entries"),
		rfc(
			"JKS",
			&[trusted("same", ROOTS[0]), trusted("same", ROOTS[1])],
		),
		valid.replace("trustedCertEntry", "UnknownEntry"),
		valid.replace("provider: SUN", "provider: OTHER"),
		valid.replace("type: JKS", "type: BKS"),
		valid.replace("-----END CERTIFICATE-----", ""),
		valid.replace("Alias name:", "Unknown:"),
		valid.replace("Entry type:", "Entry type: trustedCertEntry\nEntry type:"),
		format!("{valid}warning\n"),
		valid.replacen("*******************************************", "***", 1),
		valid.replace("Creation date:", "Unknown date:"),
	];
	// 各違反は parser 全体を失敗させ、部分的な inventory を返さない
	for input in cases {
		assert!(parse_keytool_rfc(input.as_bytes()).is_err());
	}
}

//------------------------------------------------------------------------------
/**
 * 制御文字/不正 UTF8/不正 DER/余剰 DER と出力上限を拒否します
 */
//------------------------------------------------------------------------------
#[test]
fn rejects_controls_encoding_and_invalid_der() {
	let valid = rfc("JKS", &[trusted("one", ROOTS[0])]);
	// 改行と別名の表示方向を変える制御文字を個別に拒否する
	for value in ['\0', '\t', '\u{202e}', '\u{2066}'] {
		assert!(
			parse_keytool_rfc(valid.replace("one", &format!("one{value}")).as_bytes()).is_err()
		);
	}
	assert_eq!(
		parse_keytool_rfc(&[0xff]).expect_err("UTF8").code,
		InventoryErrorCode::Encoding
	);
	assert!(
		parse_keytool_rfc(
			rfc(
				"JKS",
				&[trusted(
					"bad",
					"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
				)]
			)
			.as_bytes()
		)
		.is_err()
	);
	let (_, pem) = x509_parser::pem::parse_x509_pem(ROOTS[0].as_bytes()).expect("fixture PEM");
	let mut der = pem.contents;
	der.push(0);
	let encoded = base64::engine::general_purpose::STANDARD.encode(der);
	let encoded_lines: Vec<_> = encoded
		.as_bytes()
		.chunks(64)
		.map(|line| std::str::from_utf8(line).expect("Base64 ASCII"))
		.collect();
	let extra = format!(
		"-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
		encoded_lines.join("\n")
	);
	assert!(
		parse_keytool_rfc(rfc("JKS", &[trusted("extra DER byte", &extra)]).as_bytes()).is_err()
	);
	assert_eq!(
		parse_keytool_rfc(&vec![b'x'; crate::MAX_INPUT_BYTES + 1])
			.expect_err("上限")
			.code,
		InventoryErrorCode::InputLimit
	);
}

//------------------------------------------------------------------------------
/**
 * chain の宣言と Certificate[n] の順序・実数が一致しない出力を拒否します
 */
//------------------------------------------------------------------------------
#[test]
fn rejects_chain_count_and_sequence_mismatches() {
	let entry = format!(
		"Alias name: key\nCreation date: Oct 26, 2026\nEntry type: PrivateKeyEntry\nCertificate chain length: 1\nCertificate[1]:\n{}{END}",
		ROOTS[0]
	);
	let valid = rfc("PKCS12", &[entry]);
	// 件数過不足と Certificate[n] の順序違反を個別に拒否する
	for input in [
		valid.replace("length: 1", "length: 2"),
		valid.replace("length: 1", "length: 0"),
		valid.replace("Certificate[1]", "Certificate[2]"),
	] {
		assert!(parse_keytool_rfc(input.as_bytes()).is_err());
	}
}
