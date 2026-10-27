//------------------------------------------------------------------------------
/*!
 * - ファイル: lib.rs
 * - 概要: 副作用を持たない信頼ストア対策の定義と公開入口を提供します。
 * - バージョン: 01.00.00
 * - 作成日: 2026/10/27
 * - 制作者: Shunji Ogawa
 * - 著作権: Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * ライセンス:
 *
 * SPDX-License-Identifier: Apache-2.0
 * 本ファイルには Apache License, Version 2.0 が適用されます。
 * ライセンス全文はプロジェクトルートの LICENSE を参照してください。
 * <https://www.apache.org/licenses/LICENSE-2.0>
 *
 * 会社名: EnterSystem
 *
 * 更新履歴:
 *
 * ```text
 * VerNo.        author        update      comment
 * Ver.01.00.00  Shunji Ogawa  2026/10/27  新規作成。
 * ```
 *
 * 備考:
 *
 * ファイル、外部プロセス、通信、Windows API は扱いません。
 * transaction の副作用は Windows crate の後続工程が担当します。
 */
//------------------------------------------------------------------------------

#![forbid(unsafe_code)]

mod diagnosis;
mod inventory;
mod policy;

pub use diagnosis::{
	ChangePlan, IssueCode, PlanError, PlannedStore, ScanReport, ScanStatus, TargetMatch,
};
pub use inventory::{
	CertificateInventory, EntryInventory, EntryKind, InventoryError, InventoryErrorCode,
	MAX_INPUT_BYTES, StoreFormat, StoreInventory, parse_keytool_rfc, sha256_hex,
};

pub use policy::{Policy, PolicyError, RootCertificate, RootRelation, embedded_policy};

/// 製品で対応を計画する Java LTS major の明示リストです。
///
/// この定数だけでは、選択 Java の検査や各版の適用・復元試験の合格を表しません。
pub const SUPPORTED_JAVA_MAJORS: [u16; 4] = [11, 17, 21, 25];

#[cfg(test)]
mod diagnostics_tests;
