//------------------------------------------------------------------------------
/*!
 * - ファイル: lib.rs
 * - 概要: Windows 境界の crate と対象ビルドの確認入口を提供します
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
 * unsafe は必要な Windows API 境界だけで許可します
 */
//------------------------------------------------------------------------------

#![deny(unsafe_code)]

#[cfg(all(windows, feature = "internal-qa"))]
mod internal_qa;
#[cfg(all(windows, feature = "internal-qa"))]
pub use internal_qa::qa_checkpoint;

#[cfg(windows)]
mod ui_language;
#[cfg(windows)]
pub use ui_language::user_ui_language;
#[cfg(windows)]
mod ui_fonts;
#[cfg(windows)]
pub use ui_fonts::windows_fonts_directory;

#[cfg(windows)]
mod java;
#[cfg(windows)]
mod process;
#[cfg(windows)]
mod scan;
#[cfg(windows)]
mod snapshot;
#[cfg(windows)]
mod transaction;
#[cfg(windows)]
mod transaction_data;
#[cfg(windows)]
mod transaction_io;

#[cfg(windows)]
pub use java::{JavaEnvironment, JavaError, JavaImageKind, select_java};
#[cfg(windows)]
pub use process::{Cancellation, PROCESS_TIMEOUT, ProcessError, StorePassword};
#[cfg(windows)]
pub use scan::{
	BuiltinPasswords, CustomStore, ScanFailure, ScanGroup, ScanNotice, ScanPhase, ScanProgress,
	ScanWarning, StoreScan, scan_java,
};
#[cfg(windows)]
pub use snapshot::{FileIdentity, FileSafetyError, FileSnapshot, read_snapshot};
#[cfg(windows)]
pub use transaction::{
	ArtifactEvidence, FailureBoundary, FailurePoint, HistoryEntry, HistoryState, ItemState,
	TransactionCode, TransactionContext, TransactionError, TransactionInspection,
	TransactionOptions, TransactionOutcome, TransactionPhase, TransactionProgress,
	TransactionState, apply_transaction, inspect_transaction, list_history, recover_transaction,
	restore_transaction,
};

use std::error::Error;
use std::fmt;

/// 製品対象の Windows x64 MSVC 以外でビルドされていることを表します
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsupportedTarget;

impl fmt::Display for UnsupportedTarget {
	//------------------------------------------------------------------------------
	/**
	 * [`fmt::Display`] に従い、必要なビルド対象を表示します
	 *
	 * # Arguments
	 *
	 * - `formatter`: 本呼出し中だけ可変借用する出力先
	 *
	 * # Returns
	 *
	 * 出力先の書込みに成功すれば `Ok(())`
	 *
	 * # Errors
	 *
	 * 出力先が失敗した場合、その `fmt::Error` を返します
	 */
	//------------------------------------------------------------------------------
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str("Windows x64 MSVC 用のビルドが必要です。")
	}
}

impl Error for UnsupportedTarget {}

//------------------------------------------------------------------------------
/**
 * 実行中のバイナリが Windows x64 MSVC 向けにビルドされたことを確認します
 *
 * # Returns
 *
 * `x86_64-pc-windows-msvc` のビルドなら `Ok(())` を返します
 *
 * # Errors
 *
 * それ以外の対象では [`UnsupportedTarget`] を返します
 *
 * # Notes
 *
 * OS の版、NTFS、権限、Java、対象ストアの適合性は検査しません。
 * ファイルや共有状態を変更せず、任意のスレッドから同時に呼び出せます
 */
//------------------------------------------------------------------------------
pub fn ensure_supported_target() -> Result<(), UnsupportedTarget> {
	// 非対応ビルドから製品操作を開始しないため、対象の三条件をまとめて検査する
	if cfg!(all(
		target_os = "windows",
		target_arch = "x86_64",
		target_env = "msvc"
	)) {
		Ok(())
	} else {
		Err(UnsupportedTarget)
	}
}
