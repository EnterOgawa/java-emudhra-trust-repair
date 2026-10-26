//------------------------------------------------------------------------------
/*!
 * - ファイル: internal_qa.rs
 * - 概要: 明示 QA build の自アプリだけを永続化境界で停止し、実 kill の証拠を残します。
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
 * Ver.01.00.00  Shunji Ogawa  2026/10/26  明示 feature と専用試験領域に限定した停止を追加。
 * ```
 *
 * 備考: 通常 build には含めません。他 process の終了や file の置換はしません。
 */
//------------------------------------------------------------------------------

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

// 一つの process で指定境界が何回観測されたかだけを数える。秘密は持たない
static OCCURRENCE: AtomicUsize = AtomicUsize::new(0);

//------------------------------------------------------------------------------
/**
 * 明示 feature と子専用環境の境界名が一致した場合だけ、専用領域へ marker を sync して待ちます。
 * `label` と `item` は固定の工程と位置です。内容・password・外部出力は記録しません。
 * marker と同名の拡張子 release を親が新規作成すれば再開します。親は所有する子だけを kill します。
 *
 * # Panics
 *
 * 明示 QA 設定が不正、marker が既存、I/O 失敗、120 秒以内に再開されない場合に QA を失敗させます。
 * marker はこの workspace の artifacts/internal-qa 配下だけに作り、既存 file は上書きしません。
 */
//------------------------------------------------------------------------------
pub fn qa_checkpoint(label: &str, item: Option<usize>) {
	let Some(expected) = std::env::var_os("JTR_QA_CHECKPOINT") else {
		return;
	};
	let actual = item.map_or_else(|| label.to_owned(), |index| format!("{label}:{index}"));
	if expected != actual.as_str() {
		return;
	}
	let wanted = std::env::var("JTR_QA_OCCURRENCE")
		.ok()
		.map(|value| value.parse::<usize>().expect("QA occurrence"))
		.unwrap_or(1);
	if OCCURRENCE.fetch_add(1, Ordering::Relaxed) + 1 != wanted {
		return;
	}
	let marker = PathBuf::from(std::env::var_os("JTR_QA_MARKER").expect("QA marker"));
	let allowed = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
		.join("../../artifacts/internal-qa")
		.canonicalize()
		.expect("QA area");
	let parent = marker
		.parent()
		.expect("QA marker parent")
		.canonicalize()
		.expect("QA parent");
	assert!(marker.is_absolute() && parent.starts_with(allowed));
	let mut file = OpenOptions::new()
		.write(true)
		.create_new(true)
		.open(&marker)
		.expect("new QA marker");
	writeln!(file, "pid={} checkpoint={actual}", std::process::id()).expect("QA marker write");
	file.sync_all().expect("QA marker sync");
	drop(file);
	let started = Instant::now();
	while !marker.with_extension("release").exists() {
		assert!(
			started.elapsed() < Duration::from_secs(120),
			"QA release timeout"
		);
		std::thread::sleep(Duration::from_millis(10));
	}
}
