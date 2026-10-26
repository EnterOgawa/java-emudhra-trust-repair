//------------------------------------------------------------------------------
/*!
 * - ファイル: transaction_data.rs
 * - 概要: manifest と順序付き journal の schema・上限・復旧入力を検証します。
 * - バージョン: 01.00.01
 * - 作成日: 2026/10/26
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
 * Ver.01.00.00  Shunji Ogawa  2026/10/26  immutable manifest、順序 journal と検査を追加。
 * Ver.01.00.01  Shunji Ogawa  2026/10/26  明示内部 QA で sync 済み境界を観測可能にした。
 * ```
 *
 * 備考:
 *
 * 同じ本人が書換えられる JSON/hash は改ざん耐性や署名ではありません。
 * 末尾破断は成功扱いせず、実ファイルの照合による復旧だけを許可します。
 */
//------------------------------------------------------------------------------

use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf, Prefix};

use serde::{Deserialize, Serialize};
use trust_repair_core::{
	EntryKind, MAX_INPUT_BYTES, Policy, StoreFormat, StoreInventory, embedded_policy,
};
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;

use crate::snapshot::{FileSnapshot, read_snapshot};
use crate::transaction::{TransactionCode, TransactionError, TransactionPhase, TransactionState};
use crate::transaction_io::{same_security, valid_security};

/// manifest/journal の各最大 byte 数です。鍵・password は保存しません。
pub(crate) const MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;
/// 一つの群の最大 store 数です。上限超過時は準備前に拒否します。
pub(crate) const MAX_STORES: usize = 128;

/// 保存する形式。任意の文字列から未知形式を作れません。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SavedFormat {
	/// Java KeyStore。
	Jks,
	/// PKCS #12。
	Pkcs12,
}

/// 保存する種別。自動変更対象は証明書 entry のみです。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SavedKind {
	/// trustedCertEntry。
	TrustedCertificate,
}

/// 別名・種別・DER hash による完全比較用の entry です。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SavedEntry {
	/// 補正しない別名。
	pub alias: String,
	/// 既知種別。
	pub kind: SavedKind,
	/// 一つの DER の SHA-256。
	pub sha256: String,
}

/// 全非対象を省略しない比較用 inventory です。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SavedInventory {
	/// 維持する形式。
	pub format: SavedFormat,
	/// 別名昇順の全 entry。
	pub entries: Vec<SavedEntry>,
}

impl SavedInventory {
	//------------------------------------------------------------------------------
	/** 検証済み inventory だけを保存形式へ移します。鍵混在では変更計画を拒否します。 */
	//------------------------------------------------------------------------------
	pub fn from_inventory(value: &StoreInventory) -> Result<Self, TransactionError> {
		let mut entries = Vec::new();
		// 証明書 entry 一件ごとの完全な別名と DER hash を保存する
		for entry in value.entries() {
			if entry.kind() != EntryKind::TrustedCertificate || entry.certificates().len() != 1 {
				return Err(invalid());
			}
			entries.push(SavedEntry {
				alias: entry.alias().to_owned(),
				kind: SavedKind::TrustedCertificate,
				sha256: entry.certificates()[0].sha256().to_owned(),
			});
		}
		Ok(Self {
			format: match value.format() {
				StoreFormat::Jks => SavedFormat::Jks,
				StoreFormat::Pkcs12 => SavedFormat::Pkcs12,
			},
			entries,
		})
	}

	//------------------------------------------------------------------------------
	/** DER 定義の全一致を除いた期待 inventory を作ります。別名を削除条件にしません。 */
	//------------------------------------------------------------------------------
	pub fn without_targets(&self, policy: &Policy) -> Self {
		Self {
			format: self.format,
			entries: self
				.entries
				.iter()
				.filter(|entry| {
					!policy
						.roots()
						.iter()
						.any(|root| root.sha256() == entry.sha256)
				})
				.cloned()
				.collect(),
		}
	}

	//------------------------------------------------------------------------------
	/** 復元入力の件数/文字/重複/hash/順序を検査します。 */
	//------------------------------------------------------------------------------
	fn validate(&self) -> bool {
		self.entries.len() <= 100_000
			&& self.entries.iter().all(|entry| {
				!entry.alias.is_empty()
					&& entry.alias.len() <= 1024 * 1024
					&& !entry.alias.chars().any(char::is_control)
					&& valid_hash(&entry.sha256)
			}) && self
			.entries
			.windows(2)
			.all(|pair| pair[0].alias < pair[1].alias)
	}
}

/// 一つの置換と復元の immutable な材料です。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManifestItem {
	/// 元 path/ID/hash/保持 metadata。
	pub original: FileSnapshot,
	/// 準備した stage の実体 ID と、置換先 path の期待状態。
	pub applied: FileSnapshot,
	/// 全件の変更前一覧。
	pub before: SavedInventory,
	/// 全非対象だけが残る期待一覧。
	pub after: SavedInventory,
	/// 削除予定の全 entry。重複 DER の別名も含みます。
	pub deletions: Vec<SavedEntry>,
	/// backup directory 内の固定形式の相対 file 名。
	pub backup_name: String,
	/// 対象の親 directory を基準にした、隣接 work directory の相対名。
	pub work_name: String,
	/// work directory 内の適用 stage の固定相対名。
	pub stage_name: String,
	/// work directory 内の同 volume recovery copy の固定相対名。
	pub recovery_name: String,
}

/// 上書きしない manifest schema 1 です。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Manifest {
	/// 受理する schema の具体値。
	pub schema_version: u32,
	/// directory 名と一致する ID。
	pub transaction_id: String,
	/// 作成した製品の版。
	pub app_version: String,
	/// 今回の定義 ID。
	pub policy_id: String,
	/// 定義 ID だけの改変を防ぐため照合する四つの DER hash。
	pub policy_hashes: Vec<String>,
	/// 選択した Java root。
	pub java_root: PathBuf,
	/// release/java/keytool の厳密な実体再照合材料。
	pub java: [FileSnapshot; 3],
	/// 削除対象のある全ストア。
	pub items: Vec<ManifestItem>,
}

impl Manifest {
	//------------------------------------------------------------------------------
	/** schema、policy、path、重複、snapshot と全差分を検証します。disk 内容は別途照合します。 */
	//------------------------------------------------------------------------------
	pub fn validate(&self, id: &str, root: &Path) -> Result<(), TransactionError> {
		let policy = embedded_policy().map_err(|_| invalid())?;
		if self.schema_version != 1
			|| !valid_id(id)
			|| self.transaction_id != id
			|| self.app_version != env!("CARGO_PKG_VERSION")
			|| self.policy_id != policy.id()
			|| self.policy_hashes
				!= policy
					.roots()
					.iter()
					.map(|root| root.sha256().to_owned())
					.collect::<Vec<_>>()
			|| !valid_path(&self.java_root)
			|| self.items.is_empty()
			|| self.items.len() > MAX_STORES
		{
			return Err(invalid());
		}
		// Java 更新時は復元を止めるため、三つの期待 path を固定する
		for (snapshot, suffix) in
			self.java
				.iter()
				.zip(["release", "bin/java.exe", "bin/keytool.exe"])
		{
			if !valid_snapshot(snapshot) || snapshot.canonical_path() != self.java_root.join(suffix)
			{
				return Err(invalid());
			}
		}
		let mut paths = BTreeSet::new();
		let mut identities = BTreeSet::new();
		// 全 item を検証し、相対 backup 名を任意の絶対 path と解釈する抜け道を作らない
		for (index, item) in self.items.iter().enumerate() {
			let target = item.original.canonical_path();
			let lowered = target.to_str().ok_or_else(invalid)?.to_lowercase();
			let expected_after = item.before.without_targets(&policy);
			let deletions: Vec<_> = item
				.before
				.entries
				.iter()
				.filter(|entry| !expected_after.entries.contains(entry))
				.cloned()
				.collect();
			let identity = item.original.identity();
			if !valid_snapshot(&item.original)
				|| !valid_snapshot(&item.applied)
				|| item.applied.canonical_path() != target
				|| item.original.identity().volume_serial != item.applied.identity().volume_serial
				|| !same_preserved_metadata(&item.original, &item.applied)
				|| item.original.sha256() == item.applied.sha256()
				|| !item.before.validate()
				|| !item.after.validate()
				|| item.after != expected_after
				|| item.deletions != deletions
				|| deletions.is_empty()
				|| item.backup_name != backup_name(index)
				|| item.work_name != format!(".jtr-{id}-{index:04}")
				|| item.stage_name != "apply.stage"
				|| item.recovery_name != "apply.recovery"
				|| target.starts_with(root)
				|| self
					.java
					.iter()
					.any(|snapshot| snapshot.canonical_path() == target)
				|| !paths.insert(lowered)
				|| !identities.insert((identity.volume_serial, identity.file_id))
			{
				return Err(invalid());
			}
		}
		Ok(())
	}
}

/// 順序番号付きの journal 一行です。
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JournalRecord {
	/// 1 始まり、欠番なしの番号。
	pub sequence: u64,
	/// 型付きの状態変化。
	pub event: JournalEvent,
	/// item 付き工程の 0 始まり位置。
	pub item: Option<usize>,
	/// 復元 stage/recovery の相対名を一意にする操作 ID。Restoring の開始だけに保存します。
	pub operation_id: Option<String>,
}

/// 置換の直前/検証済みを別々に記録します。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum JournalEvent {
	/// 全 stage と manifest を保存しました。
	Prepared,
	/// 順次確定を開始します。
	Committing,
	/// 一つの置換を開始します。
	ReplaceStarted,
	/// 一つの適用後を検証しました。
	ReplaceVerified,
	/// 全適用を検証しました。
	Applied,
	/// 逆順の rollback を開始します。
	RollingBack,
	/// 一つの rollback を開始します。
	RollbackStarted,
	/// 一つの元状態を検証しました。
	RollbackVerified,
	/// 群全体を元へ戻しました。
	RolledBack,
	/// 推測での上書きを中止しました。
	RecoveryRequired,
	/// 利用者の復元/復旧を開始します。
	Restoring,
	/// 一つの復元を開始します。
	RestoreStarted,
	/// 一つの元状態を検証しました。
	RestoreVerified,
	/// 群全体を復元しました。
	Restored,
	/// 復元途中の失敗を逆順で適用後へ戻しました。
	RestoreRolledBack,
}

/// journal の検証結果です。成功文字列より実体の照合を優先します。
pub(crate) struct JournalStatus {
	/// 最後の有効な主状態。
	pub state: TransactionState,
	/// 次の追記番号。
	pub next: u64,
	/// 最後の未改行行が破断していました。
	pub torn_tail: bool,
	/// 最後まで有効な byte 長。破断時は元 journal を触らず別 journal へ分岐します。
	pub valid_bytes: u64,
	/// 各 item に永続化済みの置換開始記録があるか。
	pub started: Vec<bool>,
	/// 最後の有効な記録で未検証の item。欠落時の自動復旧はこの item にだけ許可します。
	pub pending: Option<usize>,
	/// 最新の復元操作 ID。未知の相対 path を読み込む代わりに固定名を生成します。
	pub operation_id: Option<String>,
}

/// 他の writer を許可しない、追記と sync の所有者です。
pub(crate) struct Journal {
	/// 明示的に flush/sync する file。
	file: File,
	/// 次に永続化する番号。
	next: u64,
	/// 一度の write/flush/sync 失敗後は、破断行へ追記して証拠を壊しません。
	poisoned: bool,
}

impl Journal {
	//------------------------------------------------------------------------------
	/** 新規 journal を作ります。既存の記録は上書きしません。 */
	//------------------------------------------------------------------------------
	pub fn create(path: &Path) -> Result<Self, TransactionError> {
		let file = OpenOptions::new()
			.write(true)
			.create_new(true)
			.share_mode(FILE_SHARE_READ)
			.open(path)
			.map_err(|error| TransactionError::io(TransactionPhase::Prepare, path, error))?;
		Ok(Self {
			file,
			next: 1,
			poisoned: false,
		})
	}

	//------------------------------------------------------------------------------
	/** 読戻し照合済みの正常 journal を追記用に開きます。破断 journal は修復せず拒否します。 */
	//------------------------------------------------------------------------------
	pub fn resume(path: &Path, status: &JournalStatus) -> Result<Self, TransactionError> {
		if status.torn_tail {
			return Err(TransactionError::new(
				TransactionCode::InvalidJournal,
				TransactionPhase::Recovery,
			));
		}
		let file = OpenOptions::new()
			.append(true)
			.share_mode(FILE_SHARE_READ)
			.open(path)
			.map_err(|error| TransactionError::io(TransactionPhase::Recovery, path, error))?;
		if file
			.metadata()
			.map_err(|error| TransactionError::io(TransactionPhase::Recovery, path, error))?
			.len() != status.valid_bytes
		{
			return Err(TransactionError::new(
				TransactionCode::InvalidJournal,
				TransactionPhase::Recovery,
			));
		}
		Ok(Self {
			file,
			next: status.next,
			poisoned: false,
		})
	}

	//------------------------------------------------------------------------------
	/** 一つの型付き記録を改行と共に flush/sync します。失敗を成功状態へ変換しません。 */
	//------------------------------------------------------------------------------
	pub fn append(
		&mut self,
		event: JournalEvent,
		item: Option<usize>,
	) -> Result<(), TransactionError> {
		self.append_record(event, item, None)
	}

	//------------------------------------------------------------------------------
	/** 復元の新規 stage/recovery の位置を、開始前に journal へ固定します。 */
	//------------------------------------------------------------------------------
	pub fn start_restore(&mut self, operation: &str) -> Result<(), TransactionError> {
		if !valid_id(operation) {
			return Err(invalid());
		}
		self.append_record(JournalEvent::Restoring, None, Some(operation.to_owned()))
	}

	//------------------------------------------------------------------------------
	/** 型付き記録を一行ずつ永続化します。追記失敗時は番号を進めません。 */
	//------------------------------------------------------------------------------
	fn append_record(
		&mut self,
		event: JournalEvent,
		item: Option<usize>,
		operation_id: Option<String>,
	) -> Result<(), TransactionError> {
		if self.poisoned {
			return Err(TransactionError::new(
				TransactionCode::InvalidJournal,
				TransactionPhase::Journal,
			));
		}
		let record = JournalRecord {
			sequence: self.next,
			event,
			item,
			operation_id,
		};
		let mut bytes = serde_json::to_vec(&record).map_err(|_| invalid())?;
		bytes.push(b'\n');
		if let Err(error) = self
			.file
			.write_all(&bytes)
			.and_then(|_| self.file.flush())
			.and_then(|_| self.file.sync_all())
		{
			self.poisoned = true;
			return Err(TransactionError::io(
				TransactionPhase::Journal,
				Path::new("journal.jsonl"),
				error,
			));
		}
		self.next += 1;
		#[cfg(feature = "internal-qa")]
		crate::qa_checkpoint(&format!("journal-{event:?}"), item);
		Ok(())
	}
}

//------------------------------------------------------------------------------
/** 先頭から順序/状態/範囲を検査し、末尾未改行の破断だけを安全な解析結果に残します。 */
//------------------------------------------------------------------------------
pub(crate) fn read_journal(path: &Path, count: usize) -> Result<JournalStatus, TransactionError> {
	let (_, bytes) = read_snapshot(path, MAX_DOCUMENT_BYTES)
		.map_err(|error| TransactionError::file(TransactionPhase::History, path, error))?;
	let mut status = JournalStatus {
		state: TransactionState::Prepared,
		next: 1,
		torn_tail: false,
		valid_bytes: 0,
		started: vec![false; count],
		pending: None,
		operation_id: None,
	};
	let mut pending: Option<(JournalEvent, usize)> = None;
	// 完全な各行だけを状態機械へ渡し、最後の破断を完了記録とはしない
	for line in bytes.split_inclusive(|byte| *byte == b'\n') {
		if line.last() != Some(&b'\n') {
			status.torn_tail = true;
			break;
		}
		let record: JournalRecord = serde_json::from_slice(line).map_err(|_| {
			TransactionError::new(TransactionCode::InvalidJournal, TransactionPhase::History)
		})?;
		if record.sequence != status.next
			|| record.sequence == 1 && record.event != JournalEvent::Prepared
		{
			return Err(TransactionError::new(
				TransactionCode::InvalidJournal,
				TransactionPhase::History,
			));
		}
		use JournalEvent as E;
		use TransactionState as S;
		if (record.event == E::Restoring && !record.operation_id.as_deref().is_some_and(valid_id))
			|| (record.event != E::Restoring && record.operation_id.is_some())
		{
			return Err(TransactionError::new(
				TransactionCode::InvalidJournal,
				TransactionPhase::History,
			));
		}
		let item_event = matches!(
			record.event,
			E::ReplaceStarted
				| E::ReplaceVerified
				| E::RollbackStarted
				| E::RollbackVerified
				| E::RestoreStarted
				| E::RestoreVerified
		);
		if item_event && !record.item.is_some_and(|item| item < count)
			|| !item_event && record.item.is_some()
		{
			return Err(TransactionError::new(
				TransactionCode::InvalidJournal,
				TransactionPhase::History,
			));
		}
		let valid = match record.event {
			E::Prepared => record.sequence == 1 && record.item.is_none(),
			E::Committing => {
				status.state == S::Prepared && record.sequence > 1 && record.item.is_none()
			}
			E::ReplaceStarted => status.state == S::Committing && pending.is_none(),
			E::ReplaceVerified => {
				status.state == S::Committing
					&& pending == record.item.map(|item| (E::ReplaceStarted, item))
			}
			E::Applied => {
				status.state == S::Committing && pending.is_none() && record.item.is_none()
			}
			E::RollingBack => {
				matches!(
					status.state,
					S::Prepared
						| S::Committing | S::RollingBack
						| S::Restoring | S::RecoveryRequired
				) && record.item.is_none()
			}
			E::RollbackStarted => status.state == S::RollingBack,
			E::RollbackVerified => {
				status.state == S::RollingBack
					&& pending == record.item.map(|item| (E::RollbackStarted, item))
			}
			E::RolledBack => status.state == S::RollingBack && record.item.is_none(),
			E::RecoveryRequired => record.item.is_none(),
			E::Restoring => {
				matches!(
					status.state,
					S::Prepared
						| S::Committing | S::Applied
						| S::Restoring | S::RollingBack
						| S::RolledBack | S::Restored
						| S::RecoveryRequired
				) && record.item.is_none()
			}
			E::RestoreStarted => status.state == S::Restoring,
			E::RestoreVerified => {
				status.state == S::Restoring
					&& pending == record.item.map(|item| (E::RestoreStarted, item))
			}
			E::Restored => status.state == S::Restoring && record.item.is_none(),
			E::RestoreRolledBack => status.state == S::RollingBack && pending.is_none(),
		};
		if !valid {
			return Err(TransactionError::new(
				TransactionCode::InvalidJournal,
				TransactionPhase::History,
			));
		}
		match record.event {
			E::ReplaceStarted | E::RollbackStarted | E::RestoreStarted => {
				let item = record.item.filter(|item| *item < count).ok_or_else(|| {
					TransactionError::new(
						TransactionCode::InvalidJournal,
						TransactionPhase::History,
					)
				})?;
				status.started[item] = true;
				pending = Some((record.event, item));
			}
			E::ReplaceVerified | E::RollbackVerified | E::RestoreVerified => {
				pending = None;
			}
			E::Prepared => status.state = S::Prepared,
			E::Committing => status.state = S::Committing,
			E::Applied => status.state = S::Applied,
			E::RollingBack => {
				status.state = S::RollingBack;
				pending = None;
			}
			E::RolledBack => {
				status.state = S::RolledBack;
				pending = None;
			}
			E::RecoveryRequired => {
				status.state = S::RecoveryRequired;
				pending = None;
			}
			E::Restoring => {
				status.state = S::Restoring;
				status.operation_id = record.operation_id;
				pending = None;
			}
			E::Restored => {
				status.state = S::Restored;
				pending = None;
			}
			E::RestoreRolledBack => {
				status.state = S::Applied;
				pending = None;
			}
		}
		status.next += 1;
		status.valid_bytes += line.len() as u64;
	}
	if status.next == 1 {
		status.torn_tail = true;
	}
	status.pending = pending.map(|(_, item)| item);
	Ok(status)
}

//------------------------------------------------------------------------------
/** 小さい immutable JSON を新規保存し、sync と byte 全一致の読戻しを検証します。 */
//------------------------------------------------------------------------------
pub(crate) fn write_manifest(path: &Path, manifest: &Manifest) -> Result<(), TransactionError> {
	let bytes = serde_json::to_vec_pretty(manifest).map_err(|_| invalid())?;
	if bytes.len() > MAX_DOCUMENT_BYTES {
		return Err(invalid());
	}
	write_new(path, &bytes, TransactionPhase::Prepare)?;
	let (_, actual) = read_snapshot(path, MAX_DOCUMENT_BYTES)
		.map_err(|error| TransactionError::file(TransactionPhase::Prepare, path, error))?;
	if actual != bytes {
		return Err(invalid());
	}
	#[cfg(feature = "internal-qa")]
	crate::qa_checkpoint("manifest-verified", None);
	Ok(())
}

//------------------------------------------------------------------------------
/** 新規 file だけに書込み、flush と sync を成功条件にします。失敗物は削除しません。 */
//------------------------------------------------------------------------------
pub(crate) fn write_new(
	path: &Path,
	bytes: &[u8],
	phase: TransactionPhase,
) -> Result<(), TransactionError> {
	let mut file = OpenOptions::new()
		.write(true)
		.create_new(true)
		.share_mode(FILE_SHARE_READ)
		.open(path)
		.map_err(|error| TransactionError::io(phase, path, error))?;
	file.write_all(bytes)
		.and_then(|_| file.flush())
		.and_then(|_| file.sync_all())
		.map_err(|error| TransactionError::io(phase, path, error))?;
	#[cfg(feature = "internal-qa")]
	if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
		crate::qa_checkpoint(&format!("saved-{name}"), None);
	}
	Ok(())
}

//------------------------------------------------------------------------------
/** 制限 root 内の manifest だけを読みます。内容の schema 検証は呼出し側で実施します。 */
//------------------------------------------------------------------------------
pub(crate) fn load_manifest(path: &Path) -> Result<Manifest, TransactionError> {
	let (_, bytes) = read_snapshot(path, MAX_DOCUMENT_BYTES)
		.map_err(|error| TransactionError::file(TransactionPhase::History, path, error))?;
	serde_json::from_slice(&bytes).map_err(|_| invalid())
}

//------------------------------------------------------------------------------
/** 既存を上書きしない ID の字句形式を検査します。path separator を受理しません。 */
//------------------------------------------------------------------------------
pub(crate) fn valid_id(id: &str) -> bool {
	id.len() == 53
		&& id.starts_with("tx-")
		&& id.as_bytes()[35] == b'-'
		&& id.as_bytes()[44] == b'-'
		&& id.bytes().enumerate().all(|(index, byte)| {
			matches!(index, 0..=2 | 35 | 44)
				|| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
		})
}

//------------------------------------------------------------------------------
/** SHA-256 の上位文字を正規形とし、不正な長さや文字は補正しません。 */
//------------------------------------------------------------------------------
fn valid_hash(value: &str) -> bool {
	value.len() == 64
		&& value
			.bytes()
			.all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
}

//------------------------------------------------------------------------------
/** 未存在 path も検査できる、純粋な DOS path の字句検査です。実体検査は別に必須です。 */
//------------------------------------------------------------------------------
pub(crate) fn valid_path(path: &Path) -> bool {
	path.to_str().is_some_and(|value| value.len() <= 32_000 && !value.chars().any(char::is_control)) && path.is_absolute() && matches!(path.components().next(), Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))) && path.components().all(|part| !matches!(part, Component::ParentDir | Component::CurDir) && !matches!(part, Component::Normal(value) if value.to_str().is_none_or(|value| value.contains(':'))))
}

//------------------------------------------------------------------------------
/** snapshot を信用する前に path/上限/hash/metadata の schema を検査します。 */
//------------------------------------------------------------------------------
fn valid_snapshot(snapshot: &FileSnapshot) -> bool {
	valid_path(snapshot.canonical_path())
		&& valid_hash(snapshot.sha256())
		&& snapshot.length() <= MAX_INPUT_BYTES as u64
		&& snapshot.creation_time() > 0
		&& snapshot.last_write_time() > 0
		&& snapshot.identity().file_id != [0; 16]
		&& snapshot.attributes() & !0x20a6 == 0
		&& valid_security(snapshot.security_descriptor())
}

//------------------------------------------------------------------------------
/** 更新日時を除く、維持必須 metadata の完全一致を調べます。 */
//------------------------------------------------------------------------------
pub(crate) fn same_preserved_metadata(left: &FileSnapshot, right: &FileSnapshot) -> bool {
	left.attributes() == right.attributes()
		&& left.creation_time() == right.creation_time()
		&& same_security(left.security_descriptor(), right.security_descriptor())
}

//------------------------------------------------------------------------------
/** byte hash と全保持 metadata/更新日時を比較します。復元で file ID の再利用は要求しません。 */
//------------------------------------------------------------------------------
pub(crate) fn same_content_metadata(left: &FileSnapshot, right: &FileSnapshot) -> bool {
	left.sha256() == right.sha256()
		&& left.length() == right.length()
		&& left.last_write_time() == right.last_write_time()
		&& same_preserved_metadata(left, right)
		&& left.canonical_path() == right.canonical_path()
		&& left.identity().volume_serial == right.identity().volume_serial
}

//------------------------------------------------------------------------------
/** backup の相対 file 名を位置から一意に生成します。 */
//------------------------------------------------------------------------------
pub(crate) fn backup_name(index: usize) -> String {
	format!("{index:04}.original.bin")
}

//------------------------------------------------------------------------------
/** 隣接 work directory を target と ID/位置から決め、manifest の任意相対 path を使いません。 */
//------------------------------------------------------------------------------
pub(crate) fn work_directory(
	target: &Path,
	id: &str,
	index: usize,
) -> Result<PathBuf, TransactionError> {
	Ok(target
		.parent()
		.ok_or_else(invalid)?
		.join(format!(".jtr-{id}-{index:04}")))
}

//------------------------------------------------------------------------------
/** schema/整合性失敗の型付き値を作ります。入力本文は保存しません。 */
//------------------------------------------------------------------------------
fn invalid() -> TransactionError {
	TransactionError::new(TransactionCode::InvalidManifest, TransactionPhase::History)
}
