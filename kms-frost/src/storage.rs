//! sled-based key storage for FROST key material.
//!
//! Data is organized into three tree families per group:
//!   - `keys/<group_id>`    — active key shards (hot path: sign, keygen)
//!   - `pending/<group_id>` — in-flight reshare results (at most one per key)
//!   - `archive/<group_id>` — previous generations (for rollback)
//!
//! Sled transactions span multiple trees for atomic commit/rollback operations.

use serde::{Deserialize, Serialize};
use sled::Transactional;

/// Persistent key material for a single key shard.
///
/// The curve is not stored here — it is a group-level property known by the
/// node, which passes it to the KMS via session params.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredKey {
    /// FROST KeyPackage serialized bytes (curve-specific).
    pub key_package: Vec<u8>,
    /// FROST PublicKeyPackage serialized bytes (curve-specific).
    pub public_key_package: Vec<u8>,
    /// Compressed group public key (33 bytes secp256k1, 32 bytes Ed25519).
    pub group_key: Vec<u8>,
    /// This node's compressed public key share.
    pub verifying_share: Vec<u8>,
    /// Key generation counter (0 for initial keygen, incremented on reshare).
    pub generation: u64,
}

/// sled-backed key storage with separate trees for active, pending, and archive.
pub struct Storage {
    db: sled::Db,
}

impl Storage {
    /// Open (or create) a sled database at the given path.
    pub fn new(path: &str) -> Result<Self, String> {
        let db = sled::open(path).map_err(|e| format!("open sled db: {e}"))?;
        Ok(Storage { db })
    }

    /// Flush all pending writes to disk.
    pub fn flush(&self) {
        let _ = self.db.flush();
    }

    /// Normalize a group_id to lowercase hex without "0x" prefix.
    fn normalize_group_id(group_id: &str) -> String {
        group_id
            .strip_prefix("0x")
            .or_else(|| group_id.strip_prefix("0X"))
            .unwrap_or(group_id)
            .to_ascii_lowercase()
    }

    fn active_tree_name(group_id: &str) -> String {
        format!("keys/{}", Self::normalize_group_id(group_id))
    }

    fn pending_tree_name(group_id: &str) -> String {
        format!("pending/{}", Self::normalize_group_id(group_id))
    }

    fn archive_tree_name(group_id: &str) -> String {
        format!("archive/{}", Self::normalize_group_id(group_id))
    }

    // -------------------------------------------------------------------------
    // Active key operations (hot path)
    // -------------------------------------------------------------------------

    /// Store an active key under (group_id, key_id). Flushes immediately —
    /// this is the keygen completion path and must be durable before reporting success.
    pub fn put_key(&self, group_id: &str, key_id: &str, key: &StoredKey) -> Result<(), String> {
        let tree = self
            .db
            .open_tree(Self::active_tree_name(group_id))
            .map_err(|e| format!("open tree: {e}"))?;
        let data = serde_json::to_vec(key).map_err(|e| format!("serialize key: {e}"))?;
        tree.insert(key_id.as_bytes(), data)
            .map_err(|e| format!("insert key: {e}"))?;
        tree.flush().map_err(|e| format!("flush: {e}"))?;
        Ok(())
    }

    /// Retrieve an active key by (group_id, key_id). Returns None if not found.
    pub fn get_key(&self, group_id: &str, key_id: &str) -> Result<Option<StoredKey>, String> {
        let tree = self
            .db
            .open_tree(Self::active_tree_name(group_id))
            .map_err(|e| format!("open tree: {e}"))?;
        Self::get_from_tree(&tree, key_id)
    }

    /// List all active key IDs for a group.
    pub fn list_keys(&self, group_id: &str) -> Result<Vec<String>, String> {
        let tree = self
            .db
            .open_tree(Self::active_tree_name(group_id))
            .map_err(|e| format!("open tree: {e}"))?;
        Self::list_from_tree(&tree)
    }

    // -------------------------------------------------------------------------
    // Pending key operations (reshare in-flight)
    // -------------------------------------------------------------------------

    /// Store a pending reshare result. No immediate flush — the pending result
    /// is not critical until commit_reshare promotes it (which flushes).
    pub fn put_pending(&self, group_id: &str, key_id: &str, key: &StoredKey) -> Result<(), String> {
        let tree = self
            .db
            .open_tree(Self::pending_tree_name(group_id))
            .map_err(|e| format!("open pending tree: {e}"))?;
        let data = serde_json::to_vec(key).map_err(|e| format!("serialize key: {e}"))?;
        tree.insert(key_id.as_bytes(), data)
            .map_err(|e| format!("insert pending: {e}"))?;
        Ok(())
    }

    /// Retrieve a pending reshare result.
    pub fn get_pending(&self, group_id: &str, key_id: &str) -> Result<Option<StoredKey>, String> {
        let tree = self
            .db
            .open_tree(Self::pending_tree_name(group_id))
            .map_err(|e| format!("open pending tree: {e}"))?;
        Self::get_from_tree(&tree, key_id)
    }

    // -------------------------------------------------------------------------
    // Reshare lifecycle (atomic via sled transactions)
    // -------------------------------------------------------------------------

    /// Atomically promote a pending reshare result to active, archiving the
    /// previous active key. Returns the new generation number.
    pub fn commit_reshare(&self, group_id: &str, key_id: &str) -> Result<u64, String> {
        let active_tree = self
            .db
            .open_tree(Self::active_tree_name(group_id))
            .map_err(|e| format!("open active tree: {e}"))?;
        let pending_tree = self
            .db
            .open_tree(Self::pending_tree_name(group_id))
            .map_err(|e| format!("open pending tree: {e}"))?;
        let archive_tree = self
            .db
            .open_tree(Self::archive_tree_name(group_id))
            .map_err(|e| format!("open archive tree: {e}"))?;

        let key_bytes = key_id.as_bytes();

        // Read pending outside transaction (we need it for the return value).
        let pending_data = pending_tree
            .get(key_bytes)
            .map_err(|e| format!("read pending: {e}"))?
            .ok_or_else(|| format!("no pending reshare for {group_id}/{key_id}"))?;
        let pending: StoredKey = serde_json::from_slice(&pending_data)
            .map_err(|e| format!("deserialize pending: {e}"))?;
        let generation = pending.generation;

        // Atomic transaction across all three trees.
        (&active_tree, &pending_tree, &archive_tree)
            .transaction(|(active_tx, pending_tx, archive_tx)| {
                // Archive current active (if exists).
                if let Some(current) = active_tx.get(key_bytes)? {
                    let current_key: StoredKey = serde_json::from_slice(&current)
                        .map_err(|e| sled::transaction::ConflictableTransactionError::Abort(
                            format!("deserialize active: {e}"),
                        ))?;
                    let ak = format!("gen{g}/{key_id}", g = current_key.generation);
                    archive_tx.insert(ak.as_bytes(), current)?;
                }

                // Promote pending to active.
                active_tx.insert(key_bytes, pending_data.clone())?;

                // Remove pending.
                pending_tx.remove(key_bytes)?;

                Ok(())
            })
            .map_err(|e: sled::transaction::TransactionError<String>| {
                format!("commit transaction failed: {e:?}")
            })?;

        self.db.flush().map_err(|e| format!("flush: {e}"))?;

        Ok(generation)
    }

    /// Discard a pending reshare result without promoting. No flush — discarding
    /// a pending result is non-critical; sled's auto-flush covers it.
    pub fn discard_pending_reshare(&self, group_id: &str, key_id: &str) -> Result<(), String> {
        let tree = self
            .db
            .open_tree(Self::pending_tree_name(group_id))
            .map_err(|e| format!("open pending tree: {e}"))?;
        tree.remove(key_id.as_bytes())
            .map_err(|e| format!("remove pending: {e}"))?;
        Ok(())
    }

    /// Rollback: restore a specific archived generation as the active key.
    pub fn rollback_reshare(
        &self,
        group_id: &str,
        key_id: &str,
        generation: u64,
    ) -> Result<(), String> {
        let active_tree = self
            .db
            .open_tree(Self::active_tree_name(group_id))
            .map_err(|e| format!("open active tree: {e}"))?;
        let archive_tree = self
            .db
            .open_tree(Self::archive_tree_name(group_id))
            .map_err(|e| format!("open archive tree: {e}"))?;
        let pending_tree = self
            .db
            .open_tree(Self::pending_tree_name(group_id))
            .map_err(|e| format!("open pending tree: {e}"))?;

        let archive_key_name = format!("gen{g}/{key_id}", g = generation);
        let key_bytes = key_id.as_bytes();

        let archived_data = archive_tree
            .get(archive_key_name.as_bytes())
            .map_err(|e| format!("read archive: {e}"))?
            .ok_or_else(|| {
                format!("no archived key at generation {generation} for {group_id}/{key_id}")
            })?;

        // Atomic: replace active + remove any pending.
        (&active_tree, &pending_tree)
            .transaction(|(active_tx, pending_tx)| {
                active_tx.insert(key_bytes, archived_data.clone())?;
                pending_tx.remove(key_bytes)?;
                Ok(())
            })
            .map_err(|e: sled::transaction::TransactionError<()>| {
                format!("rollback transaction failed: {e:?}")
            })?;

        self.db.flush().map_err(|e| format!("flush: {e}"))?;
        Ok(())
    }

    /// Drop all pending keys for a group. Safe when no reshares are in flight.
    pub fn drop_pending(&self, group_id: &str) -> Result<(), String> {
        let name = Self::pending_tree_name(group_id);
        self.db
            .drop_tree(name.as_bytes())
            .map_err(|e| format!("drop pending tree: {e}"))?;
        Ok(())
    }

    /// Drop all archived keys for a group. Safe after confirming active keys are healthy.
    pub fn drop_archive(&self, group_id: &str) -> Result<(), String> {
        let name = Self::archive_tree_name(group_id);
        self.db
            .drop_tree(name.as_bytes())
            .map_err(|e| format!("drop archive tree: {e}"))?;
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    fn get_from_tree(tree: &sled::Tree, key_id: &str) -> Result<Option<StoredKey>, String> {
        match tree.get(key_id.as_bytes()) {
            Ok(Some(data)) => {
                let key: StoredKey =
                    serde_json::from_slice(&data).map_err(|e| format!("deserialize key: {e}"))?;
                Ok(Some(key))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(format!("get key: {e}")),
        }
    }

    fn list_from_tree(tree: &sled::Tree) -> Result<Vec<String>, String> {
        let mut ids = Vec::new();
        for entry in tree.iter() {
            let (key, _) = entry.map_err(|e| format!("iter: {e}"))?;
            let id = String::from_utf8(key.to_vec()).map_err(|e| format!("key utf8: {e}"))?;
            ids.push(id);
        }
        Ok(ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_put_get_list() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().to_str().unwrap()).unwrap();

        let key = StoredKey {
            key_package: vec![1, 2, 3],
            public_key_package: vec![4, 5, 6],
            group_key: vec![0x02; 33],
            verifying_share: vec![0x03; 33],
            generation: 0,
        };

        storage.put_key("group-1", "key-a", &key).unwrap();
        storage.put_key("group-1", "key-b", &key).unwrap();

        let loaded = storage.get_key("group-1", "key-a").unwrap().unwrap();
        assert_eq!(loaded.key_package, vec![1, 2, 3]);
        assert_eq!(loaded.generation, 0);

        assert!(storage.get_key("group-1", "key-missing").unwrap().is_none());

        let ids = storage.list_keys("group-1").unwrap();
        assert_eq!(ids, vec!["key-a", "key-b"]);

        let empty = storage.list_keys("group-missing").unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn test_pending_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().to_str().unwrap()).unwrap();

        // Initial active key.
        let key_gen0 = StoredKey {
            key_package: vec![1],
            public_key_package: vec![2],
            group_key: vec![0x02; 33],
            verifying_share: vec![0x03; 33],
            generation: 0,
        };
        storage.put_key("group-1", "k1", &key_gen0).unwrap();

        // Write pending reshare result.
        let key_gen1 = StoredKey {
            key_package: vec![10],
            public_key_package: vec![20],
            group_key: vec![0x02; 33],
            verifying_share: vec![0x04; 33],
            generation: 1,
        };
        storage.put_pending("group-1", "k1", &key_gen1).unwrap();

        // Pending should not appear in active list.
        let ids = storage.list_keys("group-1").unwrap();
        assert_eq!(ids, vec!["k1"]);
        assert_eq!(storage.get_key("group-1", "k1").unwrap().unwrap().generation, 0);

        // Commit: pending → active, old → archive.
        let new_gen = storage.commit_reshare("group-1", "k1").unwrap();
        assert_eq!(new_gen, 1);

        // Active should now be gen 1.
        let active = storage.get_key("group-1", "k1").unwrap().unwrap();
        assert_eq!(active.generation, 1);
        assert_eq!(active.key_package, vec![10]);

        // Pending should be gone.
        assert!(storage.get_pending("group-1", "k1").unwrap().is_none());
    }

    #[test]
    fn test_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().to_str().unwrap()).unwrap();

        let key_gen0 = StoredKey {
            key_package: vec![1],
            public_key_package: vec![2],
            group_key: vec![0x02; 33],
            verifying_share: vec![0x03; 33],
            generation: 0,
        };
        storage.put_key("group-1", "k1", &key_gen0).unwrap();

        let key_gen1 = StoredKey {
            key_package: vec![10],
            public_key_package: vec![20],
            group_key: vec![0x02; 33],
            verifying_share: vec![0x04; 33],
            generation: 1,
        };
        storage.put_pending("group-1", "k1", &key_gen1).unwrap();
        storage.commit_reshare("group-1", "k1").unwrap();

        // Active is gen 1. Rollback to gen 0.
        storage.rollback_reshare("group-1", "k1", 0).unwrap();
        let active = storage.get_key("group-1", "k1").unwrap().unwrap();
        assert_eq!(active.generation, 0);
        assert_eq!(active.key_package, vec![1]);
    }

    #[test]
    fn test_discard_pending() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().to_str().unwrap()).unwrap();

        let key = StoredKey {
            key_package: vec![99],
            public_key_package: vec![],
            group_key: vec![],
            verifying_share: vec![],
            generation: 1,
        };
        storage.put_pending("group-1", "k1", &key).unwrap();
        assert!(storage.get_pending("group-1", "k1").unwrap().is_some());

        storage.discard_pending_reshare("group-1", "k1").unwrap();
        assert!(storage.get_pending("group-1", "k1").unwrap().is_none());
    }

    #[test]
    fn test_drop_archive() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().to_str().unwrap()).unwrap();

        let key = StoredKey {
            key_package: vec![1],
            public_key_package: vec![2],
            group_key: vec![0x02; 33],
            verifying_share: vec![0x03; 33],
            generation: 0,
        };
        storage.put_key("group-1", "k1", &key).unwrap();

        let key1 = StoredKey { generation: 1, ..key.clone() };
        storage.put_pending("group-1", "k1", &key1).unwrap();
        storage.commit_reshare("group-1", "k1").unwrap();

        // Archive exists. Drop it.
        storage.drop_archive("group-1").unwrap();

        // Active still works.
        assert_eq!(storage.get_key("group-1", "k1").unwrap().unwrap().generation, 1);

        // Rollback should now fail (no archive).
        assert!(storage.rollback_reshare("group-1", "k1", 0).is_err());
    }
}
