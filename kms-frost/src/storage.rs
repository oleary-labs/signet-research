//! sled-based key storage for FROST KeyPackage and PublicKeyPackage.

use serde::{Deserialize, Serialize};

/// Persistent key material for a single key shard.
#[derive(Debug, Serialize, Deserialize)]
pub struct StoredKey {
    /// frost-secp256k1 KeyPackage serialized bytes.
    pub key_package: Vec<u8>,
    /// frost-secp256k1 PublicKeyPackage serialized bytes.
    pub public_key_package: Vec<u8>,
    /// 33-byte compressed secp256k1 group public key.
    pub group_key: Vec<u8>,
    /// This node's compressed public key share.
    pub verifying_share: Vec<u8>,
    /// Key generation counter (0 for initial keygen, incremented on reshare).
    pub generation: u64,
}

/// sled-backed key storage.
pub struct Storage {
    db: sled::Db,
}

impl Storage {
    /// Open (or create) a sled database at the given path.
    pub fn new(path: &str) -> Result<Self, String> {
        let db = sled::open(path).map_err(|e| format!("open sled db: {e}"))?;
        Ok(Storage { db })
    }

    /// Normalize a group_id to lowercase hex without "0x" prefix.
    fn normalize_group_id(group_id: &str) -> String {
        group_id
            .strip_prefix("0x")
            .or_else(|| group_id.strip_prefix("0X"))
            .unwrap_or(group_id)
            .to_ascii_lowercase()
    }

    /// Tree name for a group's keys.
    fn tree_name(group_id: &str) -> String {
        let normalized = Self::normalize_group_id(group_id);
        format!("keys/{normalized}")
    }

    /// Store a key under (group_id, key_id).
    pub fn put_key(&self, group_id: &str, key_id: &str, key: &StoredKey) -> Result<(), String> {
        let tree = self
            .db
            .open_tree(Self::tree_name(group_id))
            .map_err(|e| format!("open tree: {e}"))?;
        let data = serde_json::to_vec(key).map_err(|e| format!("serialize key: {e}"))?;
        tree.insert(key_id.as_bytes(), data)
            .map_err(|e| format!("insert key: {e}"))?;
        tree.flush().map_err(|e| format!("flush: {e}"))?;
        Ok(())
    }

    /// Retrieve a key by (group_id, key_id). Returns None if not found.
    pub fn get_key(&self, group_id: &str, key_id: &str) -> Result<Option<StoredKey>, String> {
        let tree = self
            .db
            .open_tree(Self::tree_name(group_id))
            .map_err(|e| format!("open tree: {e}"))?;
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

    /// List all key IDs for a group (excludes internal pending/ and archive/ prefixed keys).
    pub fn list_keys(&self, group_id: &str) -> Result<Vec<String>, String> {
        let tree = self
            .db
            .open_tree(Self::tree_name(group_id))
            .map_err(|e| format!("open tree: {e}"))?;
        let mut ids = Vec::new();
        for entry in tree.iter() {
            let (key, _) = entry.map_err(|e| format!("iter: {e}"))?;
            let id = String::from_utf8(key.to_vec()).map_err(|e| format!("key utf8: {e}"))?;
            if !id.starts_with("pending/") && !id.starts_with("archive/") {
                ids.push(id);
            }
        }
        Ok(ids)
    }

    /// Promote a pending reshare result to active, archiving the previous active key.
    /// Returns the new generation number.
    pub fn commit_reshare(&self, group_id: &str, key_id: &str) -> Result<u64, String> {
        let pending_id = format!("pending/{key_id}");
        let pending = self
            .get_key(group_id, &pending_id)?
            .ok_or_else(|| format!("no pending reshare for {group_id}/{key_id}"))?;

        // Archive the current active key (if it exists).
        if let Some(active) = self.get_key(group_id, key_id)? {
            let archive_id = format!("archive/{key_id}/gen{}", active.generation);
            self.put_key(group_id, &archive_id, &active)?;
        }

        // Promote pending to active.
        let generation = pending.generation;
        self.put_key(group_id, key_id, &pending)?;

        // Remove pending.
        self.delete_key(group_id, &pending_id)?;

        Ok(generation)
    }

    /// Discard a pending reshare result without promoting.
    pub fn discard_pending_reshare(&self, group_id: &str, key_id: &str) -> Result<(), String> {
        let pending_id = format!("pending/{key_id}");
        self.delete_key(group_id, &pending_id)
    }

    /// Rollback: restore a specific archived generation as the active key.
    pub fn rollback_reshare(&self, group_id: &str, key_id: &str, generation: u64) -> Result<(), String> {
        let archive_id = format!("archive/{key_id}/gen{generation}");
        let archived = self
            .get_key(group_id, &archive_id)?
            .ok_or_else(|| format!("no archived key at generation {generation} for {group_id}/{key_id}"))?;

        // Replace active with archived version.
        self.put_key(group_id, key_id, &archived)?;

        // Clean up: remove any pending key.
        let pending_id = format!("pending/{key_id}");
        let _ = self.delete_key(group_id, &pending_id);

        Ok(())
    }

    /// Delete a key by (group_id, key_id).
    fn delete_key(&self, group_id: &str, key_id: &str) -> Result<(), String> {
        let tree = self
            .db
            .open_tree(Self::tree_name(group_id))
            .map_err(|e| format!("open tree: {e}"))?;
        tree.remove(key_id.as_bytes())
            .map_err(|e| format!("delete key: {e}"))?;
        tree.flush().map_err(|e| format!("flush: {e}"))?;
        Ok(())
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
}
