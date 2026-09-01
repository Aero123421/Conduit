use crate::{NodeStore, StoreError, map_sql};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    os::unix::ffi::OsStringExt,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageClass {
    Hot,
    Archive,
    Backup,
    Cache,
}
impl StorageClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::Hot => "hot",
            Self::Archive => "archive",
            Self::Backup => "backup",
            Self::Cache => "cache",
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageObject {
    pub object_id: String,
    pub class: StorageClass,
    pub path: PathBuf,
    pub size_bytes: u64,
    pub pinned: bool,
    pub custody_count: u32,
    pub contains_credentials: bool,
    pub collected: bool,
}
pub struct StorageManager {
    store: NodeStore,
    roots: [PathBuf; 4],
    quotas: [u64; 4],
}
impl StorageManager {
    pub fn new(
        store: NodeStore,
        hot: PathBuf,
        archive: PathBuf,
        backup: PathBuf,
        cache: PathBuf,
        quotas: [u64; 4],
    ) -> Result<Self, StoreError> {
        for p in [&hot, &archive, &backup, &cache] {
            fs::create_dir_all(p)?;
        }
        let roots = [
            fs::canonicalize(hot)?,
            fs::canonicalize(archive)?,
            fs::canonicalize(backup)?,
            fs::canonicalize(cache)?,
        ];
        Ok(Self {
            store,
            roots,
            quotas,
        })
    }
    fn index(class: StorageClass) -> usize {
        match class {
            StorageClass::Hot => 0,
            StorageClass::Archive => 1,
            StorageClass::Backup => 2,
            StorageClass::Cache => 3,
        }
    }
    pub fn root(&self, class: StorageClass) -> &Path {
        &self.roots[Self::index(class)]
    }
    pub fn used(&self, class: StorageClass) -> Result<u64, StoreError> {
        self.store
            .conn()?
            .query_row(
                "SELECT COALESCE(SUM(size_bytes),0) FROM storage_objects WHERE class=?1",
                [class.as_str()],
                |r| r.get(0),
            )
            .map_err(map_sql)
    }
    pub fn reserve(&self, object: &StorageObject) -> Result<(), StoreError> {
        validate_object_id(&object.object_id)?;
        if object.custody_count == 0 {
            return Err(StoreError::Invalid(
                "storage object must have custody".into(),
            ));
        }
        if !object.path.is_absolute() || !object.path.starts_with(self.root(object.class)) {
            return Err(StoreError::Invalid(
                "storage path is outside its class root".into(),
            ));
        }
        if object.path.to_string_lossy().contains(['\n', '\r', '\0']) {
            return Err(StoreError::Invalid(
                "storage path contains a delimiter".into(),
            ));
        }
        if let Some(parent) = object.path.parent() {
            let canonical = fs::canonicalize(parent)?;
            if !canonical.starts_with(self.root(object.class)) {
                return Err(StoreError::Invalid(
                    "storage path parent escaped class root".into(),
                ));
            }
        }
        let i = Self::index(object.class);
        if self.used(object.class)?.saturating_add(object.size_bytes) > self.quotas[i]
            || free_bytes(self.root(object.class))? < object.size_bytes
        {
            return Err(StoreError::Exhausted);
        }
        self.store.conn()?.execute("INSERT INTO storage_objects(object_id,class,path,size_bytes,pinned,custody_count,contains_credentials,collected) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",params![object.object_id,object.class.as_str(),object.path.as_os_str().as_encoded_bytes(),object.size_bytes,object.pinned,object.custody_count,object.contains_credentials,object.collected]).map_err(map_sql)?;
        Ok(())
    }
    pub fn pin(&self, id: &str, pinned: bool) -> Result<(), StoreError> {
        if self
            .store
            .conn()?
            .execute(
                "UPDATE storage_objects SET pinned=?2 WHERE object_id=?1",
                params![id, pinned],
            )
            .map_err(map_sql)?
            == 0
        {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }
    pub fn can_remove(&self, id: &str, discard_authorized: bool) -> Result<(), StoreError> {
        let row:Option<(bool,u32,bool,bool)>=self.store.conn()?.query_row("SELECT pinned,custody_count,contains_credentials,collected FROM storage_objects WHERE object_id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional().map_err(map_sql)?;
        let (pinned, custody, credential, collected) = row.ok_or(StoreError::NotFound)?;
        if pinned || custody <= 1 || credential || (!collected && !discard_authorized) {
            return Err(StoreError::Invalid("custody prevents cleanup".into()));
        }
        Ok(())
    }
    pub fn move_class(&self, id: &str, to: StorageClass) -> Result<PathBuf, StoreError> {
        validate_object_id(id)?;
        let row: Option<(Vec<u8>, u64)> = self
            .store
            .conn()?
            .query_row(
                "SELECT path,size_bytes FROM storage_objects WHERE object_id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(map_sql)?;
        let (raw, size) = row.ok_or(StoreError::NotFound)?;
        if self.used(to)?.saturating_add(size) > self.quotas[Self::index(to)]
            || free_bytes(self.root(to))? < size
        {
            return Err(StoreError::Exhausted);
        }
        let from = PathBuf::from(std::ffi::OsString::from_vec(raw));
        let canonical = fs::canonicalize(&from)?;
        if !self.roots.iter().any(|r| canonical.starts_with(r)) {
            return Err(StoreError::Invalid(
                "stored path escaped configured roots".into(),
            ));
        }
        let dest = self.root(to).join(id);
        if dest.exists() {
            return Err(StoreError::Invalid(
                "storage destination already exists".into(),
            ));
        }
        let conn = self.store.conn()?;
        fs::rename(&from, &dest)?;
        if let Err(error) = conn
            .execute(
                "UPDATE storage_objects SET class=?2,path=?3 WHERE object_id=?1",
                params![id, to.as_str(), dest.as_os_str().as_encoded_bytes()],
            )
            .map_err(map_sql)
        {
            fs::rename(&dest, &from).map_err(|rollback| {
                StoreError::Corrupt(format!(
                    "storage metadata update failed ({error}); rollback failed ({rollback})"
                ))
            })?;
            return Err(error);
        }
        Ok(dest)
    }
}
fn validate_object_id(id: &str) -> Result<(), StoreError> {
    let suffix = id
        .strip_prefix("obj_")
        .ok_or_else(|| StoreError::Invalid("invalid storage object ID".into()))?;
    if !(8..=128).contains(&suffix.len())
        || !suffix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(StoreError::Invalid("invalid storage object ID".into()));
    }
    Ok(())
}
fn free_bytes(path: &Path) -> Result<u64, StoreError> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| StoreError::Invalid("storage root contains NUL".into()))?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::statvfs(c.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return Err(StoreError::Io(std::io::Error::last_os_error()));
    }
    let stat = unsafe { stat.assume_init() };
    Ok(stat.f_bavail.saturating_mul(stat.f_frsize))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    #[test]
    fn quota_and_custody_block_cleanup() {
        let d = tempdir().unwrap();
        let s = NodeStore::open(d.path()).unwrap();
        let m = StorageManager::new(
            s,
            d.path().join("h"),
            d.path().join("a"),
            d.path().join("b"),
            d.path().join("c"),
            [10, 20, 20, 20],
        )
        .unwrap();
        let o = StorageObject {
            object_id: "obj_12345678".into(),
            class: StorageClass::Hot,
            path: d.path().join("h/x"),
            size_bytes: 8,
            pinned: true,
            custody_count: 1,
            contains_credentials: false,
            collected: false,
        };
        m.reserve(&o).unwrap();
        assert!(m.can_remove(&o.object_id, false).is_err());
        let mut o2 = o.clone();
        o2.object_id = "obj_87654321".into();
        o2.size_bytes = 3;
        assert!(matches!(m.reserve(&o2), Err(StoreError::Exhausted)));
    }
}
