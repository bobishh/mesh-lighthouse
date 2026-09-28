use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use sha2::{Digest, Sha256};

const MAGIC: &[u8; 8] = b"MMPAGE01";
const HEADER_BYTES: usize = 8 + 4 + 32;
const DEFAULT_MAX_PAGE_BYTES: usize = 224 * 1024;
const DEFAULT_MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

#[derive(Clone)]
pub(crate) struct ProofPageCache {
    inner: Arc<CacheInner>,
}

struct CacheInner {
    directory: PathBuf,
    lock: Mutex<()>,
    limits: CacheLimits,
}

#[derive(Clone, Copy)]
struct CacheLimits {
    max_page_bytes: usize,
    max_total_bytes: u64,
    ttl: Duration,
}

struct Entry {
    path: PathBuf,
    size: u64,
    accessed: SystemTime,
}

impl ProofPageCache {
    pub(crate) fn new(state_path: &Path) -> Self {
        Self::with_limits(
            state_path,
            CacheLimits {
                max_page_bytes: DEFAULT_MAX_PAGE_BYTES,
                max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
                ttl: DEFAULT_TTL,
            },
        )
    }

    fn with_limits(state_path: &Path, limits: CacheLimits) -> Self {
        Self {
            inner: Arc::new(CacheInner {
                directory: sibling_staging_dir(state_path),
                lock: Mutex::new(()),
                limits,
            }),
        }
    }

    pub(crate) fn read(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        let _guard = self
            .inner
            .lock
            .lock()
            .map_err(|_| "Proof page cache lock poisoned")?;
        self.prepare_directory()?;
        let path = self.page_path(key);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("Inspect proof page cache: {error}")),
        };
        if !metadata.file_type().is_file()
            || is_expired(
                metadata.modified().ok(),
                self.inner.limits.ttl,
                SystemTime::now(),
            )
        {
            let _ = fs::remove_file(&path);
            return Ok(None);
        }
        let max_encoded_size =
            u64::try_from(HEADER_BYTES.saturating_add(self.inner.limits.max_page_bytes))
                .unwrap_or(u64::MAX);
        if metadata.len() > max_encoded_size {
            let _ = fs::remove_file(&path);
            return Ok(None);
        }
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("Read proof page cache: {error}")),
        };
        let Some(payload) = decode_page(&bytes, self.inner.limits.max_page_bytes) else {
            let _ = fs::remove_file(&path);
            return Ok(None);
        };
        let _ = touch(&path);
        Ok(Some(payload))
    }

    pub(crate) fn write(&self, key: &str, payload: &[u8]) -> Result<(), String> {
        if payload.len() > self.inner.limits.max_page_bytes {
            return Err("Proof page exceeds cache page limit".into());
        }
        let encoded = encode_page(payload)?;
        let _guard = self
            .inner
            .lock
            .lock()
            .map_err(|_| "Proof page cache lock poisoned")?;
        self.prepare_directory()?;
        let now = SystemTime::now();
        let mut entries = self.entries(now)?;
        let path = self.page_path(key);
        let existing_size = entries
            .iter()
            .find(|entry| entry.path == path)
            .map(|entry| entry.size)
            .unwrap_or(0);
        let mut total = entries.iter().map(|entry| entry.size).sum::<u64>();
        let target_size = encoded.len() as u64;
        while total
            .saturating_sub(existing_size)
            .saturating_add(target_size)
            > self.inner.limits.max_total_bytes
        {
            let Some((index, oldest)) = entries
                .iter()
                .enumerate()
                .filter(|(_, entry)| entry.path != path)
                .min_by_key(|(_, entry)| entry.accessed)
            else {
                return Err("Proof page cache budget is smaller than one page".into());
            };
            fs::remove_file(&oldest.path)
                .map_err(|error| format!("Evict proof page cache: {error}"))?;
            total = total.saturating_sub(oldest.size);
            entries.remove(index);
        }
        self.atomic_write(&path, &encoded)?;
        Ok(())
    }

    pub(crate) fn clear(&self) -> Result<(), String> {
        let _guard = self
            .inner
            .lock
            .lock()
            .map_err(|_| "Proof page cache lock poisoned")?;
        match fs::remove_dir_all(&self.inner.directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("Clear proof page staging directory: {error}")),
        }
        self.prepare_directory()
    }

    fn prepare_directory(&self) -> Result<(), String> {
        match fs::symlink_metadata(&self.inner.directory) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => return Err("Proof page staging path is not a directory".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(&self.inner.directory)
                    .map_err(|error| format!("Create proof page staging directory: {error}"))?;
            }
            Err(error) => return Err(format!("Inspect proof page staging path: {error}")),
        }
        let metadata = fs::symlink_metadata(&self.inner.directory)
            .map_err(|error| format!("Inspect proof page staging directory: {error}"))?;
        if !metadata.file_type().is_dir() {
            return Err("Proof page staging path is not a directory".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.inner.directory, fs::Permissions::from_mode(0o700))
                .map_err(|error| format!("Set proof page directory permissions: {error}"))?;
        }
        Ok(())
    }

    fn entries(&self, now: SystemTime) -> Result<Vec<Entry>, String> {
        let mut entries = Vec::new();
        let directory = fs::read_dir(&self.inner.directory)
            .map_err(|error| format!("List proof page staging directory: {error}"))?;
        for item in directory {
            let item = item.map_err(|error| format!("Read proof page directory entry: {error}"))?;
            let path = item.path();
            let file_type = item
                .file_type()
                .map_err(|error| format!("Inspect proof page directory entry: {error}"))?;
            let name = item.file_name();
            if file_type.is_file() && is_staging_temp(&name) {
                fs::remove_file(&path)
                    .map_err(|error| format!("Remove stale proof page temporary file: {error}"))?;
                continue;
            }
            if !file_type.is_file() || !is_page_filename(&name) {
                continue;
            }
            let metadata = item
                .metadata()
                .map_err(|error| format!("Read proof page metadata: {error}"))?;
            let modified = metadata.modified().unwrap_or(UNIX_EPOCH);
            if is_expired(Some(modified), self.inner.limits.ttl, now) {
                fs::remove_file(&path)
                    .map_err(|error| format!("Remove expired proof page: {error}"))?;
                continue;
            }
            entries.push(Entry {
                path,
                size: metadata.len(),
                accessed: metadata.accessed().unwrap_or(modified),
            });
        }
        Ok(entries)
    }

    fn page_path(&self, key: &str) -> PathBuf {
        let digest = Sha256::digest(key.as_bytes());
        self.inner.directory.join(format!("{digest:x}.page"))
    }

    fn atomic_write(&self, path: &Path, bytes: &[u8]) -> Result<(), String> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| format!("Proof page cache clock: {error}"))?
            .as_nanos();
        let temporary = self
            .inner
            .directory
            .join(format!(".tmp-{}-{nonce}", std::process::id()));
        let result = (|| -> Result<(), String> {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(&temporary)
                .map_err(|error| format!("Create proof page temporary file: {error}"))?;
            file.write_all(bytes)
                .map_err(|error| format!("Write proof page cache: {error}"))?;
            file.sync_all()
                .map_err(|error| format!("Sync proof page cache: {error}"))?;
            fs::rename(&temporary, path)
                .map_err(|error| format!("Commit proof page cache: {error}"))?;
            File::open(&self.inner.directory)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| format!("Sync proof page staging directory: {error}"))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
}

fn sibling_staging_dir(state_path: &Path) -> PathBuf {
    let parent = state_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = state_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("state");
    parent.join(format!(".{name}.proof-staging"))
}

fn encode_page(payload: &[u8]) -> Result<Vec<u8>, String> {
    let length = u32::try_from(payload.len()).map_err(|_| "Proof page is too large")?;
    let digest = Sha256::digest(payload);
    let mut bytes = Vec::with_capacity(HEADER_BYTES + payload.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(&digest);
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

fn decode_page(bytes: &[u8], max_page_bytes: usize) -> Option<Vec<u8>> {
    if bytes.len() < HEADER_BYTES || &bytes[..MAGIC.len()] != MAGIC {
        return None;
    }
    let length = u32::from_be_bytes(bytes[8..12].try_into().ok()?) as usize;
    if length > max_page_bytes || bytes.len() != HEADER_BYTES.checked_add(length)? {
        return None;
    }
    let payload = &bytes[HEADER_BYTES..];
    let expected = Sha256::digest(payload);
    (expected.as_slice() == &bytes[12..HEADER_BYTES]).then(|| payload.to_vec())
}

fn touch(path: &Path) -> Result<(), String> {
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|error| format!("Open proof page for LRU update: {error}"))?;
    file.set_times(std::fs::FileTimes::new().set_accessed(SystemTime::now()))
        .map_err(|error| format!("Update proof page LRU time: {error}"))
}

fn is_expired(modified: Option<SystemTime>, ttl: Duration, now: SystemTime) -> bool {
    modified.is_none_or(|modified| now.duration_since(modified).unwrap_or_default() > ttl)
}

fn is_page_filename(name: &std::ffi::OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let Some(digest) = name.strip_suffix(".page") else {
        return false;
    };
    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_staging_temp(name: &std::ffi::OsStr) -> bool {
    name.to_str().is_some_and(|name| name.starts_with(".tmp-"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "mesh-lighthouse-proof-cache-{}-{label}-{nonce}",
            std::process::id()
        ))
    }

    fn cache(
        state_path: &Path,
        max_page_bytes: usize,
        max_total_bytes: u64,
        ttl: Duration,
    ) -> ProofPageCache {
        ProofPageCache::with_limits(
            state_path,
            CacheLimits {
                max_page_bytes,
                max_total_bytes,
                ttl,
            },
        )
    }

    fn page_path(cache: &ProofPageCache, key: &str) -> PathBuf {
        cache.page_path(key)
    }

    #[test]
    fn persists_pages_across_instances_and_overwrites_atomically() {
        let state_path = temp_path("state.json");
        let first = ProofPageCache::new(&state_path);
        first.write("page/key:1", b"untrusted page v1").unwrap();
        let second = ProofPageCache::new(&state_path);
        assert_eq!(
            second.read("page/key:1").unwrap().as_deref(),
            Some(b"untrusted page v1".as_slice())
        );
        second.write("page/key:1", b"untrusted page v2").unwrap();
        assert_eq!(
            first.read("page/key:1").unwrap().as_deref(),
            Some(b"untrusted page v2".as_slice())
        );
        assert!(!state_path.exists());
        fs::remove_dir_all(first.inner.directory.as_path()).unwrap();
    }

    #[test]
    fn rejects_oversized_page_without_creating_cache_file() {
        let state_path = temp_path("oversized.json");
        let cache = cache(&state_path, 4, 128, Duration::from_secs(60));
        assert!(cache.write("page", b"12345").is_err());
        assert!(!cache.inner.directory.exists());
    }

    #[test]
    fn oversized_corrupt_file_is_rejected_before_page_read() {
        let state_path = temp_path("oversized-disk.json");
        let cache = cache(&state_path, 4, 128, Duration::from_secs(60));
        cache.prepare_directory().unwrap();
        fs::write(page_path(&cache, "page"), vec![0u8; HEADER_BYTES + 5]).unwrap();
        assert_eq!(cache.read("page").unwrap(), None);
        assert!(!page_path(&cache, "page").exists());
        fs::remove_dir_all(cache.inner.directory.as_path()).unwrap();
    }

    #[test]
    fn total_budget_evicts_least_recently_used_page() {
        let state_path = temp_path("budget.json");
        let cache = cache(
            &state_path,
            32,
            (HEADER_BYTES + 8) as u64 * 2,
            Duration::from_secs(60),
        );
        cache.write("a", b"aaaaaaaa").unwrap();
        cache.write("b", b"bbbbbbbb").unwrap();
        assert_eq!(
            cache.read("a").unwrap().as_deref(),
            Some(b"aaaaaaaa".as_slice())
        );
        cache.write("c", b"cccccccc").unwrap();
        assert_eq!(
            cache.read("a").unwrap().as_deref(),
            Some(b"aaaaaaaa".as_slice())
        );
        assert_eq!(cache.read("b").unwrap(), None);
        assert_eq!(
            cache.read("c").unwrap().as_deref(),
            Some(b"cccccccc".as_slice())
        );
        fs::remove_dir_all(cache.inner.directory.as_path()).unwrap();
    }

    #[test]
    fn ttl_expires_old_page_and_allows_refetch() {
        let state_path = temp_path("ttl.json");
        let cache = cache(&state_path, 32, 128, Duration::from_secs(60));
        cache.write("page", b"old").unwrap();
        let file = File::open(page_path(&cache, "page")).unwrap();
        file.set_times(std::fs::FileTimes::new().set_modified(UNIX_EPOCH))
            .unwrap();
        assert_eq!(cache.read("page").unwrap(), None);
        cache.write("page", b"new").unwrap();
        assert_eq!(
            cache.read("page").unwrap().as_deref(),
            Some(b"new".as_slice())
        );
        fs::remove_dir_all(cache.inner.directory.as_path()).unwrap();
    }

    #[test]
    fn corrupt_page_is_a_cache_miss_and_can_be_refetched() {
        let state_path = temp_path("corrupt.json");
        let cache = ProofPageCache::new(&state_path);
        cache.write("page", b"good page").unwrap();
        fs::write(page_path(&cache, "page"), b"corrupt bytes").unwrap();
        assert_eq!(cache.read("page").unwrap(), None);
        cache.write("page", b"replacement page").unwrap();
        assert_eq!(
            cache.read("page").unwrap().as_deref(),
            Some(b"replacement page".as_slice())
        );
        fs::remove_dir_all(cache.inner.directory.as_path()).unwrap();
    }

    #[test]
    fn clear_only_removes_staging_directory() {
        let state_path = temp_path("preserved-state.json");
        fs::write(&state_path, b"durable state").unwrap();
        let cache = ProofPageCache::new(&state_path);
        cache.write("page", b"proof page").unwrap();
        cache.clear().unwrap();
        assert_eq!(fs::read(&state_path).unwrap(), b"durable state");
        assert_eq!(cache.read("page").unwrap(), None);
        fs::remove_file(state_path).unwrap();
        fs::remove_dir_all(cache.inner.directory.as_path()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn cache_files_and_directory_are_private() {
        use std::os::unix::fs::PermissionsExt;

        let state_path = temp_path("private.json");
        let cache = ProofPageCache::new(&state_path);
        cache.write("page", b"proof page").unwrap();
        let directory_mode = fs::metadata(&cache.inner.directory)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let file_mode = fs::metadata(page_path(&cache, "page"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(directory_mode, 0o700);
        assert_eq!(file_mode, 0o600);
        fs::remove_dir_all(cache.inner.directory.as_path()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn staging_symlink_is_rejected_without_touching_target() {
        use std::os::unix::fs::symlink;

        let state_path = temp_path("symlink-state.json");
        let cache = ProofPageCache::new(&state_path);
        let target = temp_path("symlink-target");
        fs::create_dir_all(&target).unwrap();
        let marker = target.join("keep");
        fs::write(&marker, b"keep").unwrap();
        symlink(&target, &cache.inner.directory).unwrap();
        assert!(cache.read("page").is_err());
        assert_eq!(fs::read(marker).unwrap(), b"keep");
        fs::remove_file(&cache.inner.directory).unwrap();
        fs::remove_dir_all(target).unwrap();
    }
}
