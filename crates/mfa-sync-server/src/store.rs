//! On-disk storage for the encrypted blobs.
//!
//! One file per name, written atomically, with a strong ETag derived from the
//! content so a client can detect that someone else wrote in between.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use data_encoding::HEXLOWER;
use sha2::{Digest, Sha256};

/// A blob and the revision it is at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    pub bytes: Vec<u8>,
    pub etag: String,
}

/// The data directory.
#[derive(Debug)]
pub struct Store {
    root: PathBuf,
    /// Distinguishes concurrent temporary files.
    counter: AtomicU64,
}

impl Store {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            counter: AtomicU64::new(0),
        }
    }

    /// Creates the data directory if it is not there.
    pub async fn prepare(&self) -> io::Result<()> {
        tokio::fs::create_dir_all(&self.root).await
    }

    /// Reads a blob, or `None` if it has never been written.
    pub async fn get(&self, name: &str) -> io::Result<Option<Stored>> {
        match tokio::fs::read(self.path(name)).await {
            Ok(bytes) => Ok(Some(Stored {
                etag: etag(&bytes),
                bytes,
            })),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Writes a blob and returns its new ETag.
    ///
    /// Writes to a temporary file and renames, so a crash or a full disk
    /// cannot leave a half-written vault that no longer decrypts.
    pub async fn put(&self, name: &str, bytes: &[u8]) -> io::Result<String> {
        let sequence = self.counter.fetch_add(1, Ordering::Relaxed);
        let temporary = self
            .root
            .join(format!(".{name}.{}.{sequence}.tmp", std::process::id()));

        let result = write_then_rename(&temporary, &self.path(name), bytes).await;
        if result.is_err() {
            // Leaving temporary files behind would fill the disk over time.
            let _ = tokio::fs::remove_file(&temporary).await;
        }
        result.map(|()| etag(bytes))
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

async fn write_then_rename(temporary: &Path, final_path: &Path, bytes: &[u8]) -> io::Result<()> {
    use tokio::io::AsyncWriteExt as _;

    let mut file = tokio::fs::File::create(temporary).await?;
    file.write_all(bytes).await?;
    // Flush to the device before the rename, or a crash can leave the new
    // name pointing at an empty file on some filesystems.
    file.sync_all().await?;
    drop(file);

    tokio::fs::rename(temporary, final_path).await
}

/// A strong ETag: the hex SHA-256 of the content.
///
/// Content-derived rather than a counter, so two servers given the same file
/// agree, and a restore from a filesystem backup does not reuse a revision
/// for different content.
pub fn etag(bytes: &[u8]) -> String {
    HEXLOWER.encode(&Sha256::digest(bytes))
}
