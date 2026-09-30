use std::{
    collections::HashSet,
    fs,
    io::{self, Write},
    path::PathBuf,
    sync::{Arc, Mutex},
};

use axum::http::HeaderValue;
use reqwest::Url;
use serde::{Deserialize, Serialize};

const MAX_ORIGINS: usize = 16;

#[derive(Clone)]
pub(crate) struct CorsSettings {
    inner: Arc<Inner>,
}

struct Inner {
    path: PathBuf,
    required_origin: Option<String>,
    origins: Mutex<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedOrigins {
    version: u8,
    origins: Vec<String>,
}

impl CorsSettings {
    pub(crate) fn open(path: PathBuf, defaults: Vec<String>) -> io::Result<Self> {
        validate(&defaults, defaults.first().map(String::as_str))?;
        let required_origin = defaults.first().cloned();
        let origins = if path.exists() {
            let saved: SavedOrigins = serde_json::from_slice(&fs::read(&path)?)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            if saved.version != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Unsupported CORS settings version",
                ));
            }
            validate(&saved.origins, required_origin.as_deref())?;
            saved.origins
        } else {
            defaults
        };
        Ok(Self {
            inner: Arc::new(Inner {
                path,
                required_origin,
                origins: Mutex::new(origins),
            }),
        })
    }

    pub(crate) fn origins(&self) -> Vec<String> {
        self.inner
            .origins
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }

    pub(crate) fn required_origin(&self) -> Option<&str> {
        self.inner.required_origin.as_deref()
    }

    pub(crate) fn allows(&self, origin: &HeaderValue) -> bool {
        origin
            .to_str()
            .is_ok_and(|value| self.origins().iter().any(|allowed| allowed == value))
    }

    pub(crate) fn replace(&self, origins: Vec<String>) -> io::Result<()> {
        validate(&origins, self.required_origin())?;
        let mut current = self
            .inner
            .origins
            .lock()
            .map_err(|_| io::Error::other("CORS settings lock poisoned"))?;
        let bytes = serde_json::to_vec(&SavedOrigins {
            version: 1,
            origins: origins.clone(),
        })?;
        let path = &self.inner.path;
        let directory = path
            .parent()
            .ok_or_else(|| io::Error::other("Invalid CORS settings path"))?;
        let temporary = directory.join(format!(".cors-origins-{}.tmp", rand::random::<u64>()));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        let result = (|| {
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, path)?;
            fs::File::open(directory)?.sync_all()
        })();
        let _ = fs::remove_file(temporary);
        result?;
        *current = origins;
        Ok(())
    }
}

fn validate(origins: &[String], required: Option<&str>) -> io::Result<()> {
    if origins.len() > MAX_ORIGINS
        || required.is_some_and(|value| origins.first().map(String::as_str) != Some(value))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid CORS origin list",
        ));
    }
    let mut seen = HashSet::new();
    for origin in origins {
        let parsed = Url::parse(origin)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid CORS origin"))?;
        let loopback = parsed
            .host_str()
            .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "[::1]"));
        if parsed.origin().ascii_serialization() != *origin
            || (parsed.scheme() != "https" && !(loopback && parsed.scheme() == "http"))
            || origin.parse::<HeaderValue>().is_err()
            || !seen.insert(origin)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid CORS origin",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_persist_and_keep_match_origin_first() {
        let root = std::env::temp_dir().join(format!("lighthouse-cors-{}", rand::random::<u64>()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("cors-origins.json");
        let match_origin = "https://match.example".to_owned();
        let settings = CorsSettings::open(path.clone(), vec![match_origin.clone()]).unwrap();
        settings
            .replace(vec![match_origin.clone(), "https://home.example".into()])
            .unwrap();
        assert!(settings.allows(&HeaderValue::from_static("https://home.example")));
        assert_eq!(
            CorsSettings::open(path, vec![match_origin.clone()])
                .unwrap()
                .origins(),
            vec![match_origin, "https://home.example".to_owned()]
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn invalid_update_does_not_replace_current_origins() {
        let root = std::env::temp_dir().join(format!("lighthouse-cors-{}", rand::random::<u64>()));
        fs::create_dir_all(&root).unwrap();
        let settings = CorsSettings::open(
            root.join("cors-origins.json"),
            vec!["https://match.example".into()],
        )
        .unwrap();
        for invalid in [
            vec!["https://evil.example".into()],
            vec!["https://match.example".into(), "http://home.example".into()],
        ] {
            assert!(settings.replace(invalid).is_err());
        }
        assert_eq!(settings.origins(), vec!["https://match.example"]);
        let _ = fs::remove_dir_all(root);
    }
}
