//! Helpers for reading credentials injected by `systemd`.
//!
//! `systemd` services can expose credentials to a process by setting the
//! `CREDENTIALS_DIRECTORY` environment variable to a directory that contains one
//! file per credential. This crate provides small helper functions to discover
//! and load those files without requiring the caller to manually walk the
//! directory.
//!
//! The crate assumes the current process was started by `systemd`, or that the
//! caller has otherwise set `CREDENTIALS_DIRECTORY` to a compatible directory.

use std::{fmt, fs::OpenOptions, io::Read, path::PathBuf};

#[derive(Debug)]
pub enum Error {
    IO(std::io::Error),
    Env(std::env::VarError),
}

pub type Credential = (String, Vec<u8>);
pub type CredentialLoadResult = Result<Credential, Error>;
pub type CredentialLoadResults = Vec<CredentialLoadResult>;

impl From<std::env::VarError> for Error {
    fn from(value: std::env::VarError) -> Self {
        Error::Env(value)
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Error::IO(value)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::IO(err) => write!(f, "I/O error while reading systemd credentials: {err}"),
            Error::Env(err) => write!(f, "environment error while reading credentials: {err}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::IO(err) => Some(err),
            Error::Env(err) => Some(err),
        }
    }
}

const CREDENTIALS_DIRECTORY: &str = "CREDENTIALS_DIRECTORY";

/// Discovers credential files in `CREDENTIALS_DIRECTORY`.
///
/// Only regular files in the top-level credentials directory are returned.
/// Nested directories are ignored.
///
/// # Examples
///
/// ```no_run
/// let credential_paths = systemd_creds_rs::discover()?;
/// for path in credential_paths {
///     println!("{}", path.display());
/// }
/// # Ok::<(), systemd_creds_rs::Error>(())
/// ```
pub fn discover() -> Result<Vec<PathBuf>, Error> {
    let dir = std::env::var(CREDENTIALS_DIRECTORY)?;
    let dir_iter = std::fs::read_dir(&dir)?;
    let entries = dir_iter
        .into_iter()
        .flat_map(Result::ok)
        .flat_map(|e| {
            let p = e.path();
            if p.is_dir() { None } else { Some(p) }
        })
        .collect();
    Ok(entries)
}

/// Loads all secrets from the $CREDENTIALS_DIRECTORY if it's present.
/// The result is very verbose as it includes a result for every credentials file.
/// This is an intentional choice, because we do not want to fail on the first entry and return
/// early. Since we do not know why it fails we cannot determine if we should return early.
/// Doing this is out of scope now. We could return early on something like "filesystem gone" (this
/// error does obv. not exist exactly like this).
/// We think it's better to return a full list so that the developer / user can see which entries
/// are faulty and which are not.
///
/// # Errors
/// If it's not present returns an error from std::env:var which currently would be,
/// [`std::env::VarError::NotPresent`]. Please double check the std lib if you must rely on this.
///
/// # Examples
///
/// ```no_run
/// let credentials = systemd_creds_rs::load_all()?;
/// for credential in credentials {
///     let (name, bytes) = credential?;
///     println!("{name}: {} bytes", bytes.len());
/// }
/// # Ok::<(), systemd_creds_rs::Error>(())
/// ```
pub fn load_all() -> Result<CredentialLoadResults, Error> {
    let dir = std::env::var(CREDENTIALS_DIRECTORY)?;
    let dir_iter = std::fs::read_dir(&dir)?;
    let entries = dir_iter
        .into_iter()
        // TODO(juf): consider better api which reports errors
        .flat_map(|item| match item {
            Ok(e) => {
                let p = e.path();
                if p.is_dir() {
                    None
                } else {
                    let mut f = OpenOptions::new().read(true).open(&p).ok()?;
                    let mut buf = Vec::with_capacity(
                        p.metadata().map(|m| m.len() as usize).unwrap_or_default(),
                    );
                    f.read_to_end(&mut buf).expect("Could not read file");
                    Some(Ok((
                        p.file_name()
                            .expect("could not read OsStr")
                            .to_str()
                            .unwrap_or("could not read OsStr as &str")
                            .to_string(),
                        buf,
                    )))
                }
            }
            Err(err) => Some(Err(err.into())),
        })
        .collect();
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use std::{fs, io::Write};

    use tempfile::tempdir;

    use crate::{CREDENTIALS_DIRECTORY, discover, load_all};

    fn set_credentials_directory(path: &std::path::Path) {
        unsafe {
            std::env::set_var(
                CREDENTIALS_DIRECTORY,
                path.to_str()
                    .expect("should be able to convert OsStr to &str"),
            );
        }
    }

    #[test]
    fn discover_none() {
        let dir = tempdir().expect("should be able to create tempdir");
        set_credentials_directory(dir.path());
        let creds = discover().unwrap();
        assert_eq!(0, creds.len());
    }

    #[test]
    fn discover_errors_when_credentials_directory_is_missing() {
        unsafe {
            std::env::remove_var(CREDENTIALS_DIRECTORY);
        }

        let err = discover().expect_err("missing environment variable should fail");
        assert!(matches!(
            err,
            crate::Error::Env(std::env::VarError::NotPresent)
        ));
    }

    #[test]
    fn discover_skips_nested_directories() {
        let dir = tempdir().expect("should be able to create tempdir");
        let nested = dir.path().join("nested");
        fs::create_dir(&nested).expect("should create nested directory");
        fs::write(dir.path().join("db-password"), b"secret").expect("should write credential");
        fs::write(nested.join("ignored"), b"nested-secret").expect("should write nested file");

        set_credentials_directory(dir.path());

        let creds = discover().expect("discover should succeed");
        assert_eq!(creds, vec![dir.path().join("db-password")]);
    }

    #[test]
    fn load_all_reads_all_credential_files() {
        let dir = tempdir().expect("should be able to create tempdir");
        let mut api_key =
            fs::File::create(dir.path().join("api-key")).expect("should create api-key");
        api_key
            .write_all(b"very-secret")
            .expect("should write api-key");
        fs::write(dir.path().join("token"), b"abc123").expect("should write token");
        fs::create_dir(dir.path().join("nested")).expect("should create nested directory");
        set_credentials_directory(dir.path());

        let mut creds = load_all().expect("load_all should succeed");
        creds.sort_by(|left, right| {
            left.as_ref()
                .expect("expected successful credential")
                .0
                .cmp(&right.as_ref().expect("expected successful credential").0)
        });

        assert_eq!(creds.len(), 2);
        assert_eq!(
            creds[0].as_ref().expect("credential should load"),
            &("api-key".to_string(), b"very-secret".to_vec())
        );
        assert_eq!(
            creds[1].as_ref().expect("credential should load"),
            &("token".to_string(), b"abc123".to_vec())
        );
    }
}
