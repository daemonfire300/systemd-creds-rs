use std::{fs::OpenOptions, io::Read, path::PathBuf};

#[derive(Debug)]
pub enum Error {
    IO(std::io::Error),
    Env(std::env::VarError),
}

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

const CREDENTIALS_DIRECTORY: &str = "CREDENTIALS_DIRECTORY";

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
///
pub fn load_all() -> Result<Vec<Result<(String, Vec<u8>), Error>>, Error> {
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
    use std::path::PathBuf;

    use tempfile::tempdir;

    use crate::{CREDENTIALS_DIRECTORY, discover};

    #[test]
    fn discover_none() {
        let dir = tempdir().expect("should be able to create tempdir");
        unsafe {
            std::env::set_var(
                CREDENTIALS_DIRECTORY,
                dir.path()
                    .to_str()
                    .expect("should be able to convert OsStr to &str"),
            );
        }
        let creds = discover().unwrap();
        assert_eq!(0, creds.len());
    }
}
