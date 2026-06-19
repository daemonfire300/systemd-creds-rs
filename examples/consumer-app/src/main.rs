const EXPECTED: &[&str] = &["api-token", "db-password"];

fn main() {
    let loaded = match systemd_creds_rs::load_all() {
        Ok(loaded) => loaded,
        Err(err) => {
            eprintln!("failed to load credentials: {err}");
            std::process::exit(1);
        }
    };

    let mut seen = Vec::new();

    for credential in loaded {
        match credential {
            Ok((name, bytes)) => {
                let rendered = String::from_utf8_lossy(&bytes);
                println!("credential:{name}:{}:{rendered}", bytes.len());
                seen.push(name);
            }
            Err(err) => {
                eprintln!("credential-error:{err}");
                std::process::exit(1);
            }
        }
    }

    seen.sort_unstable();

    if seen.as_slice() != EXPECTED {
        eprintln!("expected credentials {EXPECTED:?}, saw {seen:?}");
        std::process::exit(2);
    }
}
