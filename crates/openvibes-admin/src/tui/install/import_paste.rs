//! Import from your PKI's boxes and bar (`import.rs`): the chain and key
//! checked as they are pasted or read, a .p12 or a locked key opened with
//! "Its password", and what is added.

use platform_host::Host;
use platform_pki::{Chain, ChainError, KeyInfo, P12, PkiError};
use zeroize::{Zeroize, Zeroizing};

use super::{
    Imported, Install, Locked, Stage, Which,
    import::{CERT, KEY, KEY_FIRST, NEXT},
    paste::{ended, holds_private_key},
};
use crate::{
    setup::import::{import_message, key_message},
    tui::{
        app::{App, Key},
        ca_request::{Picked, pick, read_bytes},
        nav::Screen,
        password::{PasswordPrompt, Typed},
    },
};

/// A locked key before its password: its kind is known only once opened.
const LOCKED: &str = "A private key, locked with a password";

impl Install {
    /// The box's certificate chain or key, checked; `None` while a locked
    /// key waits for its password.
    pub(super) fn import_check(
        &self,
        which: Which,
        text: &str,
    ) -> Option<Result<Vec<String>, String>> {
        let now = chrono::Utc::now();
        if which == Which::Cert {
            let chain = platform_pki::check_chain(text, now);
            return Some(
                chain
                    .map(|c| chain_lines(&c))
                    .map_err(|e| import_message(&e, "", None)),
            );
        }
        if self.unlocked.is_none() && platform_pki::is_locked(text) {
            return Some(match &self.error {
                Some(why) => Err(why.clone()),
                None => Ok(vec![LOCKED.into()]),
            });
        }
        Some(self.key_of(text).map(|(_, info, locked)| {
            let mut said = capitalised(&info.to_string());
            if locked {
                said.push_str(", locked with a password");
            }
            vec![said]
        }))
    }

    /// Our certificate's line while the chain above it is not whole yet.
    pub(super) fn import_partial(&self, which: Which, text: &str) -> Option<String> {
        if which != Which::Cert {
            return None;
        }
        match platform_pki::check_chain(text, chrono::Utc::now()) {
            Err(ChainError::Missing(_) | ChainError::NoCaBelow(_)) => {
                let name = platform_pki::common_name(text).ok()?;
                let until = platform_pki::not_after(text).ok()?;
                Some(ours_line(&name, &until))
            }
            _ => None,
        }
    }

    /// The box's key as PKCS#8, what it is, and whether it was locked;
    /// it must be our certificate's own.
    fn key_of(&self, text: &str) -> Result<(Zeroizing<String>, KeyInfo, bool), String> {
        let Some(imported) = &self.imported else {
            return Err(KEY_FIRST.into());
        };
        let (pkcs8, locked) = match &self.unlocked {
            Some(pkcs8) => (pkcs8.clone(), true),
            None => (
                platform_pki::pkcs8_pem(text, None).map_err(key_message)?,
                false,
            ),
        };
        let name = &imported.chain.name;
        let names = self.cert_names();
        let info = platform_pki::check_key(&imported.chain, &pkcs8, &names, chrono::Utc::now())
            .map_err(|e| import_message(&e, name, None))?;
        Ok((pkcs8, info, locked))
    }

    /// The names the server certificates will carry, as `Plan::names`
    /// makes them; none while they are not valid names.
    fn cert_names(&self) -> Vec<String> {
        if super::fields::check_names(&self.hostname, &self.sans).is_err() {
            return Vec::new();
        }
        let mut names = vec![self.hostname.trim().to_ascii_lowercase()];
        let sans = self.sans.split(',').map(|s| s.trim().to_ascii_lowercase());
        for name in sans.chain(["localhost".into(), "127.0.0.1".into()]) {
            if !name.is_empty() && !names.contains(&name) {
                names.push(name);
            }
        }
        names
    }
}

fn ours_line(name: &str, until: &chrono::DateTime<chrono::Utc>) -> String {
    format!(
        "{name} · may sign certificates · valid until {}",
        until.format("%F")
    )
}

/// What the chain is: ours (its own end date), then the path to the root.
fn chain_lines(chain: &Chain) -> Vec<String> {
    let until = platform_pki::not_after(&chain.ours).unwrap_or(chain.not_after);
    vec![
        ours_line(&chain.name, &until),
        format!("Chain: {} (root, also added)", chain.path.join(" › ")),
    ]
}

fn capitalised(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

impl<H: Host> App<H> {
    /// The certificate or key in the box is added; back to step 3.
    pub(super) fn import_use(&mut self, which: Which, text: &str) {
        let now = chrono::Utc::now();
        let install = &mut self.install;
        if which == Which::Cert {
            let Ok(chain) = platform_pki::check_chain(text, now) else {
                return;
            };
            // A key added before stays only if it is the new one's.
            let key = (install.imported.take())
                .and_then(|i| i.key)
                .filter(|(key, _)| {
                    platform_pki::check_key(&chain, key, &install.cert_names(), now).is_ok()
                });
            install.imported = Some(Imported {
                chain,
                key,
                from: None,
            });
        } else {
            let Ok((pkcs8, info, _)) = install.key_of(text) else {
                return;
            };
            if let Some(imported) = &mut install.imported {
                imported.key = Some((pkcs8, info));
            }
        }
        self.added();
    }

    /// Something was added: the box closes, the helper is asked again on
    /// Next, and the cursor moves to what is left to do.
    fn added(&mut self) {
        let install = &mut self.install;
        install.close_box();
        install.error = None;
        install.import_done = None;
        self.nav.pop();
        // Step 3's rows start at CERT; Maintenance's Replace page at the top.
        let first = if self.nav.screen == Screen::Install(Stage::Step(2)) {
            CERT
        } else {
            0
        };
        let to = if install.both_added() { NEXT } else { KEY };
        self.nav.row = to - CERT + first;
    }

    /// A locked key in the box asks its password in the bar, once for
    /// that text.
    pub(super) fn ask_if_locked(&mut self) {
        let install = &mut self.install;
        let text = (install.paste.as_deref()).filter(|t| ended(t) && platform_pki::is_locked(t));
        match (text, &install.locked) {
            (Some(text), Some(Locked::Key(asked))) if asked == text => {}
            (Some(text), _) => {
                install.locked = Some(Locked::Key(text.to_owned()));
                install.unlocked = None;
                install.error = None;
                install.secret = Some(PasswordPrompt::default());
            }
            (None, Some(Locked::Key(_))) => {
                install.locked = None;
                install.unlocked = None;
            }
            (None, _) => {}
        }
    }

    /// "Its password": Enter opens the .p12 or unlocks the key, a wrong
    /// one asks again; Esc forgets the bytes and the text.
    pub(super) fn secret_key(&mut self, key: Key) {
        let Some(prompt) = self.install.secret.as_mut() else {
            return;
        };
        let password = match prompt.key(key) {
            Typed::Pending => return,
            Typed::Cancelled => return self.install.close_box(),
            Typed::Entered(password) => password,
        };
        let install = &mut self.install;
        match install.locked.take() {
            Some(Locked::P12(path, bytes)) => {
                match platform_pki::read_p12(&bytes, password.expose()) {
                    Err(PkiError::WrongPassword) => {
                        install.locked = Some(Locked::P12(path, bytes));
                        if let Some(prompt) = &mut install.secret {
                            prompt.failures = prompt.failures.saturating_add(1);
                        }
                    }
                    Err(e) => {
                        let file = path.display().to_string();
                        install.secret = None;
                        install.error = Some(import_message(&ChainError::Pki(e), "", Some(&file)));
                    }
                    Ok(p12) => {
                        install.secret = None;
                        self.import_p12(p12, path.display().to_string());
                    }
                }
            }
            Some(Locked::Key(text)) => {
                match platform_pki::pkcs8_pem(&text, Some(password.expose())) {
                    Err(PkiError::WrongPassword) => {
                        install.locked = Some(Locked::Key(text));
                        if let Some(prompt) = &mut install.secret {
                            prompt.failures = prompt.failures.saturating_add(1);
                        }
                    }
                    Err(e) => {
                        install.locked = Some(Locked::Key(text));
                        install.secret = None;
                        install.error = Some(key_message(e));
                    }
                    Ok(pkcs8) => {
                        install.locked = Some(Locked::Key(text));
                        install.secret = None;
                        install.unlocked = Some(pkcs8);
                    }
                }
            }
            None => install.secret = None,
        }
    }

    /// A .p12 opened: its chain and key fill both rows, or one red line.
    fn import_p12(&mut self, p12: P12, file: String) {
        let now = chrono::Utc::now();
        let chain = match platform_pki::check_chain(&p12.certs_pem, now) {
            Ok(chain) => chain,
            Err(e) => {
                self.install.error = Some(import_message(&e, "", Some(&file)));
                return;
            }
        };
        let names = self.install.cert_names();
        match platform_pki::check_key(&chain, &p12.key_pem, &names, now) {
            Ok(info) => {
                self.install.imported = Some(Imported {
                    chain,
                    key: Some((p12.key_pem, info)),
                    from: Some(file),
                });
                self.added();
            }
            Err(e) => self.install.error = Some(import_message(&e, &chain.name, Some(&file))),
        }
    }

    /// The file browser of the certificate or key row: a .p12 asks its
    /// password; any other file must be UTF-8 text holding a certificate
    /// (no key) or a key.
    pub(super) fn import_pick(&mut self, which: Which, key: Key) {
        let path = match pick(
            &mut self.install.pick,
            &mut self.nav.row,
            &self.nav.scroll,
            key,
        ) {
            Picked::Nothing => return,
            Picked::Closed => {
                self.nav.row = 1;
                return;
            }
            Picked::File(path) => path,
        };
        let install = &mut self.install;
        let bytes = match read_bytes(&path) {
            Ok(bytes) => bytes,
            Err(error) => {
                if let Some(browse) = &mut install.pick {
                    browse.error = Some(format!("{}: {error}", path.display()));
                }
                return;
            }
        };
        if which == Which::Cert && platform_pki::is_p12(&bytes) {
            install.pick = None;
            install.error = None;
            install.locked = Some(Locked::P12(path, bytes));
            install.secret = Some(PasswordPrompt::default());
            self.nav.row = 1;
            return;
        }
        let text = String::from_utf8(bytes).map_err(|e| e.into_bytes().zeroize());
        let refused = match (which, text.as_deref()) {
            (Which::Cert, Ok(t)) if holds_private_key(t) => {
                Some("That file holds a private key: pick the certificate.")
            }
            (Which::Cert, Ok(t)) if t.contains("-----BEGIN CERTIFICATE-----") => None,
            (Which::Cert, _) => Some("That file holds no certificate: pick the certificate."),
            (_, Ok(t)) if holds_private_key(t) => None,
            _ => Some("That file holds no private key: pick the key."),
        };
        match (text, refused) {
            (Ok(text), None) => {
                install.paste = Some(text);
                install.paste_file = path
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned());
                install.pick = None;
                self.ask_if_locked();
            }
            (text, why) => {
                if let Ok(mut text) = text {
                    text.zeroize();
                }
                if let Some(browse) = &mut install.pick {
                    browse.refused = why.map(str::to_owned);
                }
            }
        }
    }
}
