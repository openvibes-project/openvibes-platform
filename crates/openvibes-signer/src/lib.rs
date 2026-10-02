#![forbid(unsafe_code)]

//! The rule signer (board #107, own rules, platform #151 §4): holds the
//! site key and signs `site` and `site-alarms` rule sets for the console,
//! only after checking the publishing user's password and `rules.upload`
//! itself. It answers on a Unix socket, one request per connection.

pub mod config;
pub mod request;
pub mod sign;
pub mod state;

use std::{os::unix::fs::PermissionsExt, path::Path, sync::Arc, time::Duration};

use chrono::Utc;
use ed25519_dalek::SigningKey;
use platform_password::{
    NormalizedPassword, canonical_username, dummy_password_phc, verify_password,
};
use platform_store::{Pool, console_auth, signer as store};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::{Mutex, Semaphore},
};

pub use config::SignerConfig;
use request::{Refusal, SITE, SITE_ALARMS, SignRequest, SignResponse};
use state::State;

/// Largest request: the rule set plus a little.
pub const MAX_REQUEST: u64 = 1 << 20;
/// A connection's whole request must arrive within this.
pub const READ_TIMEOUT: Duration = Duration::from_secs(5);
/// Argon2id checks at once: each takes ~19 MiB.
pub const VERIFICATIONS: usize = 2;
/// Connections at once (each may hold up to [`MAX_REQUEST`] for
/// [`READ_TIMEOUT`]); more are closed at once.
pub const CONNECTIONS: usize = 8;
/// Wrong passwords per account before it locks, the same bucket and limit
/// as console sign-in.
const ACCOUNT_FAILURE_LIMIT: i32 = 5;
const FAILURE_WINDOW_MINUTES: i64 = 15;

/// A running signer.
pub struct Signer {
    config: SignerConfig,
    key: SigningKey,
    pool: Pool,
    state: Mutex<State>,
    verify: Semaphore,
}

impl Signer {
    /// Reads the key and the version state.
    ///
    /// # Errors
    /// An unusable key file.
    pub fn new(config: SignerConfig, pool: Pool) -> Result<Self, String> {
        let key = sign::read_key(&config.key_file)?;
        let state = State::open(&config.state_dir);
        Ok(Self {
            config,
            key,
            pool,
            state: Mutex::new(state),
            verify: Semaphore::new(VERIFICATIONS),
        })
    }

    /// Answers one request. The body is never logged.
    pub async fn handle(&self, body: &[u8]) -> SignResponse {
        let now = Utc::now();
        let now_ms = now.timestamp_millis();
        let (user, rule_set, outcome) = match serde_json::from_slice::<SignRequest>(body) {
            Ok(request) => {
                let user = canonical_username(&request.username);
                let outcome = self.check_and_sign(&request, user.as_deref(), now).await;
                (user, Some(request.rule_set), outcome)
            }
            Err(_) => (None, None, Err(Refusal::Invalid)),
        };
        let mut state = self.state.lock().await;
        let response = match outcome {
            Ok((signed, version, rules)) => {
                audit(
                    user.as_deref(),
                    rule_set.as_deref(),
                    "signed",
                    Some((version, rules, &signed.sha256)),
                );
                SignResponse::Signed {
                    envelope: signed.envelope,
                    version,
                    expires_at_unix_ms: signed.expires_at_unix_ms,
                }
            }
            Err(code) => {
                state.record_refusal(code, now_ms);
                audit(user.as_deref(), rule_set.as_deref(), code.code(), None);
                SignResponse::Refused { code }
            }
        };
        if let Err(error) = state.write_status(now_ms, false) {
            eprintln!("openvibes-signer: cannot write status.json: {error}");
        }
        response
    }

    async fn check_and_sign(
        &self,
        request: &SignRequest,
        user: Option<&str>,
        now: chrono::DateTime<Utc>,
    ) -> Result<(sign::Signed, u64, usize), Refusal> {
        let now_ms = now.timestamp_millis();
        if request.rule_set != SITE && request.rule_set != SITE_ALARMS {
            return Err(Refusal::Invalid);
        }
        // Fail fast without state; the version itself is taken under the
        // lock below.
        if self
            .state
            .lock()
            .await
            .next_version(&request.rule_set)
            .is_none()
        {
            return Err(Refusal::VersionState);
        }
        let client = self.pool.get().await.map_err(|_| Refusal::Unavailable)?;
        // An impossible name still costs a full check (and gets the same
        // answer), so names can't be probed.
        let bucket = console_auth::account_throttle_bucket(user.unwrap_or(""));
        if console_auth::login_is_throttled(&client, &[&bucket], now)
            .await
            .map_err(|_| Refusal::Unavailable)?
        {
            return Err(Refusal::Throttled);
        }
        let account = match user {
            Some(user) => store::signer_user(&client, user)
                .await
                .map_err(|_| Refusal::Unavailable)?,
            None => None,
        };
        let valid = self.verify(request, account.as_ref()).await?;
        let Some(account) = account.filter(|account| valid && account.enabled) else {
            if user.is_some() {
                let window = chrono::Duration::minutes(FAILURE_WINDOW_MINUTES);
                store::record_signer_failure(
                    &client,
                    &bucket,
                    now,
                    window,
                    ACCOUNT_FAILURE_LIMIT,
                    window,
                )
                .await
                .map_err(|_| Refusal::Unavailable)?;
            }
            return Err(Refusal::Credentials);
        };
        if account.must_change
            || !store::may_upload_rules(&client, &account.user_id)
                .await
                .map_err(|_| Refusal::Unavailable)?
        {
            return Err(Refusal::Forbidden);
        }
        sign::check_rules(
            &request.rule_set,
            &request.rules,
            self.config.rules_per_publish,
        )?;
        // One lock from the rate check to the recorded version: two
        // publishes at once must never both pass the limit or sign the same
        // version (signing takes microseconds).
        let mut state = self.state.lock().await;
        let limit = usize::try_from(self.config.publishes_per_hour).unwrap_or(usize::MAX);
        if state.publishes_this_hour(now_ms) >= limit {
            return Err(Refusal::Rate);
        }
        let version = state
            .next_version(&request.rule_set)
            .ok_or(Refusal::VersionState)?;
        let signed = sign::sign(
            &self.key,
            &self.config.issuer_key_id,
            &request.rule_set,
            version,
            &request.rules,
            now_ms,
            self.config.validity_days,
        )?;
        state
            .record_signed(
                &request.rule_set,
                version,
                signed.expires_at_unix_ms,
                &request.rules,
                now_ms,
            )
            .map_err(|error| {
                eprintln!("openvibes-signer: {error}");
                Refusal::Unavailable
            })?;
        drop(state);
        let rules = serde_json::from_str::<openvibes_core::RuleSet>(&request.rules)
            .map_or(0, |set| set.rules.len());
        Ok((signed, version, rules))
    }

    /// Argon2id against the account's credential, or a dummy one when there
    /// is no account, at most [`VERIFICATIONS`] at once.
    async fn verify(
        &self,
        request: &SignRequest,
        account: Option<&store::SignerUser>,
    ) -> Result<bool, Refusal> {
        let phc = account
            .map(|account| account.password_phc.clone())
            .or_else(|| dummy_password_phc().map(str::to_owned))
            .ok_or(Refusal::Unavailable)?;
        let bounded = NormalizedPassword::for_verification(request.password.expose());
        let usable = bounded.is_ok();
        let password = bounded
            .or_else(|_| NormalizedPassword::for_verification("invalid bounded input"))
            .map_err(|_| Refusal::Unavailable)?;
        let _permit = self
            .verify
            .acquire()
            .await
            .map_err(|_| Refusal::Unavailable)?;
        let verified = tokio::task::spawn_blocking(move || verify_password(&password, &phc))
            .await
            .map_err(|_| Refusal::Unavailable)?;
        Ok(usable && account.is_some() && verified.is_ok_and(|v| v.valid))
    }

    /// Serves `listener` until `shutdown` resolves.
    pub async fn serve(
        self: Arc<Self>,
        listener: UnixListener,
        shutdown: impl Future<Output = ()>,
    ) {
        tokio::pin!(shutdown);
        let connections = Arc::new(Semaphore::new(CONNECTIONS));
        let mut flush = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                () = &mut shutdown => {
                    self.flush_status().await;
                    return;
                }
                _ = flush.tick() => self.flush_status().await,
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else { continue };
                    // Over the cap the stream is dropped unread.
                    let Ok(permit) = Arc::clone(&connections).try_acquire_owned() else {
                        continue;
                    };
                    let signer = Arc::clone(&self);
                    tokio::spawn(async move {
                        signer.connection(stream).await;
                        drop(permit);
                    });
                }
            }
        }
    }

    /// Writes `status.json` if something changed since it was last written.
    pub async fn flush_status(&self) {
        let now_ms = Utc::now().timestamp_millis();
        if let Err(error) = self.state.lock().await.write_status(now_ms, true) {
            eprintln!("openvibes-signer: cannot write status.json: {error}");
        }
    }

    async fn connection(&self, mut stream: UnixStream) {
        let mut body = Vec::new();
        let read = tokio::time::timeout(
            READ_TIMEOUT,
            (&mut stream).take(MAX_REQUEST + 1).read_to_end(&mut body),
        )
        .await;
        let response = match read {
            Ok(Ok(_)) if body.len() as u64 <= MAX_REQUEST => self.handle(&body).await,
            _ => SignResponse::Refused {
                code: Refusal::Invalid,
            },
        };
        zeroize::Zeroize::zeroize(&mut body);
        if let Ok(bytes) = serde_json::to_vec(&response) {
            let _ = stream.write_all(&bytes).await;
        }
        let _ = stream.shutdown().await;
    }
}

/// Binds `path` as the signer's socket, mode 0660 (the unit's group is the
/// console's), replacing a stale socket.
///
/// # Errors
/// The socket can't be bound.
pub fn bind(path: &Path) -> std::io::Result<UnixListener> {
    use std::os::unix::fs::FileTypeExt;
    if std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_socket()) {
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(listener)
}

/// One audit line to the journal: who, which set, the result, and for a
/// signature its version, rule count and digest. Never the rules or the
/// password.
fn audit(
    user: Option<&str>,
    rule_set: Option<&str>,
    result: &str,
    signed: Option<(u64, usize, &str)>,
) {
    let mut line = serde_json::json!({
        "audit": "rules.sign",
        "user": user,
        "rule_set": rule_set.filter(|set| *set == SITE || *set == SITE_ALARMS),
        "result": result,
    });
    if let Some((version, rules, sha256)) = signed {
        line["version"] = version.into();
        line["rules"] = rules.into();
        line["sha256"] = sha256.into();
    }
    eprintln!("{line}");
}
