//! `openvibes-admin token …`: enrollment tokens, shown once, stored hashed.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use clap::Subcommand;
use platform_store::tokens::{self, NewToken};
use ring::rand::{SecureRandom, SystemRandom};

#[derive(Subcommand)]
pub enum TokenCommand {
    /// Create a token; it is printed once and never stored.
    Create {
        /// Validity: `Nh` or `Nd`, from 1h to 365d.
        #[arg(long, value_parser = parse_expiry)]
        expires: Duration,
        /// Enrollments it allows (1 to 100000).
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(i32).range(1..=100_000))]
        uses: i32,
        /// Operator's note.
        #[arg(long)]
        label: Option<String>,
    },
    /// Show the standing token every agent can enroll with (never expires,
    /// no use limit), creating it first if there is none. Revoke it with
    /// `token revoke` to replace it; agents already enrolled keep working.
    Fleet,
    /// List tokens (never shows the tokens themselves).
    List,
    /// Revoke a token by id.
    Revoke {
        /// Token id from `token create` or `token list`.
        id: String,
    },
}

impl TokenCommand {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Create { .. } => "token create",
            Self::Fleet => "token fleet",
            Self::List => "token list",
            Self::Revoke { .. } => "token revoke",
        }
    }
}

fn parse_expiry(value: &str) -> Result<Duration, String> {
    const HINT: &str = "use Nh or Nd, e.g. 12h or 7d";
    let (number, per_unit) = match (value.strip_suffix('h'), value.strip_suffix('d')) {
        (Some(number), _) => (number, 1),
        (_, Some(number)) => (number, 24),
        _ => return Err(HINT.into()),
    };
    // Bounded before building a duration, so no input can overflow.
    let number: u32 = number.parse().map_err(|_| HINT.to_owned())?;
    let hours = u64::from(number) * per_unit;
    if !(1..=365 * 24).contains(&hours) {
        return Err("must be between 1h and 365d".into());
    }
    Ok(Duration::hours(
        i64::try_from(hours).map_err(|_| HINT.to_owned())?,
    ))
}

/// The standing token's id and secret, created on first use. The `bool` is
/// whether this call created it.
pub async fn fleet(
    client: &platform_store::Client,
    actor: &str,
) -> Result<(String, String, bool), String> {
    let store = |error: platform_store::StoreError| error.to_string();
    if let Some((id, secret)) = tokens::live_standing(client).await.map_err(store)? {
        return Ok((id, secret, false));
    }
    let mut bytes = [0u8; 32];
    if SystemRandom::new().fill(&mut bytes).is_err() {
        return Err("no randomness available".into());
    }
    let secret = URL_SAFE_NO_PAD.encode(bytes);
    let Some(hash) = platform_pki::enrollment_token_sha256(&secret) else {
        return Err("token encoding failed".into());
    };
    if let Some(id) = tokens::create_standing(client, &secret, hash, actor, Utc::now())
        .await
        .map_err(store)?
    {
        return Ok((id, secret, true));
    }
    // Lost a race with another creator: theirs is the standing token.
    match tokens::live_standing(client).await.map_err(store)? {
        Some((id, secret)) => Ok((id, secret, false)),
        None => Err("the standing token could not be created".into()),
    }
}

/// Runs a token command; returns the output and the audit target (the
/// token id, never the token).
pub async fn run(
    command: &TokenCommand,
    client: &platform_store::Client,
    actor: &str,
) -> (Result<String, String>, Option<String>) {
    match command {
        TokenCommand::Create {
            expires,
            uses,
            label,
        } => {
            let mut secret = [0u8; 32];
            if SystemRandom::new().fill(&mut secret).is_err() {
                return (Err("no randomness available".into()), None);
            }
            let token = URL_SAFE_NO_PAD.encode(secret);
            // The same helper ingest uses, so the stored hash always matches.
            let Some(hash) = platform_pki::enrollment_token_sha256(&token) else {
                return (Err("token encoding failed".into()), None);
            };
            let new = NewToken {
                token_sha256: hash,
                label: label.clone(),
                created_by: actor.to_owned(),
                expires_at: Utc::now() + *expires,
                max_uses: *uses,
            };
            match tokens::create(client, &new).await {
                Ok(id) => (
                    Ok(format!(
                        "token id {id}\ntoken {token}\nThe token is shown only now; store it safely.\n"
                    )),
                    Some(id),
                ),
                Err(error) => (Err(error.to_string()), None),
            }
        }
        TokenCommand::Fleet => match fleet(client, actor).await {
            Ok((id, token, created)) => (
                Ok(format!(
                    "token id {id}\ntoken {token}\n{}\n",
                    if created {
                        "Created the standing token: it never expires and has no use limit."
                    } else {
                        "The standing token: it never expires and has no use limit."
                    }
                )),
                Some(id),
            ),
            Err(error) => (Err(error), None),
        },
        TokenCommand::List => {
            let now = Utc::now();
            let listed = tokens::list(client)
                .await
                .map_err(|error| error.to_string());
            let output = listed.map(|tokens| {
                tokens
                    .iter()
                    .map(|token| {
                        let state = if token.revoked {
                            "revoked"
                        } else if token.standing {
                            "standing"
                        } else if token.expires_at <= now {
                            "expired"
                        } else if token.uses >= i64::from(token.max_uses) {
                            "used up"
                        } else {
                            "usable"
                        };
                        let (limit, expires) = if token.standing {
                            ("unlimited".to_owned(), "never".to_owned())
                        } else {
                            (
                                token.max_uses.to_string(),
                                token.expires_at.format("%Y-%m-%d %H:%M UTC").to_string(),
                            )
                        };
                        format!(
                            "{}  {state}  uses {}/{limit}  expires {expires}  {}\n",
                            token.token_id,
                            token.uses,
                            token.label.as_deref().unwrap_or(""),
                        )
                    })
                    .collect()
            });
            (output, None)
        }
        TokenCommand::Revoke { id } => {
            let target = Some(id.clone());
            match tokens::revoke(client, id, Utc::now()).await {
                Ok(true) => (Ok(format!("revoked token {id}\n")), target),
                Ok(false) => (Err("token already revoked or unknown".into()), target),
                Err(platform_store::StoreError::Query) => (Err("not a token id".into()), target),
                Err(error) => (Err(error.to_string()), target),
            }
        }
    }
}
