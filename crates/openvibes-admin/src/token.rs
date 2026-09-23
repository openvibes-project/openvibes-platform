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
            Self::List => "token list",
            Self::Revoke { .. } => "token revoke",
        }
    }
}

fn parse_expiry(value: &str) -> Result<Duration, String> {
    let (number, unit) = value.split_at(value.len().saturating_sub(1));
    let number: i64 = number
        .parse()
        .map_err(|_| "use Nh or Nd, e.g. 12h or 7d".to_owned())?;
    let duration = match unit {
        "h" => Duration::hours(number),
        "d" => Duration::days(number),
        _ => return Err("use Nh or Nd, e.g. 12h or 7d".into()),
    };
    if duration < Duration::hours(1) || duration > Duration::days(365) {
        return Err("must be between 1h and 365d".into());
    }
    Ok(duration)
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
            let hash: [u8; 32] = match ring::digest::digest(&ring::digest::SHA256, &secret)
                .as_ref()
                .try_into()
            {
                Ok(hash) => hash,
                Err(_) => return (Err("hashing failed".into()), None),
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
                        } else if token.expires_at <= now {
                            "expired"
                        } else if token.uses >= i64::from(token.max_uses) {
                            "used up"
                        } else {
                            "usable"
                        };
                        format!(
                            "{}  {state}  uses {}/{}  expires {}  {}\n",
                            token.token_id,
                            token.uses,
                            token.max_uses,
                            token.expires_at.format("%Y-%m-%d %H:%M UTC"),
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
