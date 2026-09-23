//! Enrollment token hashing and agent ids, shared by admin and ingest so
//! both sides derive the same stored hash.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

/// Length of a printed token: 32 bytes in base64url without padding.
const TOKEN_CHARS: usize = 43;

/// SHA-256 of a token's 32 decoded bytes, or `None` unless `token` is
/// exactly 43 base64url characters (no padding, no whitespace).
#[must_use]
pub fn enrollment_token_sha256(token: &str) -> Option<[u8; 32]> {
    if token.len() != TOKEN_CHARS {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(token).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    ring::digest::digest(&ring::digest::SHA256, &bytes)
        .as_ref()
        .try_into()
        .ok()
}

/// Whether `id` is `agent.` followed by a lowercase hyphenated UUID, the
/// only form the platform assigns (and the database accepts).
#[must_use]
pub fn is_agent_id(id: &str) -> bool {
    let Some(uuid) = id.strip_prefix("agent.") else {
        return false;
    };
    uuid.len() == 36
        && uuid.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}
