//! Console users (#85): an administrator creates a local user with a
//! one-time password, and every user sets their own password, which the
//! one-time password forces at first sign-in (`password_must_change`).

use axum::{
    Json,
    extract::{State, rejection::JsonRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use platform_store::{console_auth, console_read::AgentScope};
use ring::rand::{SecureRandom, SystemRandom};

use crate::{
    auth::{
        NormalizedPassword, PresentedCredentials, hash_password, presented_credentials,
        verify_password,
    },
    problem::{ProblemDetails, problem_response},
    router::{
        ACCOUNT_FAILURE_LIMIT, AuthHttpState, account_throttle_bucket, authenticated_permission,
        authentication_required, bounded_user_agent, checked_session, unavailable_auth,
    },
};

/// Letters and digits that cannot be mistaken for one another when read
/// aloud or copied by hand (no 0/O, 1/l/I).
const ONE_TIME_ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
/// Four groups of five: 20 random symbols, about 99 bits.
const ONE_TIME_GROUPS: usize = 4;

fn bad_request(code: &'static str, detail: &'static str) -> Response {
    problem_response(ProblemDetails::new(StatusCode::BAD_REQUEST, code, detail))
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// The CLI's rule: 1 to 64 ASCII letters, digits or `._@+-`, lowercased.
fn canonical_username(username: &str) -> Option<String> {
    let valid = !username.is_empty()
        && username.len() <= 64
        && username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._@+-".contains(&byte));
    valid.then(|| username.to_ascii_lowercase())
}

/// A one-time password such as `k7m2p-qx9rt-…`, from the system RNG.
fn one_time_password() -> Option<String> {
    let mut bytes = [0_u8; ONE_TIME_GROUPS * 5];
    SystemRandom::new().fill(&mut bytes).ok()?;
    let symbols: Vec<char> = bytes
        .iter()
        // 256 is not a multiple of 31; the bias (< 1 %) costs well under a
        // bit of the ~99.
        .map(|byte| char::from(ONE_TIME_ALPHABET[usize::from(*byte) % ONE_TIME_ALPHABET.len()]))
        .collect();
    Some(
        symbols
            .chunks(5)
            .map(|group| group.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join("-"),
    )
}

fn random_uuid() -> Option<String> {
    let mut bytes = [0_u8; 16];
    SystemRandom::new().fill(&mut bytes).ok()?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    Some(format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
}

/// Creates a local user with one global built-in role and a one-time
/// password, returned only here; the user must replace it at first sign-in.
#[utoipa::path(post, path = "/api/v1/access-control/users", tag = "access control",
    request_body = crate::CreateUserRequest,
    responses(
        (status = 201, description = "User created; the one-time password is shown only here", body = crate::CreatedUser),
        (status = 400, description = "Invalid username, display name or role", body = ProblemDetails),
        (status = 403, description = "Needs rbac.manage with a global binding", body = ProblemDetails),
        (status = 409, description = "The username is taken", body = ProblemDetails),
    ))]
pub(crate) async fn create_user(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    payload: Result<Json<crate::CreateUserRequest>, JsonRejection>,
) -> Response {
    // Authentication, CSRF and permission first: nothing about the body is
    // answered to a caller who may not make the request (no validation
    // oracle; a forced-change session gets 403, not 400).
    let (scope, actor) =
        match authenticated_permission(&state, &headers, crate::Permission::RbacManage, true).await
        {
            Ok(value) => value,
            Err(response) => return response,
        };
    // Users get global roles; only a global administrator makes them.
    if !matches!(scope, AgentScope::Global) {
        return problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "Access is not available",
        ));
    }
    let Ok(Json(request)) = payload else {
        return bad_request("invalid_user", "Provide a username, display name and role");
    };
    let display_name = request.display_name.trim();
    let (Some(username), true, true) = (
        canonical_username(&request.username),
        !display_name.is_empty()
            && display_name.chars().count() <= 160
            && !display_name.chars().any(char::is_control),
        matches!(
            request.role_id.as_str(),
            "viewer" | "analyst" | "operator" | "admin"
        ),
    ) else {
        return bad_request(
            "invalid_user",
            "Use 1 to 64 letters, digits or ._@+- for the username, 1 to 160 characters for the name, and a built-in role",
        );
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match console_auth::username_taken(&client, &username).await {
        Ok(false) => {}
        Ok(true) => {
            return problem_response(ProblemDetails::new(
                StatusCode::CONFLICT,
                "user_conflict",
                "A user with this username already exists",
            ));
        }
        Err(_) => return unavailable_auth(),
    }
    let (Some(password), Some(user_id), Some(binding_id)) =
        (one_time_password(), random_uuid(), random_uuid())
    else {
        return unavailable_auth();
    };
    let Ok(normalized) = NormalizedPassword::new(&password) else {
        return unavailable_auth(); // the generator always makes a valid one
    };
    let Ok(permit) = state.password_slots.clone().try_acquire_owned() else {
        return busy();
    };
    let Ok(Ok(phc)) = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        hash_password(&normalized).map(|hash| hash.as_str().to_owned())
    })
    .await
    else {
        return unavailable_auth();
    };
    let created = console_auth::create_local_user(
        &mut client,
        &console_auth::NewLocalUser {
            user_id: &user_id,
            binding_id: &binding_id,
            username: &username,
            display_name,
            password_phc: &phc,
            role_id: &request.role_id,
            actor_id: &actor,
            actor_kind: "user",
            password_must_change: true,
            now: Utc::now(),
        },
    )
    .await;
    if created.is_err() {
        // Lost a race with another create of the same name (the unique
        // username refused it): a conflict, not an outage.
        return match console_auth::username_taken(&client, &username).await {
            Ok(true) => problem_response(ProblemDetails::new(
                StatusCode::CONFLICT,
                "user_conflict",
                "A user with this username already exists",
            )),
            _ => unavailable_auth(),
        };
    }
    no_store(
        (
            StatusCode::CREATED,
            Json(crate::CreatedUser {
                user_id,
                username,
                display_name: display_name.to_owned(),
                role_id: request.role_id,
                one_time_password: password,
            }),
        )
            .into_response(),
    )
}

fn too_many_attempts() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::TOO_MANY_REQUESTS,
        "too_many_attempts",
        "Too many wrong passwords; wait 15 minutes",
    ))
}

fn busy() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "authentication_busy",
        "Authentication is temporarily busy",
    ))
}

/// Sets the signed-in user's own password: the current one is required,
/// the new one must be at least 15 characters and differ from it. Clears
/// `password_must_change`, signs out the user's other sessions, and is
/// audited. Works while the flag is set; browser sessions only.
#[utoipa::path(post, path = "/api/v1/session/password", tag = "session",
    request_body = crate::ChangePasswordRequest,
    responses(
        (status = 204, description = "Password set; the user's other sessions are signed out"),
        (status = 400, description = "Wrong current password, or a new password that is too short or unchanged", body = ProblemDetails),
        (status = 401, description = "Not signed in", body = ProblemDetails),
        (status = 429, description = "Too many wrong passwords for this account (shared with sign-in)", body = ProblemDetails),
    ))]
pub(crate) async fn change_password(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    payload: Result<Json<crate::ChangePasswordRequest>, JsonRejection>,
) -> Response {
    let secret = match presented_credentials(&headers) {
        Ok(PresentedCredentials::Session(secret)) => secret,
        Ok(PresentedCredentials::Bearer(_)) => {
            return problem_response(ProblemDetails::new(
                StatusCode::FORBIDDEN,
                "permission_denied",
                "Access is not available",
            ));
        }
        _ => return authentication_required(),
    };
    let (active, digest) =
        match checked_session(&state, &headers, secret.expose_secret(), true).await {
            Ok(value) => value,
            Err(response) => return response,
        };
    let Ok(Json(request)) = payload else {
        return bad_request(
            "invalid_password",
            "Provide the current and the new password",
        );
    };
    let Ok(current) = NormalizedPassword::for_verification(&request.current_password) else {
        return bad_request(
            "invalid_current_password",
            "The current password is not right",
        );
    };
    let Ok(new) = NormalizedPassword::new(&request.new_password) else {
        return bad_request(
            "weak_password",
            "Use at least 15 characters for the new password",
        );
    };
    if current.as_bytes() == new.as_bytes() {
        return bad_request(
            "password_unchanged",
            "Choose a password different from the current one",
        );
    }
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    // A wrong current password counts against sign-in's per-account limit,
    // so a stolen session cannot guess it faster than sign-in could.
    let bucket = account_throttle_bucket(&active.username);
    let buckets: [&[u8]; 1] = [&bucket];
    let now = Utc::now();
    match console_auth::login_is_throttled(&client, &buckets, now).await {
        Ok(false) => {}
        Ok(true) => return too_many_attempts(),
        Err(_) => return unavailable_auth(),
    }
    let credential = match console_auth::credential_by_username(&client, &active.username).await {
        Ok(Some(credential)) if credential.enabled => credential,
        Ok(_) => return authentication_required(),
        Err(_) => return unavailable_auth(),
    };
    let Ok(permit) = state.password_slots.clone().try_acquire_owned() else {
        return busy();
    };
    let stored = credential.password_phc.clone();
    let hashed = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let valid = verify_password(&current, &stored)?.valid;
        Ok::<_, crate::PasswordHashError>(if valid {
            Some(hash_password(&new)?.as_str().to_owned())
        } else {
            None
        })
    })
    .await;
    let user_agent = bounded_user_agent(&headers);
    let audit = console_auth::AuditContext {
        request_id: None,
        source_address: None,
        user_agent: user_agent.as_deref(),
    };
    let phc = match hashed {
        Ok(Ok(Some(phc))) => phc,
        Ok(Ok(None)) => {
            let window = chrono::Duration::minutes(15);
            let recorded = console_auth::record_login_failure(
                &mut client,
                &buckets,
                now,
                window,
                &[ACCOUNT_FAILURE_LIMIT],
                window,
                &audit,
            )
            .await;
            return match recorded {
                Ok(()) => bad_request(
                    "invalid_current_password",
                    "The current password is not right",
                ),
                Err(_) => unavailable_auth(),
            };
        }
        _ => return unavailable_auth(),
    };
    if console_auth::clear_login_throttle(&client, &buckets, now)
        .await
        .is_err()
    {
        return unavailable_auth();
    }
    match console_auth::change_own_password(
        &mut client,
        &active.user_id,
        &digest,
        &phc,
        now,
        &audit,
    )
    .await
    {
        Ok(true) => no_store(StatusCode::NO_CONTENT.into_response()),
        Ok(false) => authentication_required(),
        Err(_) => unavailable_auth(),
    }
}

#[cfg(test)]
mod tests {
    use super::{canonical_username, one_time_password};

    #[test]
    fn one_time_passwords_are_long_unambiguous_and_different() {
        let a = one_time_password().unwrap();
        let b = one_time_password().unwrap();
        assert_ne!(a, b);
        assert_eq!(a.len(), 23, "{a}");
        assert!(a.split('-').all(|group| group.len() == 5));
        assert!(!a.chars().any(|c| "0o1liI".contains(c)), "{a}");
        assert!(crate::auth::NormalizedPassword::new(&a).is_ok());
    }

    #[test]
    fn usernames_follow_the_cli_rule() {
        assert_eq!(canonical_username("Alice.B").as_deref(), Some("alice.b"));
        assert!(canonical_username("").is_none());
        assert!(canonical_username("a b").is_none());
        assert!(canonical_username(&"a".repeat(65)).is_none());
    }
}
