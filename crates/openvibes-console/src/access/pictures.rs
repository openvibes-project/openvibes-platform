//! Profile pictures (spec §9.2): set, remove and serve a person's picture.
//! Anyone may set or remove their own; someone else's needs `access.users`
//! inside the share. The upload is checked here from its header, then decoded
//! by the sandboxed `openvibes-picture` service; the original is never kept.

use std::{path::Path as FsPath, time::Duration};

use axum::{
    body::Bytes,
    extract::{Json, Path, Query, State, rejection::BytesRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use openvibes_picture::{Crop, Output, Refusal, wire};
use platform_store::console_people::{self, PictureSize};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::Permission;
use crate::access::editor::caller;
use crate::access::guard::{session_user, unavailable_auth};
use crate::access::people::{user_not_found, visible_person};
use crate::http::{
    AuthHttpState,
    problem::{ProblemDetails, problem_response},
    validate::valid_uuid,
};

/// Room for the picture plus its request line.
pub(crate) const MAX_BODY: usize = openvibes_picture::MAX_BYTES + 4096;

/// Where `openvibes-picture.socket` listens.
pub(crate) const DEFAULT_PICTURE_SOCKET: &str = "/run/openvibes-picture/picture.sock";
/// The service allows 10 s of CPU and kills itself at 15 s of run time.
const TIMEOUT: Duration = Duration::from_secs(20);
const MAX_REPLY: u64 = 7 * 1024 * 1024;

/// The square to keep, in pixels of the uploaded picture.
#[derive(Deserialize, ToSchema, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct CropQuery {
    /// Left edge.
    x: u32,
    /// Top edge.
    y: u32,
    /// Side of the square.
    size: u32,
}

/// Which stored image to serve.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct SizeQuery {
    /// `64` or `256`.
    size: u32,
}

/// The picture was saved.
#[derive(Serialize, ToSchema)]
pub struct PictureSet {
    /// The picture's version; add it as `v` to the picture URL.
    pub picture: String,
}

fn refused(refusal: Refusal) -> Response {
    let status = match refusal {
        Refusal::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        _ => StatusCode::UNPROCESSABLE_ENTITY,
    };
    problem_response(ProblemDetails::new(
        status,
        refusal.code(),
        refusal.message(),
    ))
}

fn unavailable() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "picture_unavailable",
        "Pictures cannot be processed right now; try again shortly",
    ))
}

/// One exchange with the picture service; `None` when it cannot be reached
/// or answers anything but a response.
async fn convert_remote(
    socket: &FsPath,
    crop: Crop,
    picture: &[u8],
) -> Option<Result<Output, Refusal>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let request = wire::request(crop, picture);
    let exchange = async {
        let mut stream = tokio::net::UnixStream::connect(socket).await?;
        stream.write_all(&request).await?;
        stream.shutdown().await?;
        let mut reply = Vec::new();
        stream.take(MAX_REPLY).read_to_end(&mut reply).await?;
        Ok::<_, std::io::Error>(reply)
    };
    let reply = tokio::time::timeout(TIMEOUT, exchange).await.ok()?.ok()?;
    wire::parse_response(&reply)
}

/// Sets a person's picture from an uploaded file and the square to keep.
#[utoipa::path(put, path = "/api/v1/users/{user_id}/picture", tag = "access control",
    params(("user_id" = String, Path), CropQuery),
    request_body(content = Vec<u8>, content_type = "application/octet-stream", description = "The original picture, at most 10 MB"),
    responses((status = 200, description = "Saved", body = PictureSet),
        (status = 403, description = "Needs access.users for someone else", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such person inside your access", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 413, description = "picture_too_large", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "The picture was refused (picture_svg, picture_heic, picture_unsupported, picture_dimensions, picture_frames, picture_work, picture_crop, picture_decode, picture_output)", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "picture_unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn put_picture(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Query(crop): Query<CropQuery>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let editor = match caller(&state, &headers, true).await {
        Ok(editor) => editor,
        Err(response) => return response,
    };
    if !user_id.eq_ignore_ascii_case(&editor.actor)
        && let Some(response) = editor.denied(Permission::AccessUsers)
    {
        return response;
    }
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let person = match visible_person(&client, &editor, &user_id).await {
        Ok((person, _)) => person,
        Err(response) => return response,
    };
    let Ok(body) = body else {
        return refused(Refusal::TooLarge);
    };
    let crop = Crop {
        x: crop.x,
        y: crop.y,
        size: crop.size,
    };
    // The service checks the picture from its header before decoding it.
    let output = match convert_remote(&state.picture_socket, crop, &body).await {
        Some(Ok(output)) => output,
        Some(Err(refusal)) => return refused(refusal),
        None => return unavailable(),
    };
    let saved = console_people::set_picture(
        &mut client,
        &person.user_id,
        &output.large,
        &output.small,
        output.animated,
        &editor.actor,
        Utc::now(),
    )
    .await;
    match saved {
        Ok(Some(picture)) => Json(PictureSet { picture }).into_response(),
        Ok(None) => user_not_found(),
        Err(_) => unavailable_auth(),
    }
}

/// Removes a person's picture; their initials are shown again.
#[utoipa::path(delete, path = "/api/v1/users/{user_id}/picture", tag = "access control",
    params(("user_id" = String, Path)),
    responses((status = 204, description = "Removed (or there was none)"),
        (status = 403, description = "Needs access.users for someone else", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such person inside your access", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn delete_picture(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Response {
    let editor = match caller(&state, &headers, true).await {
        Ok(editor) => editor,
        Err(response) => return response,
    };
    if !user_id.eq_ignore_ascii_case(&editor.actor)
        && let Some(response) = editor.denied(Permission::AccessUsers)
    {
        return response;
    }
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let person = match visible_person(&client, &editor, &user_id).await {
        Ok((person, _)) => person,
        Err(response) => return response,
    };
    match console_people::remove_picture(&mut client, &person.user_id, &editor.actor, Utc::now())
        .await
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => unavailable_auth(),
    }
}

/// A person's picture as a WebP image, at 64 or 256 px. Any signed-in person
/// may fetch it; it is never served as HTML.
#[utoipa::path(get, path = "/api/v1/users/{user_id}/picture", tag = "access control",
    params(("user_id" = String, Path), SizeQuery),
    responses((status = 200, description = "The image", body = Vec<u8>, content_type = "image/webp"),
        (status = 304, description = "Not modified"),
        (status = 404, description = "No picture", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn get_picture(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Query(query): Query<SizeQuery>,
) -> Response {
    if let Err(response) = session_user(&state, &headers, false).await {
        return response;
    }
    let size = match query.size {
        64 => PictureSize::Small,
        256 => PictureSize::Large,
        _ => {
            return problem_response(ProblemDetails::new(
                StatusCode::BAD_REQUEST,
                "invalid_size",
                "Ask for size 64 or 256",
            ));
        }
    };
    if !valid_uuid(&user_id) {
        return no_picture();
    }
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let found = match console_people::picture(&client, &user_id, size).await {
        Ok(Some(found)) => found,
        Ok(None) => return no_picture(),
        Err(_) => return unavailable_auth(),
    };
    // One ETag for the person's picture; the size is in the URL.
    let etag = format!("\"{}-{}\"", found.etag, query.size);
    let mut response = if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|presented| presented.split(',').any(|tag| tag.trim() == etag))
    {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        (StatusCode::OK, found.image).into_response()
    };
    let ok = response.status() == StatusCode::OK;
    let out = response.headers_mut();
    if ok {
        out.insert(header::CONTENT_TYPE, HeaderValue::from_static("image/webp"));
    }
    out.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    out.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("inline"),
    );
    out.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-cache"),
    );
    if let Ok(value) = HeaderValue::from_str(&etag) {
        out.insert(header::ETAG, value);
    }
    response
}

fn no_picture() -> Response {
    problem_response(ProblemDetails::not_found("picture_not_found", "No picture"))
}
