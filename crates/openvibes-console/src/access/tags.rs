//! Host tags: replaced by labels (schema 53); the routes answer 410 until
//! the label routes arrive.

use axum::response::Response;

use super::asset_groups::moved;
use crate::http::problem::ProblemDetails;

/// Previews asset group membership changes for an agent's complete tag set.
#[utoipa::path(post, path="/api/v1/agents/{agent_id}/tags/preview", tag="agents", params(("agent_id"=String,Path)), request_body=crate::AgentTagChangeRequest, responses((status=200,description="Membership impact preview",body=crate::AgentTagPreviewResponse),(status=400,description="Invalid tag set",body=ProblemDetails),(status=404,description="Agent not found",body=ProblemDetails)))]
pub(crate) async fn preview_authenticated_agent_tags() -> Response {
    moved()
}

/// Applies an agent tag set only while its membership preview remains current.
#[utoipa::path(put, path="/api/v1/agents/{agent_id}/tags", tag="agents", params(("agent_id"=String,Path)), request_body=crate::ApplyAgentTagsRequest, responses((status=204,description="Tags changed and impact audited"),(status=409,description="Preview is stale",body=crate::AgentTagPreviewResponse),(status=400,description="Invalid tag set",body=ProblemDetails)))]
pub(crate) async fn apply_authenticated_agent_tags() -> Response {
    moved()
}
