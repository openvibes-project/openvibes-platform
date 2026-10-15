//! HTTP plumbing shared by every area: router assembly and the route
//! table, middleware, the web app's files, problem and error types, and the
//! OpenAPI document.

#[cfg(feature = "embedded-ui")]
mod assets;
pub(crate) mod error;
mod frontend;
#[cfg(feature = "embedded-ui")]
mod frontend_contract;
pub(crate) mod middleware;
pub(crate) mod openapi;
pub(crate) mod problem;
mod router;
mod routes;

pub(crate) use router::{AuthHttpState, authenticated_router_with_assistant};
pub use router::{
    Readiness, authenticated_router, authenticated_router_for_hosts,
    authenticated_router_with_agent_install, authenticated_router_with_fetch,
    authenticated_router_with_signer, development_router, health_router, public_router,
};
