//! The People tests' fixture: Alice (Administrator), the `win` host group,
//! the "Win viewers" role, and the Windows lead.

use axum::http::StatusCode;
use openvibes_console::authenticated_router;
use platform_store::console_roles::Reach;
use serde_json::Value;

use super::http::{Session, TestDb, call, sign_in};

pub const WIN: &str = "31111111-1111-4111-8111-111111111111";

pub fn uid(index: u8) -> String {
    format!("11111111-1111-4111-8111-1111111111{index:02}")
}

pub struct Fx {
    pub db: TestDb,
    pub router: axum::Router,
    pub admin: Session,
    /// Holds `hosts.read` on the `win` group.
    pub win_viewers: String,
}

impl Fx {
    pub async fn new() -> Option<Self> {
        let db = TestDb::create("people").await?;
        db.user("alice", "admin", 1).await;
        db.pool
            .get()
            .await
            .unwrap()
            .batch_execute(&format!(
                "INSERT INTO console_asset_groups (asset_group_id, name, created_at, created_by)
                 VALUES ('{WIN}', 'win', now(), 'test')"
            ))
            .await
            .unwrap();
        let router = authenticated_router(db.pool.clone(), super::http::ORIGIN);
        let admin = sign_in(&router, "alice").await;
        let mut fx = Self {
            db,
            router,
            admin,
            win_viewers: String::new(),
        };
        fx.win_viewers = fx
            .role(
                "Win viewers",
                &["hosts.read"],
                Reach::Groups(vec![WIN.into()]),
            )
            .await;
        Some(fx)
    }

    pub async fn call(
        &self,
        who: &Session,
        method: &str,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        call(&self.router, method, uri, who, body).await
    }

    pub async fn role(&self, name: &str, permissions: &[&str], reach: Reach) -> String {
        let mut client = self.db.pool.get().await.unwrap();
        super::create_role(&mut client, name, permissions, reach).await
    }

    /// The Windows lead: may read, add and grant people, on `win` only.
    pub async fn windows_lead(&self) -> Session {
        let perms = ["access.read", "access.users", "access.grant", "hosts.read"];
        let id = self
            .role("Windows lead", &perms, Reach::Groups(vec![WIN.into()]))
            .await;
        self.db.user("wl", &id, 2).await;
        sign_in(&self.router, "wl").await
    }
}
