//! A fresh, uniquely named database per test, dropped afterwards.

use std::hash::{BuildHasher, Hasher};

use deadpool_postgres::Pool;

pub struct TestDb {
    pub pool: Pool,
    admin_url: String,
    name: String,
}

fn base_url() -> String {
    std::env::var("OPENVIBES_TEST_DATABASE_URL")
        .expect("set OPENVIBES_TEST_DATABASE_URL, see scripts/test-db.sh")
}

/// `url` with its database name replaced by `name`.
fn with_database(url: &str, name: &str) -> String {
    let (head, query) = url
        .split_once('?')
        .map_or((url, None), |(h, q)| (h, Some(q)));
    let head = &head[..head.rfind('/').expect("database URL has a path")];
    match query {
        Some(query) => format!("{head}/{name}?{query}"),
        None => format!("{head}/{name}"),
    }
}

impl TestDb {
    pub async fn create() -> Self {
        let admin_url = base_url();
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u64(std::process::id().into());
        let name = format!("ov_test_{:016x}", hasher.finish());
        let admin = platform_store::connect(&admin_url).await.unwrap();
        let client = admin.get().await.unwrap();
        client
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .await
            .unwrap();
        let pool = platform_store::connect(&with_database(&admin_url, &name))
            .await
            .unwrap();
        Self {
            pool,
            admin_url,
            name,
        }
    }

    pub async fn drop(self) {
        self.pool.close();
        let admin = platform_store::connect(&self.admin_url).await.unwrap();
        let client = admin.get().await.unwrap();
        client
            .batch_execute(&format!("DROP DATABASE {} WITH (FORCE)", self.name))
            .await
            .unwrap();
    }
}
