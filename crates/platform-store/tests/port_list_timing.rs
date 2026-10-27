//! The Ports list on the step 5e ruling 26 fleet: 10,000 hosts with 20
//! listeners each (200,000 rows, about 300 distinct ports, 10 % exposed),
//! 500,000 change-log rows, 15 groups. Ignored by default; run it with
//! `cargo test --release -p platform-store --test port_list_timing -- --ignored --nocapture`.
//! Timings are recorded in docs/components/platform-store.md.

mod common;
use common::timing;

use std::time::Duration;

use chrono::Utc;
use platform_store::{
    Client,
    console_read::AgentScope,
    port_list::{Changes, PortQuery, PortSort, port_list},
};

async fn fleet(c: &Client) -> String {
    timing::hosts(c).await;
    c.batch_execute(
        "         -- Host n listens on 20 ports out of about 300; tcp 22, 80, 443 and 5432 are common.
         INSERT INTO host_listeners (agent_id, protocol, address, port, exposed, service, program)
         SELECT g.agent_id, 'tcp', CASE WHEN x.exposed THEN '0.0.0.0'::inet ELSE '127.0.0.1'::inet END,
                x.port, x.exposed, 'unit' || (x.port % 40) || '.service', NULL
         FROM gen g CROSS JOIN LATERAL (
           SELECT DISTINCT ON (port) port, abs(hashtext(g.n || ':' || j)) % 10 = 0 AS exposed
           FROM (SELECT j, CASE WHEN j < 4 THEN (ARRAY[22, 80, 443, 5432])[j + 1]
                                ELSE 1000 + (g.n * 7 + j * 13) % 300 END AS port
                 FROM generate_series(0, 19) j) q ORDER BY port, j) x;
         INSERT INTO change_log (at, agent_id, kind, key, change)
         SELECT now() - (random() * (CASE WHEN n % 20 = 0 THEN 7 ELSE 85 END) * interval '1 day'),
                g.agent_id, 'listener', 'tcp/' || (1000 + (g.n * 7 + j * 13) % 300),
                CASE WHEN j % 4 = 0 THEN 'went_away' ELSE 'appeared' END
         FROM gen g CROSS JOIN generate_series(1, 50) j;",
    )
    .await
    .unwrap();
    timing::groups(c).await
}

#[tokio::test]
#[ignore = "timing run; see the module doc"]
async fn the_list_answers_within_two_seconds() {
    let (db, c) = common::migrated().await;
    let group = fleet(&c).await;
    let base = PortQuery {
        q: None,
        exposure: None,
        protocol: None,
        group: None,
        service: None,
        changes: None,
        host: None,
        sort: PortSort::Port,
        descending: false,
        offset: 0,
        limit: 50,
    };
    let global = AgentScope::Global;
    let scoped = AgentScope::AssetGroups(vec![group.clone()]);
    for (label, q, scope) in [
        ("full reach, unfiltered", &base, &global),
        (
            "full reach, needs a look, by hosts",
            &PortQuery {
                changes: Some(Changes::Look),
                sort: PortSort::Hosts,
                descending: true,
                ..base.clone()
            },
            &global,
        ),
        (
            "full reach, search",
            &PortQuery {
                q: Some("unit7"),
                ..base.clone()
            },
            &global,
        ),
        (
            "full reach, one group",
            &PortQuery {
                group: Some(&group),
                ..base.clone()
            },
            &global,
        ),
        ("one group's reach (about 500 hosts)", &base, &scoped),
    ] {
        let (time, total) =
            timing::median(async || port_list(&c, q, scope, Utc::now()).await.unwrap().total).await;
        println!("{label}: {time:?} ({total} ports)");
        assert!(time < Duration::from_secs(2), "{label}: {time:?}");
    }
    db.drop().await;
}
