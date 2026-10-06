# Live agent status

Decision (2026-10-06): the console should show a host online or offline
within about a minute and push changes, not show the last saved heartbeat.

- Agents already heartbeat about every minute. Ingest saved that to
  `agents.last_seen_at` only every 5 minutes (the column is indexed, so each
  write churns the index), and the console called a host offline after 15.
- Ingest now also upserts an UNLOGGED `agent_presence` row on every
  heartbeat. Reads use `agent_seen_at(agent_id, saved)`, the later of the
  two. Offline is 3 minutes (three missed heartbeats).
- The console pushes changes over a server-sent event stream
  (`GET /api/v1/agents/events`). It says only that the online set changed;
  the browser refetches its own scoped views.
- Trade-offs: one extra small write per heartbeat (about 170/s at 10,000
  agents, unlogged, no index churn); agent list ordering by last seen no
  longer uses the `agents` index, which is fine at fleet sizes of thousands.
  A host that stops without a heartbeat shows offline after 3 minutes, not
  instantly: the server cannot know sooner with request-per-heartbeat agents.
- The health report's freshness limit stays 15 minutes
  (`HEALTH_REPORT_FRESH_MINUTES`) because the report is still saved on the
  throttled write.
