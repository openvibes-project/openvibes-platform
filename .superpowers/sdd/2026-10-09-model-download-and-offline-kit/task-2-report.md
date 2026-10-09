# Task 2 report (phase A)
Commit bda32ce: `model fetch` in src/model_fetch.rs (Pin, read_pin, Downloader, Curl, fetch, free_bytes), CLI in model.rs, audit name in assistant.rs, admin docs row. Unit tests written; not yet run (phase B).
Doubts: free space via `stat -f` (crate forbids unsafe, so no statvfs); "exists" = no-op even if model.conf does not select it; curl Requires already present in spec.

## Fix round 1 (all five items done)
Download is hashed in place and renamed onto the pinned name (no second copy; 2.7 GB check kept); Temp drop guard; wrong-content file at the pinned name is replaced after a verified download, matching-but-unselected is selected with no download; --proto-redir =https; tests for http pin, missing dir, foreign file, bad config (no temp file); spec messages reworded with no command; docs mark fetch as internal. Full test/clippy/doc/fmt green.
