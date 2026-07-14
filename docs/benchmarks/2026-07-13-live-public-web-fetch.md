# Live public web-fetch observation (development checkout)

Date: 2026-07-13 (Pacific/Auckland)

The opt-in `web_live` integration test passed against `https://example.com/` using the production
`WebReadTool`, not a mock transport. The activated authority contained only the `example.com`
domain and no credential. The adapter used direct no-proxy HTTPS with DNS address pinning and
post-connect peer verification, denied redirects by construction, enforced a 32-KiB call bound and
the normal two-second connect/eight-second total timeouts, accepted the exact HTML media type,
converted active HTML to bounded text, and returned the exact URL citation plus raw-byte SHA-256.

Reproduction:

```sh
cargo test -p mealy-infrastructure --all-features --test web_live -- --ignored --nocapture
```

This is dirty-development, x86_64 local evidence and depends on public DNS/network/site
availability. It is not deterministic CI evidence and does not exercise Brave Search, which still
requires an owner-supplied subscription credential.
