# Hand-back: semantic cache (`prompt_embeddings`) has no eviction

**From:** Andrei (edge-infra / data-tier + ISO 27001 hardening)
**To:** Nicolai (owner of `internal/cache` + `internal/quality`)
**Repo:** talyvor-lens · **Status:** read-only audit, nothing touched — handing back because cache eviction policy + the quality-score contract are your design domain.

I did **not** edit any code or migrations. This is a flag, not a PR. If you pick a direction I'm happy to implement it as a PR against talyvor-lens.

---

## TL;DR

The semantic cache table `prompt_embeddings` **grows without bound** — nothing ever deletes a row on a live code path. Two related things make this worse:

1. The configured cache TTL (`MaxCacheTTL`) is **silently ignored** by the semantic cache; the read window is hardcoded to 24h.
2. The quality-based eviction machinery (`QualityScore.ShouldEvict` + `Scorer.EvictLowQuality`) was built, typed, and unit-tested, but is **never wired to a caller** — so low-quality responses the system already flags as evict-worthy stay cached and keep getting served.

Net effect: unbounded Postgres growth, ivfflat index bloat (which degrades the very vector search the cache relies on), and the cache serving answers it has already judged bad.

---

## Finding 1 — `prompt_embeddings` grows unbounded

- The only writer is `SemanticCache.Set` — an `INSERT ... ON CONFLICT (prompt_hash) DO UPDATE` (`internal/cache/semantic.go:59-65`, `:99-109`). Every new unique `(provider, model, prompt)` mints a row that lives forever.
- `SemanticCache.Get` filters reads to `updated_at > NOW() - INTERVAL '24 hours'` (`internal/cache/semantic.go:51`). Rows older than that become **invisible to reads but are never deleted** — they just accumulate as dead weight.
- The **only** `DELETE FROM prompt_embeddings` in the entire repo is `evictSQL` (`internal/quality/scorer.go:189`), reachable solely through `EvictLowQuality` — which has zero callers (see Finding 3).
- Each row carries a `vector(1536)` (~6 KB raw for the embedding) plus the full response text. Schema: `migrations/0001_init.sql:3-22`. The ivfflat index (`idx_embeddings_vector`, `lists = 100`) is sized for a bounded set; unbounded growth degrades recall and latency over time.

**Conclusion:** there is no live path that removes a row. The table is append-only in practice.

## Finding 2 — configured TTL is dead; 24h is hardcoded

- `SemanticCache.ttl` (`internal/cache/semantic.go:37`) is set in the constructor (`:45`) from `cfg.MaxCacheTTL` (`cmd/lens/main.go:256`) but is **never read anywhere**.
- The read window is the literal `INTERVAL '24 hours'` in `semanticSelectSQL` (`internal/cache/semantic.go:51`).
- `MaxCacheTTL` is a real operator-facing knob: `internal/config/config.go:22`, default `24 * time.Hour` (`:317`), overridable from config (`:546`). The **same** knob is honored by the exact cache (`internal/cache/exact.go:51`) and distill cache (`internal/cache/distill.go:70`) via Redis TTL.
- So an operator who sets `MaxCacheTTL = 1h` gets 1h on the Redis caches but the semantic cache still serves 24h-old entries — inconsistent and surprising.

**Why it's easy to miss:** the hardcoded `24 hours` coincidentally equals the default, so the bug is invisible at default config and only shows up when the knob is changed. Note that even if the field were honored, it would only change the *read* window — it still wouldn't delete anything (that's Finding 1). The two need separate fixes.

## Finding 3 — the entire quality-eviction path is unwired (dead code)

- `Scorer.EvictLowQuality` (`internal/quality/scorer.go:207`) runs `DELETE FROM prompt_embeddings WHERE prompt_hash = $1`. **Zero callers** anywhere in the repo — only the definition.
- `QualityScore.ShouldEvict` (`internal/quality/scorer.go:18`, computed at `:142` as `score < evictThreshold` where `evictThreshold = 0.4`) is read **only in `scorer_test.go`**. No production caller branches on it.
- For contrast, `ScoreResponse` *is* live — called at four production sites (`internal/proxy/proxy.go:963`, `internal/proxy/stream.go:382`, `internal/ab/tester.go:280`, `internal/eval/pipeline.go:237`). They all consume `.Score` / `.ShouldCache` and **none** look at `.ShouldEvict`.
- The newer `internal/quality/composite.go` scorer adds no eviction either (no evict/delete/ttl/expire/prune references).

**Conclusion:** the scoring *half* is wired (it decides what to cache); the eviction *half* (decide what to drop + actually drop it) was implemented and tested but never connected. A classic half-wired feature.

---

## Why it matters

- **Storage / cost:** unbounded Postgres growth, indefinitely.
- **Cache quality:** responses `ScoreResponse` already flags `ShouldEvict` (refusals, truncated, repetitive) remain cached and keep being served as semantic hits — the cache actively serves answers the system judged bad.
- **Performance:** ivfflat recall/latency degrade as dead rows pile up.
- **Ops surprise:** `MaxCacheTTL` doesn't do what its name implies for the semantic cache.

## Options (your call — I'm flagging, not prescribing a policy)

1. **Time-based sweep.** Periodic `DELETE FROM prompt_embeddings WHERE updated_at < NOW() - $ttl`, driven by `c.ttl` (also wires the dead field). Caveat: there is **no index on `updated_at`/`created_at`** today (only the ivfflat vector index + the `uq_prompt_hash` unique constraint), so a sweep is a seq scan — add an index or run it in a low-traffic window. Decide whether the read-window interval should also switch from hardcoded 24h to `c.ttl` for consistency.
2. **Quality-based eviction.** Wire `ShouldEvict → EvictLowQuality` at the existing score sites (`proxy.go:963` / `stream.go:382`), and/or trigger on negative/repeat feedback in `RecordFeedback` (`cmd/lens/main.go:3392`), where `hit_count` already goes negative. The primitives exist; only the call is missing.
3. **Capacity / LRU bound.** Cap row count, evict coldest by `hit_count` / `updated_at`.
4. **Combination**, plus a decision on whether `MaxCacheTTL` should drive the read window, deletion, or both — and whether exact/distill/semantic should behave consistently.

Whatever you pick, keep the read-side filter and any deletion interval consistent so the cache doesn't serve rows a sweep is about to delete (or keep rows it's already hiding).

## Scope / boundary

Read-only. No edits to talyvor-lens code or migrations — eviction policy and the `ShouldEvict` / TTL semantics are yours to define. Ping me if you want me to implement a chosen option as a PR.

---

### Quick file:line index

| Item | Location |
|---|---|
| Semantic cache (Get/Set, dead `ttl`, hardcoded 24h) | `internal/cache/semantic.go:37,45,51,99` |
| Quality scorer (`ShouldEvict`, `EvictLowQuality`, `evictSQL`) | `internal/quality/scorer.go:18,142,189,207` |
| Table schema (no time index) | `migrations/0001_init.sql:3-22` |
| TTL knob (passed in, honored by Redis caches only) | `internal/config/config.go:22,317,546`; `cmd/lens/main.go:254,256,363` |
| Live `ScoreResponse` callers (none use `ShouldEvict`) | `internal/proxy/proxy.go:963`, `internal/proxy/stream.go:382`, `internal/ab/tester.go:280`, `internal/eval/pipeline.go:237` |
| Feedback path (natural eviction hook) | `cmd/lens/main.go:3392`; `internal/quality/scorer.go:191` |
