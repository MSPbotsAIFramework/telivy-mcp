# PRD-21245 · Code review

## Round 1 · 2026-10-30 · reviewed dev/PRD-21245 @ db90005 (base main @ 8e03cde)

Verdict: changes requested

### Findings

1. [must-fix] `src/telivy_mcp/api_client.py:144-154` — `_raise_for_status` can put the raw upstream response body into the tool-facing error message, which directly violates AC18 ("the `message` never contains the raw upstream response body or any credential"):
   - If the error body isn't valid JSON, `msg = resp.text` (the entire raw body, verbatim).
   - If the error body is a JSON object without a `"message"` or `"error"` key, `msg = str(detail)` (the entire parsed dict, verbatim).

   Neither path is exercised by any test. The only test that targets "does the message leak the raw body" — `tests/test_api_client.py::test_404_maps_to_not_found_and_does_not_leak_raw_body` — uses a body that happens to have a `"message"` key, so both unsafe fallbacks are never triggered and the gap passes unnoticed.

   Confirmed by reproduction (ran against the reviewed commit):
   ```
   # 502 with a non-JSON (HTML) body
   -> envelope: {"error":{"code":"upstream_error","message":"<html><body>Upstream internal trace: req-9f3a-secret-session-xyz, backend 10.0.4.17 timed out</body></html>","retryable":true}}

   # 422 with a JSON body shaped {"detail": [...]} (no "message"/"error" key — a plausible real shape, e.g. FastAPI-style validation errors)
   -> envelope: {"error":{"code":"invalid_argument","message":"{'detail': [{'loc': ['query', 'limit'], 'msg': 'value is not a valid integer', 'internal_trace_id': 'trace-zzz'}]}","retryable":false}}
   ```
   Both cases put the full raw upstream body (which could carry another tenant's data, an internal trace id, or infra details) straight into the message an Agent receives.

   Fix: drop both raw-body fallbacks. Use a fixed, generic message per status class (matching the `code` already computed by `_classify`) when the upstream body doesn't yield a `"message"`/`"error"` string field, and add a test for the non-JSON-body and message-less-JSON-body cases so this doesn't regress silently again.

2. [must-fix] `pyproject.toml:28` (`uv.lock` resolves it too) — `httpx2` is listed in `[dependency-groups] dev` but is never imported anywhere in `src/` or `tests/` (`grep -rn "httpx2" --include=*.py src/ tests/` is empty). It is not declared in the tech design's "Reuse & cleanup — New dependencies" section, which names only the `mcp` SDK and an HTTP client (`httpx`, already present as a main dependency) as the expected additions — `httpx2` is a different, unrelated package, not a typo'd re-list of `httpx`. Per `REVIEW.md` §2 BLOCKER 12 ("加了没写明的依赖"), an undeclared dependency added to a reviewed diff is a must-fix regardless of whether it's wired up. Remove `"httpx2"` from `pyproject.toml` and re-run `uv lock` to drop it (and its transitive deps `httpx2-jsfetch`/`truststore`) from `uv.lock`, unless there's an actual use for it that belongs in the tech design.

Host: dev02

### Fixes · dev/PRD-21245 @ f568c64

1. **`src/telivy_mcp/api_client.py:144-154` (must-fix 1)** — replaced both raw-body fallbacks in `_raise_for_status` with a new `_safe_error_message` helper: a parsed JSON body's `"message"`/`"error"` field is forwarded verbatim only when it is a non-empty string; every other case (body isn't valid JSON, or is a JSON body/object without one of those string fields, e.g. a FastAPI-style `{"detail": [...]}`) now returns one of five fixed, generic messages keyed by the same `code` that `_classify` already computes (`invalid_argument` / `unauthorized` / `not_found` / `rate_limited` / `upstream_error`). Added two regression tests reproducing the reviewer's exact repro cases: `tests/test_api_client.py::test_non_json_body_does_not_leak_raw_body` (502 HTML body) and `tests/test_api_client.py::test_json_body_without_message_or_error_key_does_not_leak_raw_body` (422 `{"detail": [...]}` body with an `internal_trace_id`); both assert the planted secret strings are absent from `to_envelope()`'s output. Extended `docs/tickets/PRD-21245.ac.json`'s `TC-TLV-019` (AC18) `tests`/`evidence` with these two node ids.
2. **`pyproject.toml:28` (must-fix 2)** — removed `"httpx2"` from `[dependency-groups] dev` and ran `uv lock`, which dropped it and its transitives (`httpx2-jsfetch`, `httpcore2`, `truststore`) from `uv.lock`. Confirmed still unused: `grep -rn "httpx2" --include=*.py src/ tests/` and `grep -n "httpx2" uv.lock` are both empty after the change.

**Re-run results (commit `f568c64`, synced with `main` @ `8e03cde` — unchanged, `main` has had no new commits since this branch was cut):**

| Gate | Command | Result |
|---|---|---|
| Unit tests | `uv run pytest -v` | **50 passed**, 0 failed, 0.9s (48 prior + 2 new regression tests for must-fix 1) |
| Chinese-text scan | `grep -rnP '[\x{4e00}-\x{9fff}]' --exclude-dir=.git --exclude-dir=.venv .` | One hit: this file's own Round 1 finding #2 text, which quotes a Chinese bullet from the skill's internal `REVIEW.md` §2 BLOCKER 12 by way of citation. Not code, not a new introduction, and outside this round's must-fix list — re-run excluding this file (`--exclude=PRD-21245-review.md`) is clean. Left as-is per "only change the listed must-fix, main doc untouched above this Fixes section." |
| README Connector section | `diff <(sed -n '8,78p' README.md) .../readme-connector-section.md` | Exact match (unchanged by this round) |
| Secret scan | `gitleaks` not installed; manual pattern grep (`AKIA...`, `sk-...`, `gAAAAA...`) over the tree | No matches |
| `httpx2` removed | `grep -rn "httpx2" --include=*.py src/ tests/` and `grep -n "httpx2" uv.lock` | Both empty |
| Live smoke test (placeholder credential, no real Telivy account) | started `uv run python -m telivy_mcp` on port 8080 | `GET /health` → `200`; `POST /mcp initialize` (no header) → `401` with the required-headers body; `initialize` with `X-Telivy-Api-Key: placeholder-key` → `200`, `serverInfo.name: "telivy-mcp"`; `tools/list` → `200`, 13 tools, same catalog as round 1; `tools/call telivy_list_external_scans` reached the real Telivy API and got back a real `401`, mapped to `{"error":{"code":"unauthorized","message":"Invalid API Key","retryable":false}}` — consistent with the fix (Telivy's own body here does carry a clean string `"message"` field, so it is forwarded verbatim, as intended) |

No other must-fix items were listed in round 1; no other files were touched.
