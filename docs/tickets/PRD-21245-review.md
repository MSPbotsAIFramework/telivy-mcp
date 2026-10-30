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
