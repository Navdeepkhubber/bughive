## Dependencies
Runs after: 04, 05, 06, 07

# Recon Phase: 11-flow-mapping

## Workspace
Write all output to the absolute path passed in the prompt
(`~/.dsh/hunts/<domain>/recon/11-flow-mapping/`). Use absolute paths in your
`output_files` array. Do not write anywhere else.

## Input
Candidate entry URLs are pulled from phase 04 (http-probe) and phase 05
(content-discovery) summaries — this phase does not crawl blind. If a
`scope.txt` exists in your working directory, read it first — treat every
hostname not listed there as out-of-scope. If `scope.txt` is missing, the
runner fails closed and executes nothing.

## Why this phase exists
Phases 01-10 are all static, per-endpoint recon: they tell you a URL
exists, what a response header says, what a JS file references. None of
them can see a *sequence* — whether step 3 of checkout is reachable
without steps 1-2, whether a password-reset token is guessable, whether
2FA can be skipped by hitting a URL directly. Those are exactly the bugs
`business-logic.md`, `account-takeover.md`, `2fa-bypass.md`, and
`csrf-token-bypass.md` are built to catch, and until this phase existed
nothing in recon actually fed them evidence.

## Tools
Preference order, see `recon/tools.yml` `flow_mapping`:
1. **Playwright** (headless Chromium) — `recon/scripts/flow-runner.mjs`.
   Self-hosted, MIT-licensed, deterministic, records full HAR natively.
   Preferred over cloud browser-agent SaaS (Browserbase, Firecrawl,
   Skyvern, etc.) on purpose: this tool executes real actions against a
   client's or program's live target under an authorized scope, and
   routing that traffic through an undisclosed third party's
   infrastructure is a real scope/NDA problem in bug bounty work, not
   just a preference.
2. **katana** (`-aff -jc -hl`, already in tools.yml under `history`) —
   fallback if Playwright/Node deps are unavailable. Discovery-only: it
   can find candidate multi-step form pages but cannot execute a real
   stateful sequence (email verification, cart state). Note this
   limitation explicitly in the summary if used.
3. **zap-baseline** — optional third tier, only if the operator already
   has a ZAP daemon reachable. Not required for a normal run.

## Timeout contract
- Playwright browser launch: 15s
- Per-flow execution (navigate + fill + observe): 45s, hard-killed via
  `Promise.race` in the runner if exceeded
- Whole phase: no more than (45s × number of flow templates) + 30s buffer

## Non-negotiable safety rules
These are enforced in `recon/scripts/flow-runner.mjs` itself, not
something a prompt can override:
1. **Never navigates outside `scope.txt`.** No scope file = nothing runs.
2. **Never fills or submits a payment-instrument field** (card number,
   CVV/CVC, expiry, IBAN, routing/account number) under any flag. If a
   checkout flow reaches a payment field, the runner stops there and
   records `payment_step_reached_without_submitting`.
3. **Other side-effecting steps** (account creation, password-reset
   email, invite email) only execute for real if the caller passes
   `--allow-side-effects` **and** the flow id is listed in
   `hunts/<domain>/flow-side-effects.allow`. Otherwise the runner fills
   the form, records what it *would* have done, and stops before the
   final submit (dry run). Default behavior with no allowlist file is
   dry-run for every flow.
4. **Synthetic data only.** Emails use `--synthetic-domain` (an
   operator-controlled catch-all), never a guessed real third party's
   address. Login is only attempted with an operator-supplied test
   account (via scope config); it never guesses or brute-forces
   credentials.
5. **No sensitive values in output.** Field names are logged (e.g.
   `password`) so a human can see what was touched; field values for
   password/token/card-shaped inputs are never written to the summary or
   left unredacted in the HAR.

## Steps
1. Read `recon/flow-templates/*.yml` — each defines one flow (registration,
   login, password-reset, checkout, invite-referral) as entry-URL hints,
   an ordered step list, and an `observe` checklist.
2. For each template, pull candidate entry URLs from phase 04/05 summaries
   matching `entry_hints.path_patterns`.
3. Launch headless Chromium, record HAR per flow, execute steps per the
   safety rules above.
4. Write one summary.json per this phase's output contract, plus one
   `<flow-id>.har` per attempted flow.
5. Return ONLY the JSON summary. No prose.

## Output contract
```json
{
  "phase": "11-flow-mapping",
  "domain": "<root domain>",
  "tools_run": ["playwright"],
  "tools_skipped": [{ "tool": "...", "reason": "..." }],
  "count": <int, flows actually attempted>,
  "items": [
    {
      "flow": "registration",
      "attempted": true,
      "entry_url": "https://...",
      "stopped_early": "<reason, or null>",
      "observations": { "...": true },
      "step_count": <int>,
      "har": "<absolute path>"
    }
  ],
  "notes": [...],
  "output_files": ["<absolute paths to summary.json and *.har>"]
}
```

## Feeding downstream stages
This phase's `items[].observations` are exactly the kind of literal,
matchable evidence `skill-select.sh`'s keyword scoring needs for
`business-logic`, `account-takeover`, `2fa-bypass`, and
`csrf-token-bypass` — terms like `invite_acceptable_by_different_email`
or `2fa_step_skippable_via_direct_url` will now actually appear in the
recon corpus those skills get scored against, instead of relying purely
on the hardcoded `ALWAYS_INCLUDE` fallback in `skill-select.sh`. Once this
phase has run against a real target a few times, it's worth revisiting
whether `business-logic`/`account-takeover` still need to be force-included
or can compete on score like everything else.
