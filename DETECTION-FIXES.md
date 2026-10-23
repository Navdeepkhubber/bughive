# Detection pipeline fixes

The saved Threema and Abacus hunts reached live web surfaces but produced zero
hypotheses. Their decision trails repeatedly stopped at `human_gate`, or turned
a `hold` test-method suggestion into `stop` after recon was complete. These
changes let recon and evidence-bound hypothesis generation proceed. A hunt
gets one hypothesis attempt after recon and skill scoring, even if JEV's
method suggestion is `hold`; an empty attempt does not loop indefinitely.

The hypothesis prompt now checks the full selected skill shortlist, with
JEV's choice first. Skill filenames containing spaces are loaded correctly.
The prefilter uses the same wildcard and exclusion-aware scope matcher as
the scope guard, and can suggest a baseline request from a concrete target
URL. An empty individual recon phase no longer discards a candidate found
in another phase.

The previous accuracy fixes remain: a generic HTTP response difference is
only a lead, report claims are checked against recorded requests, and fixture
scoring matches class, method and route boundaries.

Run `npm run test:accuracy` and `node scripts/pipeline/jev-decide.mjs --selftest`.
The full plugin suite is `node plugins/_selftest.mjs` and binds a local fixture
server. Detection still depends on reachable in-scope surfaces, useful recon,
and class-specific proof. These changes improve candidate throughput; they do
not imply that any saved hunt contains a confirmed vulnerability.
