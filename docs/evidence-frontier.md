# Evidence frontier

`decide` refreshes `hunts/<domain>/evidence-frontier.json` from existing recon summaries, local JavaScript, source audit hits, and proxy captures. This preprocessing sends no requests and leaves JEV in control of the next executor.

The frontier groups URL variants by host, normalized route, method, and parameter names. It keeps source file pointers, ranks test surfaces, and records changes to observed routes, status codes, and technologies. `inventory-state.json` preserves the previous observation so repeated `decide` calls do not reset a change alert. An initial inventory has no change alert.

Captured GET/HEAD requests create replay **plans** for owner, second test identity, and anonymous comparisons. Plans require owned identities and an owner baseline. No credentials are copied into the frontier and no replay runs automatically. POST and other state changing requests are excluded. JavaScript parameter names are only candidates; the owning route and baseline must be established before a bounded probe. Source audit hits become route candidates only when the source message names a route seen in recon.

The JEV prompt gets the top 18 routes and an 8 KB recon slice. The hypothesis prompt gets a compact top 24 frontier plus up to 36 KB of prioritized recon summaries. Tool hits stay in the recon slice and still require falsification. A frontier rank is search priority, never vulnerability proof. Browser XSS, auth, redirect, timing, boolean, and OOB findings still need the existing class specific validators and report audit.

The fixture evaluation scores the existing scanner, so it detects regressions in that scanner but cannot measure whether the frontier improves live target yield. Track live outcomes separately: validated findings per request, per hour, and per model token, with false positive rate after falsification.
