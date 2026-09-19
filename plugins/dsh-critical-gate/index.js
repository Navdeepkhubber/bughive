export const name = "critical-gate";

// No inject: we only listen to an event. If the approval seam isn't
// loaded, the listener is inert but doesn't block boot.

export function apply(ctx, config = {}) {
  const cfg = {
    gatedTools: ["submit_report", "create_report", "update_report_severity"],
    ...config,
  };

  // Cordis waterfall event: approval/request.
  // Third argument { prepend: true } puts us ahead of the Web UI answerer.
  // We return an outcome to claim the request, or call next() to delegate.
  ctx.on(
    "approval/request",
    async (req, next) => {
      // Only gate configured tools.
      if (!cfg.gatedTools.includes(req.toolName)) {
        return next();
      }

      // Fail-closed: defer every gated tool to the human answerer.
      // Reading severity requires the session-log API (tool/call event by
      // callId), which we haven't wired yet — so every submission goes to
      // the human. That's strictly safer than the target behavior.
      console.log(
        `[critical-gate] HUMAN APPROVAL REQUIRED: ${req.toolName}` +
        (req.reason ? ` — ${req.reason}` : "")
      );
      return next();
    },
    { prepend: true }
  );

  console.log(
    "[critical-gate] registered on approval/request for:",
    cfg.gatedTools.join(", ")
  );
}
