/**
 * Parse an authored `## Steps to reproduce` block.
 *
 * Only text the skill wrote is kept. A request, payload, host, or assertion
 * that is not literally in the block is never filled in. Doc-only enrich-repro
 * sections stay non-runnable: prose is not turned into an HTTP call.
 */

export const REPRO_STATES = Object.freeze([
  "verified-public",
  "partial",
  "unverified",
  "checklist",
  "technique-authored",
]);

const METHODS = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)$/i;

export function isReproState(value) {
  return REPRO_STATES.includes(String(value ?? "").trim());
}

export function assertReproState(value) {
  const state = String(value ?? "").trim();
  if (!isReproState(state)) throw new Error(`invalid repro state: ${state}`);
  return state;
}

function sectionKind(title) {
  const name = String(title || "").trim().toLowerCase().replace(/\s+/g, " ");
  if (name === "prerequisites" || name === "preconditions") return "preconditions";
  if (name === "steps" || name === "request" || name === "requests") return "requests";
  if (name === "input / trigger" || name === "input/trigger") return "trigger";
  if (name === "success" || name === "success condition" || name === "how to confirm") return "success";
  if (name === "false-positive guard" || name === "false positive guard") return "guard";
  if (name === "what's missing" || name === "whats missing") return "gaps";
  return "other";
}

function unquote(value) {
  const trimmed = String(value ?? "").trim();
  if (trimmed.length >= 2) {
    const quote = trimmed[0];
    if ((quote === '"' || quote === "'") && trimmed.endsWith(quote)) return trimmed.slice(1, -1);
  }
  return trimmed;
}

function bulletText(lines) {
  const out = [];
  for (const line of lines) {
    const match = String(line).match(/^\s*(?:[-*]|\d+\.)\s+(.*)$/);
    if (match && match[1].trim()) out.push(match[1].trim());
  }
  return out;
}

function matcherFor(kind, value, headerName, negative) {
  if (kind === "status") return { type: "status", value, negative };
  if (kind === "body_contains" || kind === "body_not_contains") return { type: "word", words: [value], negative };
  if (kind === "regex") return { type: "regex", regex: value, negative };
  if (kind === "header_equals") return { type: "header", name: headerName, equals: value, negative };
  if (kind === "header_contains") return { type: "header", name: headerName, contains: value, negative };
  return null;
}

function parseCheckLine(line) {
  const stepMatch = line.match(/^step\s+(\d+)\s+(.+)$/i);
  const step = stepMatch ? Number(stepMatch[1]) : null;
  const rest = (stepMatch ? stepMatch[2] : line).trim();
  if (!rest) return "skip";

  const statusNot = rest.match(/^status(?:\s+is\s+not|\s*!=|_not:)\s*(\d{3})$/i);
  const status = rest.match(/^status(?:\s+equals|\s*==|:)\s*(\d{3})$/i);
  const bodyNot = rest.match(/^body(?:\s+does\s+not\s+contain|_not_contains)\s*:?\s*(.+)$/i);
  const body = rest.match(/^body(?:\s+contains|_contains)\s*:?\s*(.+)$/i);
  const headerEq = rest.match(/^header\s+([A-Za-z0-9-]+)\s+equals\s+(.+)$/i);
  const headerHas = rest.match(/^header\s+([A-Za-z0-9-]+)\s+contains\s+(.+)$/i);
  const regex = rest.match(/^regex:\s*(.+)$/i);

  let kind;
  let value;
  let headerName = null;
  let negative = false;
  if (statusNot) {
    kind = "status";
    value = Number(statusNot[1]);
    negative = true;
  } else if (status) {
    kind = "status";
    value = Number(status[1]);
  } else if (bodyNot) {
    kind = "body_not_contains";
    value = unquote(bodyNot[1]);
    negative = true;
  } else if (body) {
    kind = "body_contains";
    value = unquote(body[1]);
  } else if (headerEq) {
    kind = "header_equals";
    headerName = headerEq[1];
    value = unquote(headerEq[2]);
  } else if (headerHas) {
    kind = "header_contains";
    headerName = headerHas[1];
    value = unquote(headerHas[2]);
  } else if (regex) {
    const pattern = unquote(regex[1]);
    try {
      new RegExp(pattern);
    } catch {
      return null;
    }
    kind = "regex";
    value = pattern;
  } else {
    return null;
  }
  if (value === "" || value == null) return null;
  const matcher = matcherFor(kind, value, headerName, negative);
  if (!matcher) return null;
  return { kind, value, negative, step, header: headerName, raw: line, matcher };
}

function parseChecks(lines) {
  const checks = [];
  let unusable = false;
  for (const line of bulletText(lines)) {
    const parsed = parseCheckLine(line);
    if (parsed === "skip") continue;
    if (!parsed) unusable = true;
    else checks.push(parsed);
  }
  return { lines: bulletText(lines), checks, unusable };
}

function nextStep(requests, explicit) {
  if (Number.isInteger(explicit)) return explicit;
  const nums = requests.map((req) => req.step).filter((n) => Number.isInteger(n));
  return (nums.length ? Math.max(...nums) : 0) + 1;
}

function parseHttpFence(text) {
  const lines = String(text || "").replace(/\r\n/g, "\n").split("\n");
  while (lines.length && lines[0].trim() === "") lines.shift();
  if (!lines.length) return null;
  const first = lines[0].trim();
  const match = first.match(/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)(?:\s+HTTP\/\d+(?:\.\d+)?)?$/i);
  if (!match) return null;
  const headers = {};
  let index = 1;
  for (; index < lines.length; index += 1) {
    if (lines[index].trim() === "") {
      index += 1;
      break;
    }
    const header = lines[index].match(/^([A-Za-z0-9-]+):\s*(.*)$/);
    if (!header) return null;
    headers[header[1]] = header[2];
  }
  const bodyLines = lines.slice(index);
  const hasBody = bodyLines.some((line) => line.length > 0);
  const request = {
    method: match[1].toUpperCase(),
    path: match[2],
    headers,
    raw: first,
    incomplete: false,
  };
  if (hasBody) request.body = bodyLines.join("\n").replace(/\n$/, "");
  return request;
}

function parseRequestLine(text) {
  const match = String(text || "").trim().match(METHODS);
  if (!match) return null;
  return {
    method: match[1].toUpperCase(),
    path: match[2],
    headers: {},
    raw: String(text).trim(),
    incomplete: false,
  };
}

function parseRequestLines(text, requests, notes, onProse) {
  let current = null;
  const flush = () => {
    if (!current) return;
    requests.push(current);
    current = null;
  };
  for (const line of String(text || "").split("\n")) {
    const trimmedEnd = line.replace(/\s+$/, "");
    if (!trimmedEnd.trim()) continue;
    const stepMatch = trimmedEnd.match(/^(?:(\d+)\.|[-*])\s+(.*)$/);
    if (stepMatch && !/^\s/.test(line)) {
      flush();
      const body = stepMatch[2].trim();
      const request = parseRequestLine(body);
      if (request) {
        current = { ...request, step: nextStep(requests, stepMatch[1] ? Number(stepMatch[1]) : null) };
      } else if (body) {
        notes.push(body);
        onProse();
      }
      continue;
    }
    if (/^\s+\S/.test(line)) {
      const cont = trimmedEnd.trim();
      const bodyMatch = cont.match(/^body:\s*(.*)$/i);
      const headerMatch = cont.match(/^header\s+([A-Za-z0-9-]+):\s*(.*)$/i);
      if (current && bodyMatch) {
        if (current.body !== undefined) current.incomplete = true;
        else current.body = bodyMatch[1];
      } else if (current && headerMatch) {
        current.headers[headerMatch[1]] = headerMatch[2];
      } else if (cont) {
        notes.push(cont);
        onProse();
      }
      continue;
    }
    flush();
    notes.push(trimmedEnd.trim());
    onProse();
  }
  flush();
}

function parseRequestRegion(text, proseIsStep) {
  const requests = [];
  const notes = [];
  let nonRequestStep = false;
  const onProse = () => {
    if (proseIsStep) nonRequestStep = true;
  };
  const fence = /```[ \t]*http[^\n]*\n([\s\S]*?)```/gi;
  const chunks = [];
  let last = 0;
  let match;
  while ((match = fence.exec(text))) {
    chunks.push({ kind: "text", text: text.slice(last, match.index) });
    chunks.push({ kind: "http", text: match[1] });
    last = match.index + match[0].length;
  }
  chunks.push({ kind: "text", text: text.slice(last) });
  for (const chunk of chunks) {
    if (chunk.kind === "http") {
      const request = parseHttpFence(chunk.text);
      if (request) requests.push({ ...request, step: nextStep(requests) });
      else onProse();
      continue;
    }
    parseRequestLines(chunk.text, requests, notes, onProse);
  }
  return { requests, notes, nonRequestStep };
}

function splitSections(lines) {
  const sections = [];
  let current = { kind: "preamble", title: "", lines: [] };
  for (const line of lines) {
    const heading = line.match(/^###\s+(.+?)\s*$/);
    if (heading) {
      sections.push(current);
      current = { kind: sectionKind(heading[1]), title: heading[1].trim(), lines: [] };
      continue;
    }
    current.lines.push(line);
  }
  sections.push(current);
  return sections;
}

function blockReason({ hasGap, nonRequestStep, requests, success, guard }) {
  if (hasGap) return "authored gap in What's missing";
  if (nonRequestStep) return "a step is not an HTTP request";
  if (requests.length === 0 || requests.some((req) => !req.method || !req.path)) return "no authored HTTP request";
  if (requests.some((req) => req.incomplete)) return "authored request is incomplete";
  if (success.checks.length === 0 || success.unusable) return "success condition is not machine-checkable";
  if (guard.present && (guard.checks.length === 0 || guard.unusable)) return "false-positive guard is not machine-checkable";
  return null;
}

function parseBlock(title, lines) {
  const sections = splitSections(lines);
  const preconditions = [];
  let requests = [];
  let notes = [];
  let nonRequestStep = false;
  let success = { present: false, lines: [], checks: [], unusable: false };
  let guard = { present: false, lines: [], checks: [], unusable: false };
  const gaps = [];
  let hasGap = false;
  for (const section of sections) {
    if (section.kind === "preconditions") preconditions.push(...bulletText(section.lines));
    if (section.kind === "requests" || section.kind === "trigger") {
      const parsed = parseRequestRegion(section.lines.join("\n"), section.kind === "requests");
      requests = requests.concat(parsed.requests);
      notes = notes.concat(parsed.notes);
      nonRequestStep = nonRequestStep || parsed.nonRequestStep;
    }
    if (section.kind === "success") {
      const parsed = parseChecks(section.lines);
      success = { present: true, ...parsed, unusable: success.unusable || parsed.unusable, checks: success.checks.concat(parsed.checks), lines: success.lines.concat(parsed.lines) };
    }
    if (section.kind === "guard") {
      const parsed = parseChecks(section.lines);
      guard = { present: true, ...parsed };
    }
    if (section.kind === "gaps") {
      const linesInSection = bulletText(section.lines);
      gaps.push(...linesInSection);
      if (linesInSection.some((line) => !/^\(none\b/i.test(line))) hasGap = true;
    }
  }
  const reproMatch = lines.join("\n").match(/`repro:\s*([a-z0-9-]+)`/i);
  const reason = blockReason({ hasGap, nonRequestStep, requests, success, guard });
  return {
    title,
    repro: reproMatch ? reproMatch[1] : null,
    preconditions,
    requests,
    notes,
    success: { lines: success.lines, checks: success.checks, unusable: success.unusable },
    falsePositiveGuard: { present: guard.present, lines: guard.lines, checks: guard.checks, unusable: guard.unusable },
    gaps,
    runnable: reason == null,
    reason,
  };
}

function extractBlocks(markdown) {
  const blocks = [];
  let current = null;
  for (const line of String(markdown || "").split("\n")) {
    if (/^## Steps to reproduce\b/.test(line)) {
      if (current) blocks.push(current);
      const title = line.replace(/^## Steps to reproduce\b/, "").replace(/^[\s:—–-]+/, "").trim();
      current = { title, lines: [] };
      continue;
    }
    if (!current) continue;
    if (/^##\s+/.test(line) || line.trim() === "<!-- bughive-repro-end -->") {
      blocks.push(current);
      current = null;
      continue;
    }
    current.lines.push(line);
  }
  if (current) blocks.push(current);
  return blocks;
}

export function parseSteps(markdown) {
  try {
    const blocks = extractBlocks(markdown).map((block) => parseBlock(block.title, block.lines));
    return {
      present: blocks.length > 0,
      runnable: blocks.some((block) => block.runnable),
      blocks,
    };
  } catch {
    return { present: false, runnable: false, blocks: [] };
  }
}
