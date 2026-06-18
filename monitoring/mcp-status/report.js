// Plain-text / ANSI rendering of a dashboard report for the CLI.

const ANSI = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  red: "\x1b[31m",
  cyan: "\x1b[36m",
};

const ICON = { pass: "✔", warn: "▲", fail: "✘" };

/**
 * Format a Unix-epoch-seconds timestamp as ISO + a coarse relative age.
 * @param {number | undefined} epochSec
 * @returns {string | undefined}
 */
const fmtTime = (epochSec) => {
  if (!Number.isFinite(epochSec)) return undefined;
  const d = new Date(epochSec * 1000);
  const diff = Date.now() - d.getTime();
  const abs = Math.abs(diff);
  const units = /** @type {[string, number][]} */ ([
    ["d", 86_400_000],
    ["h", 3_600_000],
    ["m", 60_000],
    ["s", 1000],
  ]);
  let rel = "just now";
  for (const [u, ms] of units) {
    if (abs >= ms) {
      rel = `${Math.floor(abs / ms)}${u} ${diff >= 0 ? "ago" : "from now"}`;
      break;
    }
  }
  return `${d.toISOString()} (${rel})`;
};

/**
 * @param {import("./checks.js").DashboardReport} report
 * @param {{ color?: boolean }} [opts]
 * @returns {string}
 */
export const renderText = (report, opts = {}) => {
  const color = opts.color ?? true;
  const c = (code, text) => (color ? `${code}${text}${ANSI.reset}` : text);
  const statusColor = { pass: ANSI.green, warn: ANSI.yellow, fail: ANSI.red };
  const tag = (status) =>
    c(statusColor[status], `${ICON[status]} ${status.toUpperCase()}`);

  const lines = [];
  lines.push("");
  lines.push(c(ANSI.bold, "IMCP (IC MCP) Status Dashboard"));
  lines.push(
    c(ANSI.dim, `Generated: ${report.generatedAt}`),
  );
  lines.push(
    `MCP server: ${c(ANSI.cyan, report.targets.mcpOrigin)}   ` +
      `II instance: ${c(ANSI.cyan, report.targets.iiOrigin ?? "(unresolved)")}`,
  );
  const dep = report.deployment;
  if (dep && (dep.version || dep.commit)) {
    const shortCommit =
      dep.commit && dep.commit !== "unknown"
        ? dep.commit.slice(0, 12)
        : dep.commit;
    const label = [dep.version && `v${dep.version}`, shortCommit]
      .filter(Boolean)
      .join(" @ ");
    lines.push(
      `Deployment: ${c(ANSI.cyan, label || "unknown")}` +
        (dep.commitUrl ? `  ${c(ANSI.dim, dep.commitUrl)}` : ""),
    );
    const started = fmtTime(dep.startedAt);
    if (started) {
      lines.push(`Last redeployed: ${c(ANSI.cyan, started)}`);
    }
    const built = fmtTime(dep.builtAt);
    if (built) {
      lines.push(c(ANSI.dim, `Built: ${built}`));
    }
  }
  lines.push(`Overall: ${tag(report.overall)}`);

  for (const section of report.sections) {
    lines.push("");
    lines.push(`${tag(section.status)}  ${c(ANSI.bold, section.title)}`);
    for (const check of section.checks) {
      const latency =
        check.latencyMs != null ? c(ANSI.dim, ` (${check.latencyMs}ms)`) : "";
      lines.push(`  ${tag(check.status)}  ${check.label}${latency}`);
      if (check.description) {
        lines.push(c(ANSI.dim, `      ${check.description}`));
      }
      lines.push(c(ANSI.dim, `      ${check.target}`));
      lines.push(`      ${check.detail}`);
    }
  }

  if (report.suggestions.length > 0) {
    lines.push("");
    lines.push(c(ANSI.bold, "Suggestions"));
    for (const s of report.suggestions) {
      lines.push(`  ${c(ANSI.cyan, "•")} ${s}`);
    }
  }

  lines.push("");
  return lines.join("\n");
};
