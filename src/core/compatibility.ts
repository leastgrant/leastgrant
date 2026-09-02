/**
 * Reading the compatibility data, and grading it.
 *
 * `compatibility/*.json` records what each agent's hook system can actually
 * enforce, and how each claim was established. This module turns that into the
 * one-line answer people actually want — "what am I getting with this agent" —
 * and it lives in core so that `leastgrant doctor` and the website reach the
 * same verdict from the same evidence. A grading rule duplicated in two places
 * would eventually let the CLI and the website disagree about the same agent,
 * which is precisely the drift the data directory exists to prevent.
 *
 * The grades are deliberately unflattering. There is no top grade that means
 * "perfect", because no agent surveyed so far deserves one: every agent except
 * Copilot fails open when the hook crashes, which means a LeastGrant that
 * cannot start enforces nothing and says nothing. A scale whose best value is
 * reachable by everyone is a marketing scale.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';

/** How a claim was established. Ordered weakest to strongest. */
export type Grade = 'unknown' | 'docs' | 'source' | 'probe';

export interface Fact<T = unknown> {
  value: T;
  evidence?: Grade;
  note?: string;
}

export interface AgentCompatibility {
  id: string;
  name: string;
  supported: 'enforcing' | 'partial' | 'evaluated-not-yet-shipped' | 'evaluated-and-deferred';
  adapter: string | null;
  configPath?: string;
  versionTested: string;
  lastVerified: string;
  osTested: string[];
  osUntested?: string[];
  verdicts: Record<string, Fact<string>>;
  failure: Record<string, Fact<unknown>>;
  interception: Record<string, Fact<string>>;
  observation: Record<string, Fact<unknown>>;
  modes: Record<string, unknown>;
  upstreamLimitations: string[];
  leastgrantLimitations: string[];
}

/**
 * How much of LeastGrant survives the trip through this agent.
 *
 *   enforcing  every verdict lands, everything is intercepted, and somebody
 *              watched it happen.
 *   partial    it enforces, but there is a hole worth naming — a tool class it
 *              cannot see, or a verdict that degrades.
 *   degraded   the strongest thing it can do is refuse. An `ask` cannot reach a
 *              person here, so LeastGrant is a veto and not a prompt.
 *   unverified an adapter exists and nobody has run it against the real agent.
 *   none       no adapter ships.
 */
export type Enforcement = 'enforcing' | 'partial' | 'degraded' | 'unverified' | 'none';

export interface Assessment {
  agent: AgentCompatibility;
  level: Enforcement;
  /** Ordered, most important first. Each is a fact, not a slogan. */
  findings: { status: 'ok' | 'warn' | 'bad' | 'info'; text: string }[];
}

/**
 * Find the data directory.
 *
 * Walks up for package.json rather than assuming a depth, because this runs
 * from `dist/src/core/` in an installed package and from `src/core/` under a
 * loader, and an installed copy may sit anywhere at all.
 */
export function compatibilityDir(from = fileDir()): string {
  let dir = from;
  for (let i = 0; i < 8; i++) {
    const candidate = path.join(dir, 'compatibility');
    if (fs.existsSync(path.join(dir, 'package.json')) && fs.existsSync(candidate)) return candidate;
    const up = path.dirname(dir);
    if (up === dir) break;
    dir = up;
  }
  return '';
}

function fileDir(): string {
  const u = new URL(import.meta.url);
  // On Windows a file URL path is `/D:/...`; strip the leading slash.
  return path.dirname(decodeURIComponent(u.pathname.replace(/^\/([A-Za-z]:)/, '$1')));
}

/**
 * Load every agent file.
 *
 * Never throws. Doctor runs on machines where something is already wrong, and
 * a diagnostic that dies because one data file is malformed is a diagnostic
 * that fails exactly when it is needed. A file that will not parse is skipped
 * and reported by its absence.
 */
export function loadCompatibility(dir = compatibilityDir()): AgentCompatibility[] {
  if (!dir || !fs.existsSync(dir)) return [];
  const out: AgentCompatibility[] = [];
  for (const name of fs.readdirSync(dir)) {
    if (!name.endsWith('.json')) continue;
    try {
      const parsed = JSON.parse(fs.readFileSync(path.join(dir, name), 'utf8')) as AgentCompatibility;
      if (parsed && typeof parsed.id === 'string') out.push(parsed);
    } catch {
      // Skipped on purpose. See above.
    }
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

const val = (f: Fact<unknown> | undefined): string => String(f?.value ?? 'unknown');

/** The tool classes a user would expect to be covered, in the order they matter. */
const CLASSES: [string, string][] = [
  ['shell', 'shell commands'],
  ['fileWrite', 'file writes'],
  ['fileRead', 'file reads'],
  ['fileDelete', 'deletions'],
  ['mcp', 'MCP calls'],
];

export function assess(agent: AgentCompatibility): Assessment {
  const findings: Assessment['findings'] = [];

  if (!agent.adapter) {
    return {
      agent,
      level: 'none',
      findings: [
        {
          status: 'info',
          text:
            agent.supported === 'evaluated-and-deferred'
              ? `evaluated and deferred — ${firstSentence(agent.upstreamLimitations[0] ?? 'the hook surface is not sufficient')}`
              : 'evaluated, no adapter ships yet',
        },
      ],
    };
  }

  // 1. Can it refuse? Everything else is secondary: an agent where deny does
  //    not land is not a permission layer at all.
  const deny = val(agent.verdicts?.['deny']);
  findings.push(
    deny === 'honoured'
      ? { status: 'ok', text: 'deny is enforced, including in the most permissive mode' }
      : { status: 'bad', text: `deny is ${deny} — LeastGrant cannot refuse anything here` },
  );

  // 2. Can it ask? This is the difference between a prompt and a veto.
  const ask = val(agent.verdicts?.['ask']);
  if (ask === 'honoured') findings.push({ status: 'ok', text: 'an ask reaches a person' });
  else if (ask === 'partial') findings.push({ status: 'warn', text: `an ask reaches a person only on some channels — ${note(agent.verdicts?.['ask'])}` });
  else if (ask === 'degrades') findings.push({ status: 'warn', text: `an ask degrades — ${note(agent.verdicts?.['ask'])}` });
  else findings.push({ status: 'warn', text: 'no ask exists here, so LeastGrant is a veto rather than a prompt' });

  // 3. What happens when LeastGrant itself breaks.
  const crash = val(agent.failure?.['onCrash']);
  findings.push(
    crash === 'closed'
      ? { status: 'ok', text: 'if the hook errors, the call is refused rather than run' }
      : crash === 'open'
        ? { status: 'warn', text: 'if the hook errors or times out, the call runs anyway — a LeastGrant that cannot start enforces nothing' }
        : { status: 'warn', text: 'nobody has established what happens when the hook errors' },
  );

  // 4. Coverage gaps, named individually. A gap is the thing a support table is
  //    worst at admitting, so it gets a line each rather than a footnote.
  const gaps: string[] = [];
  const observedOnly: string[] = [];
  for (const [key, label] of CLASSES) {
    const v = val(agent.interception?.[key]);
    if (v === 'none') gaps.push(label);
    else if (v === 'observed') observedOnly.push(label);
  }
  if (gaps.length) findings.push({ status: 'bad', text: `not intercepted at all: ${gaps.join(', ')}` });
  if (observedOnly.length) {
    findings.push({
      status: 'warn',
      text: `seen only after the fact, not gated: ${observedOnly.join(', ')}`,
    });
  }

  // 5. Has anyone actually run it.
  const probed = Object.values({ ...agent.verdicts, ...agent.interception }).some((f) => f?.evidence === 'probe');
  const live = probed && agent.osTested.length > 0;
  findings.push(
    live
      ? { status: 'ok', text: `verified against ${agent.name} ${agent.versionTested} on ${agent.osTested.join(', ')}` }
      : {
          status: 'warn',
          text: `never run inside a real ${agent.name} — the contract is read from what ships, the integration is untested`,
        },
  );

  for (const l of agent.upstreamLimitations.slice(0, 4)) findings.push({ status: 'info', text: l });

  // `degrades` and `unsupported` are not the same failure and must not collapse
  // into one grade. On Claude Code an ask reaches a person whenever a person is
  // there, and becomes a deny when nobody is — that is a prompt with a safe
  // fallback. On Codex there is no ask at any time, in any mode: LeastGrant can
  // only ever refuse. Calling both "degraded" would tell someone choosing
  // between them that it makes no difference, and it makes the largest
  // difference of anything in this file.
  const vetoOnly = ask === 'unsupported' || ask === 'ignored' || ask === 'unknown';

  const level: Enforcement =
    deny !== 'honoured' ? 'degraded'
    : vetoOnly ? 'degraded'
    : !live ? 'unverified'
    : gaps.length || observedOnly.length ? 'partial'
    : ask === 'honoured' && crash === 'closed' ? 'enforcing'
    : 'partial';

  return { agent, level, findings };
}

/** One line describing what a level means, for a reader who has not seen the scale. */
export const LEVEL_MEANING: Record<Enforcement, string> = {
  enforcing: 'every verdict lands and every tool class is gated',
  partial: 'it enforces, with a named gap below',
  degraded: 'it can refuse, but it cannot ask a person',
  unverified: 'an adapter ships and nobody has run it against the real agent',
  none: 'no adapter ships',
};

/**
 * The note, trimmed to one sentence and lowercased at the front.
 *
 * These are appended after an em dash mid-sentence, and a capital letter there
 * reads as the start of a new thought rather than the continuation it is. Only
 * the first character is touched, so "MCP calls" and "LeastGrant" keep their
 * capitals wherever they appear.
 */
function note(f: Fact<unknown> | undefined): string {
  const s = firstSentence(f?.note ?? 'no detail recorded');
  return /^[A-Z][a-z]/.test(s) ? s[0]!.toLowerCase() + s.slice(1) : s;
}

function firstSentence(s: string): string {
  const m = /^(.*?[.!?])(\s|$)/.exec(s.trim());
  const out = (m?.[1] ?? s).trim();
  return out.length > 160 ? out.slice(0, 157) + '…' : out;
}
