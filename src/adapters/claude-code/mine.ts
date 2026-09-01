/**
 * Learning from history you already have.
 *
 * Claude Code writes every session to plain JSONL under `~/.claude/projects/`,
 * including every tool call, the permission mode it ran under, and — crucially
 * — whether you turned it down. On a machine that has been used for a while
 * that is thousands of real decisions sitting on disk.
 *
 * So LeastGrant does not have to spend a fortnight watching you before it is
 * useful. It reads what already happened, and can tell you on the first run
 * what your agents have been doing and which of it it would have stopped.
 *
 * The honest caveat, which the UI repeats: a transcript records that a call
 * *ran*, not that a human said yes — and a transcript is a file on disk that
 * something other than Claude Code could have written. So nothing mined here
 * counts as approval, in any permission mode. Mining answers "what is normal
 * in this project", and setup asks you what to do about it. See `evidenceFor`
 * below for the attack that settled this, and envelope.ts for why the
 * distinction between typical and sanctioned is load-bearing.
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import type { Capability, Envelope, EvidenceKind } from '../../core/types.js';
import { blastTier } from '../../core/types.js';
import { analyze } from '../../core/classify.js';
import { newEnvelope, observe } from '../../core/envelope.js';
import { findProjectRoot, projectKey } from '../../core/paths.js';
import { DEFAULT_THRESHOLDS } from '../../core/envelope.js';

export interface MinedEvent {
  at: number;
  sessionId: string;
  cwd: string;
  tool: string;
  input: Record<string, unknown>;
  permissionMode: string;
  /** True when the transcript records the user turning this down. */
  denied: boolean;
  branch?: string;
}

/**
 * Tools Claude Code does not prompt for in manual mode.
 *
 * A successful call to one of these tells us nothing about what the human would
 * have agreed to, so it counts as observation, never approval.
 */
const AUTO_ALLOWED = new Set(['Read', 'Glob', 'Grep', 'TodoWrite', 'NotebookRead', 'WebSearch', 'Task']);

/** Modes in which nobody was asked. */
const UNATTENDED = new Set(['bypassPermissions', 'acceptEdits', 'dontAsk', 'auto']);

export function transcriptRoot(): string {
  const override = process.env['CLAUDE_CONFIG_DIR'];
  const base = override ? path.resolve(override) : path.join(os.homedir(), '.claude');
  return path.join(base, 'projects');
}

/** Every transcript file, newest first. */
export function transcriptFiles(root = transcriptRoot()): string[] {
  const out: string[] = [];
  let dirs: string[];
  try {
    dirs = fs.readdirSync(root);
  } catch {
    return [];
  }
  for (const d of dirs) {
    const full = path.join(root, d);
    try {
      if (!fs.statSync(full).isDirectory()) continue;
      for (const f of fs.readdirSync(full)) {
        if (f.endsWith('.jsonl')) out.push(path.join(full, f));
      }
    } catch {
      /* unreadable project dir */
    }
  }
  return out.sort((a, b) => safeMtime(b) - safeMtime(a));
}

function safeMtime(f: string): number {
  try {
    return fs.statSync(f).mtimeMs;
  } catch {
    return 0;
  }
}

/**
 * Pull tool calls out of one transcript.
 *
 * A `tool_use` block in an assistant message is the request; the matching
 * `tool_result` in the following user message is the outcome. We correlate on
 * `tool_use_id` because they are not always adjacent.
 */
export function readTranscript(file: string): MinedEvent[] {
  let raw: string;
  try {
    raw = fs.readFileSync(file, 'utf8');
  } catch {
    return [];
  }

  const pending = new Map<string, MinedEvent>();
  const events: MinedEvent[] = [];

  // `permissionMode` is recorded on user-turn records, not on the assistant
  // records that carry `tool_use`. So we track the most recent mode seen and
  // attribute tool calls to it. Getting this wrong is not cosmetic: defaulting
  // to "default" would mark thousands of bypass-mode calls as human-approved,
  // which is exactly the false evidence the whole design is built to avoid.
  let currentMode = 'default';

  for (const line of raw.split('\n')) {
    if (!line) continue;
    let rec: TranscriptRecord;
    try {
      rec = JSON.parse(line) as TranscriptRecord;
    } catch {
      continue;
    }
    if (rec.permissionMode) currentMode = rec.permissionMode;
    const content = rec.message?.content;
    if (!Array.isArray(content)) continue;

    for (const block of content) {
      if (block.type === 'tool_use' && block.name && block.id) {
        const ev: MinedEvent = {
          at: Date.parse(rec.timestamp ?? '') || 0,
          sessionId: rec.sessionId ?? path.basename(file, '.jsonl'),
          cwd: rec.cwd ?? '',
          tool: block.name,
          input: (block.input ?? {}) as Record<string, unknown>,
          permissionMode: currentMode,
          denied: false,
        };
        if (rec.gitBranch) ev.branch = rec.gitBranch;
        pending.set(block.id, ev);
      } else if (block.type === 'tool_result' && block.tool_use_id) {
        const ev = pending.get(block.tool_use_id);
        if (!ev) continue;
        pending.delete(block.tool_use_id);
        ev.denied = isDenial(rec, block);
        events.push(ev);
      }
    }
  }

  // A tool_use with no result is an interrupted or still-running call. It tells
  // us the agent wanted to do something, which is worth recording as observed
  // intent but not as a completed action.
  return events;
}

interface TranscriptRecord {
  timestamp?: string;
  sessionId?: string;
  cwd?: string;
  gitBranch?: string;
  permissionMode?: string;
  toolDenialKind?: string;
  message?: { content?: ContentBlock[] };
}

interface ContentBlock {
  type?: string;
  name?: string;
  id?: string;
  input?: unknown;
  tool_use_id?: string;
  content?: unknown;
  is_error?: boolean;
}

/**
 * Did the human turn this down?
 *
 * `toolDenialKind` is the structured signal and is preferred. The prose form is
 * checked too because it is what older transcripts contain, and because it is
 * the string Claude Code actually feeds back to the model.
 */
function isDenial(rec: TranscriptRecord, block: ContentBlock): boolean {
  if (rec.toolDenialKind === 'user-rejected') return true;
  const text = typeof block.content === 'string' ? block.content : JSON.stringify(block.content ?? '');
  return /The user doesn't want to proceed with this tool use|The user doesn't want to take this action/i.test(text);
}

/**
 * Was anybody watching when this ran?
 *
 * Reporting only — this decides what `leastgrant init` tells you about your own
 * history, never what gets promoted. See `evidenceFor` for why those are
 * different questions.
 */
export function attendedFor(ev: MinedEvent): boolean {
  if (UNATTENDED.has(ev.permissionMode)) return false;
  if (AUTO_ALLOWED.has(ev.tool)) return false;
  return true;
}

/**
 * Decide what kind of evidence a mined event represents.
 *
 * Never `confirmed`, and that is deliberate.
 *
 * This function used to return `confirmed` for anything that ran in an attended
 * permission mode, on the reasoning that a prompt must have been answered. Two
 * things are wrong with it. The small one: the call may have matched an allow
 * rule in the user's settings, in which case a human authored *a rule*, not
 * this action. The large one: transcripts are files, and files can be written.
 * An agent that has been talked into writing to `~/.claude/projects/` can
 * fabricate months of plausible history, and `leastgrant init` would read it as
 * hundreds of human approvals. Measured, that forgery promoted an outbound
 * `curl` to an attacker-chosen host on the strength of nothing at all.
 *
 * So mining is demoted to what it can honestly claim: this is what *typically*
 * happens here. Typicality is used to work out what to *offer* at setup, and
 * the human turning that offer down or accepting it is the attestation. That
 * keeps the promise the top of `envelope.ts` makes — only human-attested
 * evidence promotes — instead of quietly making an exception for the one
 * source that is not human.
 *
 * The cost was measured on 10,800 real actions before this was changed: the
 * auto-approve rate after setup is identical (42%), the same starter bundles
 * are proposed with the same coverage, and there are still no regrets. The only
 * number that moves is the rate *before* the user has agreed to anything, which
 * falls from 9% to 5% — being more cautious before being asked is the right
 * direction for that number to move.
 *
 * Denials are still mined. A refusal recorded in a transcript is worth keeping
 * even from an untrusted source, because the worst a forged denial can do is
 * make LeastGrant ask about something it would otherwise have allowed, and the
 * user can undo it with an explicit rule.
 */
export function evidenceFor(ev: MinedEvent): EvidenceKind {
  if (ev.denied) return 'denied';
  return 'observed';
}

export interface MineOptions {
  /** Only mine sessions whose cwd is inside this root. */
  project?: string;
  /** Ignore events older than this. */
  since?: number;
  /** Stop after this many files (newest first). */
  maxFiles?: number;
}

/**
 * Counts describing a mined history.
 *
 * `confirmed` and `observed` here mean *attended* and *unattended* — whether
 * anybody was at the keyboard, not whether anybody approved. Mining never
 * produces human attestation; see `evidenceFor`. The names are kept because
 * they are the same words the envelope uses for the same shape of thing, and
 * renaming the fields would only move the confusion somewhere else.
 */
export interface ProjectSummary {
  key: string;
  root: string;
  events: number;
  sessions: number;
  confirmed: number;
  observed: number;
  denied: number;
  envelope: Envelope;
}

export interface MineResult {
  filesRead: number;
  events: number;
  sessions: number;
  confirmed: number;
  observed: number;
  denied: number;
  earliest: number;
  latest: number;
  byProject: Map<string, ProjectSummary>;
  /** Signature -> how often, across everything. Used for suggestions. */
  topSignatures: { signature: string; count: number; capability: Capability; display: string }[];
  /** Events we could not attribute to a project (no cwd recorded). */
  skipped: number;
}

/**
 * Read history and fold it into per-project envelopes.
 *
 * This does the full classification pass — the same code the live hook runs —
 * so what you see in `leastgrant init` is genuinely what the hook would have
 * decided, not an approximation of it.
 */
export function mine(opts: MineOptions = {}): MineResult {
  const files = transcriptFiles();
  const limited = opts.maxFiles ? files.slice(0, opts.maxFiles) : files;

  const byProject = new Map<string, ProjectSummary>();
  const sigCounts = new Map<string, { count: number; capability: Capability; display: string }>();
  const sessions = new Set<string>();

  let events = 0;
  let confirmed = 0;
  let observed = 0;
  let denied = 0;
  let skipped = 0;
  let earliest = Number.MAX_SAFE_INTEGER;
  let latest = 0;

  const lastCapability = new Map<string, Capability>();

  for (const file of limited) {
    for (const ev of readTranscript(file)) {
      if (!ev.cwd) {
        skipped++;
        continue;
      }
      if (opts.since && ev.at < opts.since) continue;

      const root = findProjectRoot(ev.cwd);
      if (opts.project && projectKey(root) !== projectKey(opts.project)) continue;

      const key = projectKey(root);
      let summary = byProject.get(key);
      if (!summary) {
        summary = {
          key,
          root,
          events: 0,
          sessions: 0,
          confirmed: 0,
          observed: 0,
          denied: 0,
          envelope: newEnvelope('project', key),
        };
        byProject.set(key, summary);
      }

      let analysis;
      try {
        analysis = analyze(
          {
            agent: 'claude-code',
            tool: ev.tool,
            input: ev.input,
            cwd: ev.cwd,
            sessionId: ev.sessionId,
            at: ev.at,
            ...(ev.branch ? { branch: ev.branch } : {}),
            ...(ev.permissionMode ? { agentMode: ev.permissionMode } : {}),
          },
          { roots: [root], secretPatterns: [] },
        );
      } catch {
        skipped++;
        continue;
      }

      const evidence = evidenceFor(ev);
      // A refusal applies to the command as a whole, so it is attributed to the
      // most far-reaching action in it rather than to every part. See the same
      // reasoning in replay.ts — without this, refusing one compound command
      // permanently blacklists whatever ordinary verbs it happened to contain.
      const learnFrom =
        evidence === 'denied' && analysis.actions.length > 1
          ? [analysis.actions.reduce((w, a) => (blastTier(a.blast) > blastTier(w.blast) ? a : w))]
          : analysis.actions;
      for (const action of learnFrom) {
        const prev = lastCapability.get(ev.sessionId);
        observe(
          summary.envelope,
          {
            signature: action.signature,
            capability: action.capability,
            blast: action.blast,
            evidence,
            at: ev.at,
            sessionId: ev.sessionId,
            display: action.display,
            ...(prev ? { previousCapability: prev } : {}),
          },
          DEFAULT_THRESHOLDS,
        );
        lastCapability.set(ev.sessionId, action.capability);

        const s = sigCounts.get(action.signature) ?? {
          count: 0,
          capability: action.capability,
          display: action.display,
        };
        s.count++;
        sigCounts.set(action.signature, s);
      }

      summary.events++;
      events++;
      // Counted from `attendedFor`, not from the evidence kind. Mining no
      // longer produces `confirmed` — but "how much of your history ran with
      // nobody watching" is still the most useful thing setup can tell you
      // about your own habits, so it is measured separately rather than lost.
      if (evidence === 'denied') {
        summary.denied++;
        denied++;
      } else if (attendedFor(ev)) {
        summary.confirmed++;
        confirmed++;
      } else {
        summary.observed++;
        observed++;
      }

      if (!sessions.has(ev.sessionId)) {
        sessions.add(ev.sessionId);
        summary.sessions++;
      }
      if (ev.at) {
        if (ev.at < earliest) earliest = ev.at;
        if (ev.at > latest) latest = ev.at;
      }
    }
  }

  const topSignatures = [...sigCounts.entries()]
    .map(([signature, v]) => ({ signature, ...v }))
    .sort((a, b) => b.count - a.count);

  return {
    filesRead: limited.length,
    events,
    sessions: sessions.size,
    confirmed,
    observed,
    denied,
    earliest: earliest === Number.MAX_SAFE_INTEGER ? 0 : earliest,
    latest,
    byProject,
    topSignatures,
    skipped,
  };
}
