/**
 * Every verdict shown on this website, captured by running the real CLI.
 *
 * The alternative -- writing plausible terminal output into the page by hand --
 * is how a marketing site ends up claiming a behaviour the product does not
 * have. For a tool whose entire pitch is "it returns the right answer", a
 * fabricated screenshot would be the single most damaging thing on the page.
 * So there is no hand-written verdict anywhere in this site: the build shells
 * out to `leastgrant check`, captures stdout, and renders that.
 *
 * If the engine changes its mind about a command, the website changes with it
 * on the next build. If the CLI stops producing one of these, the build fails.
 *
 * Two states are captured, because the interesting thing about LeastGrant is
 * the difference between them:
 *
 *   fresh    a machine that has just installed it and knows nothing
 *   learned  the same machine after the routine work has been approved a few
 *            times, which is what the second week looks like
 *
 * The "learned" envelope is built through the product's own `observe()` -- the
 * same function the hook calls when you approve something -- rather than by
 * hand-editing a state file. It is a real profile, just reached in a hurry.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const REPO = path.resolve(HERE, '..', '..');

const DAY = 86_400_000;

/**
 * A sandbox for the capture, laid out so the CLI's own path elision produces
 * text that is already anonymous.
 *
 * The CLI shortens a long path to its last two segments -- `…/you/.ssh/id_rsa`.
 * Naming the fake home directory `you` therefore makes the elided form read
 * exactly like a generic example, with no scrubbing and no risk that a
 * find-and-replace misses one. The full paths that do appear are rewritten
 * below, and `assertClean` fails the build if anything from this machine
 * survives either way.
 */
function sandbox() {
  const root = path.join(REPO, 'site', '.capture');
  fs.rmSync(root, { recursive: true, force: true });
  const home = path.join(root, 'you');
  const project = path.join(home, 'project');
  fs.mkdirSync(path.join(project, 'src'), { recursive: true });
  fs.mkdirSync(path.join(home, '.ssh'), { recursive: true });
  // A project root the resolver will recognise, so `check` runs in a workspace
  // rather than treating the whole sandbox as outside one.
  fs.writeFileSync(path.join(project, 'package.json'), '{\n  "name": "project"\n}\n');
  fs.writeFileSync(path.join(project, 'src', 'app.ts'), 'export const x = 1;\n');
  fs.writeFileSync(path.join(home, '.ssh', 'id_rsa'), 'not-a-real-key\n');
  return { root, home, project, state: path.join(home, '.leastgrant') };
}

/** Environment that keeps this machine out of the captured text. */
function env(box) {
  return {
    ...process.env,
    HOME: box.home,
    USERPROFILE: box.home,
    LEASTGRANT_HOME: box.state,
    NO_COLOR: '1',
    // Width is part of the output: the CLI wraps to the terminal. Pinning it
    // means the captured text is identical on every machine that builds this,
    // which is the difference between a reproducible site and a diff every time
    // somebody with a wider window runs the build.
    COLUMNS: '92',
  };
}

/** Teach the sandbox profile that some commands are routine, via the real API. */
async function train(box, commands) {
  const dist = path.join(REPO, 'dist', 'src');
  const { analyze } = await import(pathToUrl(path.join(dist, 'core', 'classify.js')));
  const { observe, newEnvelope, DEFAULT_THRESHOLDS } = await import(
    pathToUrl(path.join(dist, 'core', 'envelope.js'))
  );
  const { projectKey, findProjectRoot } = await import(pathToUrl(path.join(dist, 'core', 'paths.js')));

  // `saveEnvelope` writes under the state directory resolved at import time, so
  // the override has to be in place before the store module is loaded.
  process.env['LEASTGRANT_HOME'] = box.state;
  const store = await import(pathToUrl(path.join(dist, 'store', 'index.js')));

  const root = findProjectRoot(box.project);
  const key = projectKey(root);
  const envelope = newEnvelope('project', key);
  const now = Date.now();

  // Eight approvals across eight sessions and eight days. The published bar is
  // five approvals over two sessions and two days for this tier; going past it
  // means the capture does not start failing the day somebody tightens it.
  for (let day = 8; day >= 1; day--) {
    const at = now - day * DAY;
    for (const command of commands) {
      const analysis = analyze(
        { agent: 'capture', tool: 'Bash', input: { command }, cwd: box.project, sessionId: `s${day}`, at },
        { roots: [root], secretPatterns: [] },
      );
      for (const action of analysis.actions) {
        observe(
          envelope,
          {
            signature: action.signature,
            capability: action.capability,
            blast: action.blast,
            evidence: 'confirmed',
            at,
            sessionId: `s${day}`,
            display: action.display,
          },
          DEFAULT_THRESHOLDS,
        );
      }
    }
  }
  store.saveEnvelope(envelope);
}

function pathToUrl(p) {
  return new URL(`file://${p.startsWith('/') ? '' : '/'}${p.split(path.sep).join('/')}`).href;
}

/** Run `leastgrant <args>` in the sandbox project and return its stdout. */
function cli(box, args) {
  const r = spawnSync(process.execPath, [path.join(REPO, 'bin', 'leastgrant.js'), ...args], {
    cwd: box.project,
    env: env(box),
    encoding: 'utf8',
    maxBuffer: 8 * 1024 * 1024,
  });
  if (r.error) throw r.error;
  const out = `${r.stdout || ''}${r.stderr || ''}`;
  // `check` exits non-zero to signal the verdict, which is useful in a shell
  // and meaningless here. A missing binary or a crash is not: those produce no
  // recognisable verdict, which the caller checks for.
  return out;
}

/** Rewrite sandbox paths to something a reader would recognise. */
function anonymise(text, box) {
  const forms = (p) => [p, p.split(path.sep).join('/'), p.split(path.sep).join('\\\\')];
  let out = text;
  for (const f of forms(box.project)) out = out.split(f).join('/home/you/project');
  for (const f of forms(box.home)) out = out.split(f).join('/home/you');
  return out;
}

/**
 * Refuse to ship anything carrying this machine's identity.
 *
 * A build that leaks a username or a drive letter into a public page is a small
 * privacy failure on any site and an embarrassing one on this site. This runs
 * over every captured string, and over the finished HTML in the build.
 */
export function assertClean(text, where) {
  // The documentation legitimately shows example paths -- `~/.leastgrant`, and
  // `C:\Users\<you>\.leastgrant` on Windows. So the check is not "no user
  // paths", which would fail on the docs, but "no user path naming somebody
  // real". These are the placeholders that count as anonymous, including the
  // HTML-escaped form of `<you>`, since this also runs over rendered pages.
  const PLACEHOLDER = String.raw`(?:you\b|&lt;you&gt;|<you>|<username>|%USERNAME%|\$\{?USER)`;

  // Home directories are matched with a *terminator* rather than a required
  // trailing slash. Requiring `/home/name/` meant a path that ended at the home
  // directory -- `/home/deploy`, the most likely shape on a CI runner -- sailed
  // through. The terminator is "anything that is not part of a name".
  const END = String.raw`(?=$|[\\/\s"'<>)\]:,;]|&lt;)`;

  // Files Windows holds open at the root of C:. Fixed names, present on every
  // install, and named on purpose by the traversal cases in the bypass corpus.
  const LOCKED_ROOT_FILES = String.raw`(?:pagefile\.sys|hiberfil\.sys|swapfile\.sys|DumpStack\.log(?:\.tmp)?)`;

  const bad = [
    [new RegExp(String.raw`[\\/]Users[\\/](?!${PLACEHOLDER})[^\\/\s"'<)]+`, 'i'), 'a real user directory'],
    [new RegExp(String.raw`[\\/]home[\\/](?!${PLACEHOLDER})[a-z0-9_.-]+${END}`, 'i'), 'a real home directory'],
    [new RegExp(String.raw`[\\/]root[\\/][a-z0-9_.-]+${END}`, 'i'), 'a root home directory'],
    // Any Windows absolute path, not only this repository's. The original rule
    // was anchored to `LeastGrant` and so only worked because the checkout
    // happened to live at D:\LeastGrant; a clone anywhere else leaked silently.
    // Placeholders and the two paths the docs legitimately show are excluded.
    //
    // So are the locked files Windows keeps at the root of every install.
    // They are not anybody's directory — the names are the same on every
    // machine — and the published bypass corpus needs them verbatim, because
    // being unopenable is precisely what those attacks use them for: a path
    // walk refused at `C:\pagefile.sys\..\..` used to make the whole path
    // "unplaceable", which switched off every floor keyed to it. Rewriting them
    // to a placeholder would publish an attack that no longer describes the
    // attack.
    [
      new RegExp(
        String.raw`\b[A-Za-z]:[\\/](?!Users[\\/]${PLACEHOLDER}|Program Files|Windows[\\/]|path[\\/]|srv[\\/]|${LOCKED_ROOT_FILES}[\\/])[A-Za-z0-9_.\-]{2,}[\\/]`,
      ),
      'a Windows absolute path',
    ],
    [/AppData[\\/]Local[\\/]Temp/i, 'a temp directory from the build machine'],
    [/[\\/]mnt[\\/][a-z][\\/][A-Za-z0-9_.-]+[\\/]/, 'a WSL-mounted host path'],
    [/[\\/](?:var[\\/]folders|private[\\/]var[\\/]folders)[\\/]/, 'a macOS temp directory'],
    // Secrets, in case one ever reaches a template.
    [/\bnpm_config_[a-z_]*(?:token|auth|password)/i, 'a registry credential variable'],
    [/\bnpm_[A-Za-z0-9]{30,}\b/, 'an npm token'],
    [/\bgh[pousr]_[A-Za-z0-9]{20,}\b/, 'a GitHub token'],
    [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, 'a private key'],
    [/\bAKIA[0-9A-Z]{16}\b/, 'an AWS access key id'],
  ];
  for (const [re, what] of bad) {
    const hit = text.match(re);
    if (hit) throw new Error(`${where}: leaked ${what} -- ${JSON.stringify(hit[0])}`);
  }
}

/**
 * The same check, for files that are not text.
 *
 * PNGs and woff2 files carry metadata chunks that tooling fills in without
 * being asked -- a source path, a machine name, an author. The text sweep skips
 * them because they are not text, which is precisely why nobody would notice.
 * Reading them as latin1 and running the same patterns over the result costs
 * nothing on an 800 KB site.
 */
export function assertCleanBinary(buffer, where) {
  const printable = buffer.toString('latin1').replace(/[^\x20-\x7e]+/g, '\n');
  assertClean(printable, where);
}

/**
 * The commands the site shows.
 *
 * Chosen to cover the shapes the decision engine treats differently, not to
 * flatter it: two that become routine, one where a flag changes everything, one
 * credential read, one piece of code that cannot be read before it runs, and
 * one attempt on LeastGrant's own records. `state: 'fresh'` runs against a
 * profile that has learned nothing.
 */
export const COMMANDS = [
  {
    id: 'npm-test',
    command: 'npm test',
    state: 'learned',
    caption: 'The hundredth run of the test suite.',
  },
  {
    id: 'git-status',
    command: 'git status',
    state: 'learned',
    caption: 'Looking around costs nothing and happens constantly.',
  },
  {
    id: 'git-push-force',
    command: 'git push --force origin main',
    state: 'learned',
    caption: 'Same program, same project, one flag. Not the same action.',
  },
  {
    id: 'secret-read',
    command: 'cat ~/.ssh/id_rsa',
    state: 'learned',
    caption: 'No amount of repetition promotes this one.',
  },
  {
    id: 'curl-pipe-sh',
    command: 'curl -sSL https://get.example.com/install.sh | sh',
    state: 'learned',
    caption: 'The verdict is about what cannot be read, not what was typed.',
  },
  {
    id: 'self-write',
    command: 'echo x >> ~/.leastgrant/ledger.jsonl',
    state: 'learned',
    caption: 'Editing the thing that is watching. The only outright deny.',
  },
  {
    id: 'npm-test-fresh',
    command: 'npm test',
    state: 'fresh',
    caption: 'The same command on the first day, before it has seen anything.',
  },
];

/**
 * Run every command and return the captured verdicts.
 *
 * Throws rather than degrading. A website that quietly renders half its demo
 * because the CLI was not built is worse than one that fails to build.
 */
export async function captureVerdicts() {
  if (!fs.existsSync(path.join(REPO, 'dist', 'src', 'index.js'))) {
    throw new Error('dist/ is missing -- run `npm run build` before building the site');
  }

  const box = sandbox();
  const results = [];

  // Fresh first: the learned profile is written into the same sandbox, and once
  // it exists there is no going back to not knowing anything.
  for (const spec of COMMANDS.filter((c) => c.state === 'fresh')) {
    results.push(runOne(box, spec));
  }

  await train(box, ['npm test', 'git status']);

  for (const spec of COMMANDS.filter((c) => c.state === 'learned')) {
    results.push(runOne(box, spec));
  }

  fs.rmSync(box.root, { recursive: true, force: true });
  return COMMANDS.map((c) => results.find((r) => r.id === c.id)).filter(Boolean);
}

/**
 * `leastgrant --help`, verbatim.
 *
 * The CLI reference page is this text. Writing a prettier version by hand would
 * create a second place where the command list lives, and the two would
 * disagree the first time a command is added.
 */
export function captureHelp() {
  const box = sandbox();
  try {
    const help = anonymise(cli(box, ['--help']), box).replace(/^\n+|\n+$/g, '');
    const version = anonymise(cli(box, ['--version']), box).trim();
    if (!/Commands/.test(help)) throw new Error('leastgrant --help did not print a command list');
    assertClean(help, 'captured --help');
    return { help, version };
  } finally {
    fs.rmSync(box.root, { recursive: true, force: true });
  }
}

function runOne(box, spec) {
  const text = anonymise(cli(box, ['check', spec.command]), box);
  const rawJson = anonymise(cli(box, ['check', spec.command, '--json']), box);

  let json;
  try {
    json = JSON.parse(rawJson);
  } catch {
    throw new Error(`leastgrant check --json produced no JSON for ${JSON.stringify(spec.command)}:\n${rawJson}`);
  }
  if (!['allow', 'ask', 'deny'].includes(json.decision)) {
    throw new Error(`unexpected decision ${JSON.stringify(json.decision)} for ${spec.command}`);
  }

  const body = text.replace(/^\n+|\n+$/g, '');
  if (!body) throw new Error(`leastgrant check produced no output for ${JSON.stringify(spec.command)}`);

  assertClean(text, `captured text for ${spec.command}`);
  assertClean(rawJson, `captured json for ${spec.command}`);

  return {
    ...spec,
    decision: json.decision,
    headline: json.headline,
    text: body,
    reasons: (json.reasons || []).map((r) => ({ code: r.code, text: r.text, weight: r.weight })),
    blast: json.action?.blast ?? null,
    understood: json.action?.understood ?? null,
    signature: json.action?.signature ?? null,
    floor: Boolean(json.floor),
    actionCount: Array.isArray(json.actions) ? json.actions.length : 1,
  };
}
