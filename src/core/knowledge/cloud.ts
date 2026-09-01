/**
 * Cloud providers and infrastructure-as-code.
 *
 * Everywhere else in LeastGrant the worst case is a broken working tree. Here
 * the worst case is a deleted production database, and no `git reset` brings it
 * back. So this module cares about one distinction more than any other:
 *
 *   read   asks the provider what exists           (cheap, repeatable)
 *   plan   asks the provider what *would* change   (still cheap)
 *   apply  changes it                              (frequently irreversible)
 *
 * `terraform plan` and `terraform apply` differ by one word on the command line
 * and by everything else that matters, which is exactly why a generic "does
 * this command look scary" heuristic gets both of them wrong.
 *
 * Two recurring themes:
 *  - a flag that removes the human confirmation step (`-auto-approve`,
 *    `--yes`, `--require-approval never`) is itself worth saying out loud;
 *  - a surprising number of read-only-sounding commands print live credentials
 *    (`terraform output`, `aws secretsmanager get-secret-value`, `heroku
 *    config`, `kubectl get secret -o yaml`). Those are `secret.read`.
 */

import type { Judgement, KnowledgeCtx, ProgramKnowledge } from './types.js';
import { firstNonFlag, flagValue, hasFlag, hostOf, nonFlags } from './types.js';

// ---------------------------------------------------------------------------
// The production signal
// ---------------------------------------------------------------------------

/**
 * Word-ish match so that `prod`, `my-prod-1`, `api.production`, and `go-live`
 * hit, while `product`, `reproduce` and `olive` do not. Boundaries are
 * non-letters, so digits and dashes still count as part of the name.
 */
const PRODUCTION_HINT = /(^|[^a-z])(prod|prd|production|live)([^a-z]|$)/i;

/**
 * Every value on the command line, including the right-hand side of
 * `--flag=value`. `nonFlags` already returns the value of a `--flag value`
 * pair because it only knows how to skip tokens that start with a dash.
 */
function argValues(argv: string[]): string[] {
  const out = nonFlags(argv, 1);
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i]!;
    if (!a.startsWith('-')) continue;
    const eq = a.indexOf('=');
    if (eq > 0) out.push(a.slice(eq + 1));
  }
  return out;
}

/**
 * Drop the value that follows a known option, so that positional reading still
 * works when global flags come first.
 *
 * `nonFlags` only knows how to skip tokens that start with a dash, so
 * `aws --profile prod s3 rm s3://bucket --recursive` reads `prod` as the
 * service name and `s3` as the operation — every service-specific rule below
 * then silently stops applying. Same for `kubectl -n kube-system get pods` and
 * `helm -n prod uninstall`. Only flags that always take a separate value belong
 * in these sets; a flag with an optional value (`kubectl --dry-run`) would eat
 * the subcommand instead.
 */
function dropOptionValues(argv: string[], flags: Set<string>): string[] {
  const out: string[] = argv.length > 0 ? [argv[0]!] : [];
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i]!;
    out.push(a);
    // Everything after `--` is the payload, not our options.
    if (a === '--') {
      out.push(...argv.slice(i + 1));
      break;
    }
    if (flags.has(a)) i++;
  }
  return out;
}

/**
 * True when anything on the command line names production. That covers the
 * environment selectors (`--context`, `--namespace`, `--profile`, `--env`,
 * `--stage`, `--stack`, `-var-file`) and the resource names themselves
 * (`prod-api`, `s3://live-backups`), because both arrive as plain values.
 *
 * Deliberately broad: a false production reading costs one confirmation, a
 * missed one costs an outage.
 */
function targetsProduction(argv: string[]): boolean {
  if (hasFlag(argv, '--prod', '--production')) return true;
  return argValues(argv).some((v) => PRODUCTION_HINT.test(v));
}

/**
 * Raise a judgement that already changes someone else's system up to
 * production reach. Reads are left alone: pointing `describe` at a production
 * cluster is still just a read.
 */
function withProduction(j: Judgement, argv: string[]): Judgement {
  if (j.reach !== 'external') return j;
  if (!targetsProduction(argv)) return j;
  j.reach = 'production';
  j.note = j.note ? `${j.note}, and the target is named like production` : 'the target is named like production';
  return j;
}

/** Append a clause to a note without worrying about whether one exists yet. */
function addNote(j: Judgement, clause: string): Judgement {
  j.note = j.note ? `${j.note}, ${clause}` : clause;
  return j;
}

/** A call that only asks the provider questions. */
function cloudRead(note: string): Judgement {
  return { capability: 'exec.cloud', reach: 'network', reversibility: 'trivial', scale: 'single', note, pathArgs: 'none' };
}

/** A call that prints live credentials to the terminal. */
function credentialRead(note: string): Judgement {
  return { capability: 'secret.read', reach: 'network', reversibility: 'trivial', exposure: 'can-exfiltrate', note, pathArgs: 'none' };
}

// ---------------------------------------------------------------------------
// terraform / opentofu / terragrunt
// ---------------------------------------------------------------------------

function terraform(name: string, argv: string[]): Judgement {
  const words = nonFlags(argv, 1).map((w) => w.toLowerCase());
  // terragrunt's `run-all` (and the newer `run --all`) fans one subcommand out
  // across every module in the tree, so a single `apply` becomes dozens.
  const fanOut = name === 'terragrunt' && (words[0] === 'run-all' || (words[0] === 'run' && hasFlag(argv, '--all')));
  const sub = (fanOut ? words[1] : words[0]) ?? '';
  const arg = (fanOut ? words[2] : words[1]) ?? '';
  // Each of these removes the "do you really want to do this" step.
  const autoApprove =
    hasFlag(argv, '-auto-approve', '--auto-approve', '--terragrunt-non-interactive') ||
    flagValue(argv, '-input', '--input') === 'false';

  if (sub === '' || sub === 'version' || sub === 'help') {
    return { capability: 'exec.inspect', note: 'prints terraform version or help', pathArgs: 'none' };
  }

  // `init` fetches provider binaries and modules from a registry and they run
  // locally with full user rights on the very next command. That is package
  // installation, not configuration.
  if (sub === 'init') {
    return {
      capability: 'exec.pkg',
      reach: 'machine',
      reversibility: 'easy',
      note: 'downloads provider plugins and modules, which are code that will run on this machine',
      pathArgs: 'none',
    };
  }
  if (sub === 'get') {
    return { capability: 'exec.pkg', reach: 'machine', reversibility: 'easy', note: 'downloads modules from their sources', pathArgs: 'none' };
  }

  if (sub === 'fmt') {
    if (hasFlag(argv, '-check', '--check')) return { capability: 'exec.inspect', note: 'checks formatting without changing files' };
    return { capability: 'fs.write.workspace', reversibility: 'easy', scale: 'many', note: 'reformats terraform files in place' };
  }

  // `providers` is mostly a listing, but two of its children are not: `mirror`
  // downloads every provider binary into a local directory, and `lock` rewrites
  // the lock file that decides which packages the next init will trust.
  if (sub === 'providers' && (arg === 'mirror' || arg === 'lock')) {
    return {
      capability: 'exec.pkg',
      reach: 'machine',
      reversibility: 'easy',
      scale: 'many',
      note:
        arg === 'mirror'
          ? 'downloads provider binaries into a local directory, which are code that will run on this machine'
          : 'rewrites the provider lock file, changing which package hashes the next init will accept',
      pathArgs: 'none',
    };
  }
  if (sub === 'validate' || sub === 'graph' || sub === 'providers' || sub === 'metadata') {
    return { capability: 'exec.inspect', note: 'inspects the configuration', pathArgs: 'none' };
  }

  // The whole point of plan: it reads live infrastructure and prints a diff.
  // Nothing is created, so this is the command that should become routine.
  if (sub === 'plan') {
    return {
      capability: 'exec.iac',
      reach: 'network',
      reversibility: 'trivial',
      scale: fanOut ? 'many' : 'single',
      note: 'reads live infrastructure and prints what would change, without changing it',
      pathArgs: 'none',
    };
  }

  // State and outputs hold resource attributes verbatim: database passwords,
  // private keys, generated tokens. Printing them is a credential read.
  if (sub === 'output') {
    return {
      capability: 'exec.iac',
      reach: 'network',
      reversibility: 'trivial',
      exposure: 'reads-secrets',
      note: 'prints output values, which routinely include passwords and keys',
      pathArgs: 'none',
    };
  }
  if (sub === 'show') {
    return {
      capability: 'exec.iac',
      reach: 'network',
      reversibility: 'trivial',
      exposure: 'reads-secrets',
      note: 'prints state, which stores resource attributes in the clear',
      pathArgs: 'none',
    };
  }

  if (sub === 'state') {
    if (arg === 'list') return cloudRead('lists the resources tracked in state');
    if (arg === 'show' || arg === 'pull') {
      return credentialRead('prints raw state, which stores passwords and keys in the clear');
    }
    // rm / mv / push / replace-provider rewrite the ledger terraform uses to
    // decide what it owns. A wrong edit orphans live resources or makes the
    // next apply delete them, and there is no undo.
    const note =
      arg === 'push'
        ? 'overwrites the shared state file, which can orphan or destroy live resources'
        : 'rewrites the state that decides which real resources terraform owns';
    return withProduction(
      { capability: 'exec.iac', reach: 'external', reversibility: 'irreversible', scale: 'many', note, pathArgs: 'none' },
      argv,
    );
  }

  if (sub === 'workspace') {
    if (arg === 'list' || arg === 'show') return { capability: 'exec.inspect', note: 'shows the available workspaces', pathArgs: 'none' };
    if (arg === 'delete') {
      return withProduction(
        {
          capability: 'exec.iac',
          reach: 'external',
          reversibility: 'irreversible',
          scale: 'many',
          note: 'deletes a workspace along with the state that tracks its resources',
          pathArgs: 'none',
        },
        argv,
      );
    }
    // select / new change nothing yet, but they decide which environment every
    // later command in this session lands on.
    const j: Judgement = { capability: 'meta', note: 'switches which environment later terraform commands target', pathArgs: 'none' };
    if (targetsProduction(argv)) addNote(j, 'onto one named like production');
    return j;
  }

  if (sub === 'apply' || sub === 'destroy') {
    const destroying = sub === 'destroy' || hasFlag(argv, '-destroy', '--destroy');
    const targeted = hasFlag(argv, '-target', '--target');
    const j: Judgement = {
      capability: 'exec.iac',
      reach: 'external',
      reversibility: 'irreversible',
      scale: fanOut ? 'sweeping' : targeted ? 'many' : 'sweeping',
      note: destroying
        ? 'destroys every resource this configuration manages'
        : 'creates, changes and replaces real infrastructure',
      pathArgs: 'none',
    };
    // Without this flag terraform stops and shows the diff to a human. With it,
    // the run is the decision.
    if (autoApprove) addNote(j, 'and auto-approve skips the confirmation a person would normally see');
    if (fanOut) addNote(j, 'across every module in the tree');
    return withProduction(j, argv);
  }

  // `terraform test` sounds like a unit test; it provisions and tears down real
  // infrastructure to run its assertions.
  if (sub === 'test') {
    return withProduction(
      {
        capability: 'exec.iac',
        reach: 'external',
        reversibility: 'hard',
        scale: 'many',
        note: 'runs test cases that create and then destroy real infrastructure',
        pathArgs: 'none',
      },
      argv,
    );
  }

  if (sub === 'import' || sub === 'taint' || sub === 'untaint' || sub === 'refresh' || sub === 'force-unlock' || sub === 'unlock') {
    const note =
      sub === 'force-unlock' || sub === 'unlock'
        ? 'removes the state lock, which corrupts state if another apply is still running'
        : sub === 'import'
          ? 'brings an existing resource under terraform control, changing what the next apply does to it'
          : sub === 'refresh'
            ? 'rewrites state from live infrastructure, which can drop resources out of it'
            : 'marks a resource so the next apply destroys and recreates it';
    return withProduction(
      { capability: 'exec.iac', reach: 'external', reversibility: 'irreversible', scale: 'many', note, pathArgs: 'none' },
      argv,
    );
  }

  if (sub === 'login' || sub === 'logout') {
    return {
      capability: 'fs.write.outside',
      reach: 'machine',
      reversibility: 'easy',
      note: sub === 'login' ? 'stores a registry api token on this machine' : 'removes a stored registry api token',
      pathArgs: 'none',
    };
  }

  // The console evaluates arbitrary expressions against live state.
  if (sub === 'console') {
    return {
      capability: 'exec.iac',
      reach: 'network',
      reversibility: 'trivial',
      exposure: 'reads-secrets',
      opaque: true,
      note: 'opens an interactive session that can evaluate anything against state',
      pathArgs: 'none',
    };
  }

  return {
    capability: 'exec.iac',
    reach: 'external',
    opaque: true,
    note: 'runs a terraform subcommand this module does not recognise',
    pathArgs: 'none',
  };
}

// ---------------------------------------------------------------------------
// aws cdk / cdk for terraform
// ---------------------------------------------------------------------------

function cdk(argv: string[]): Judgement {
  const sub = (firstNonFlag(argv, 1) ?? '').toLowerCase();
  const all = hasFlag(argv, '--all');

  // synth runs your application code to produce templates: local execution,
  // nothing deployed.
  if (sub === '' || sub === 'synth' || sub === 'synthesize' || sub === 'ls' || sub === 'list' || sub === 'context' || sub === 'doctor' || sub === 'version') {
    return { capability: 'exec.build', reach: 'workspace', reversibility: 'easy', note: 'runs the app code to render templates locally', pathArgs: 'none' };
  }
  if (sub === 'diff') return cloudRead('compares the rendered templates against what is deployed');
  if (sub === 'get' || sub === 'provider' || sub === 'install') {
    return { capability: 'exec.pkg', reach: 'machine', reversibility: 'easy', note: 'downloads provider bindings, which are code that will run locally', pathArgs: 'none' };
  }
  // Bootstrap plants a deployment role with very broad rights in the account.
  if (sub === 'bootstrap') {
    return withProduction(
      {
        capability: 'exec.privilege',
        reach: 'external',
        reversibility: 'hard',
        scale: 'many',
        note: 'creates a deployment role and bucket with broad rights in the account',
        pathArgs: 'none',
      },
      argv,
    );
  }
  if (sub === 'deploy' || sub === 'watch' || sub === 'import' || sub === 'migrate' || sub === 'rollback') {
    const j: Judgement = {
      capability: 'exec.iac',
      reach: 'external',
      reversibility: 'irreversible',
      scale: all ? 'sweeping' : 'many',
      note: sub === 'watch' ? 'redeploys automatically every time a file changes' : 'creates and replaces real infrastructure',
      pathArgs: 'none',
    };
    if (flagValue(argv, '--require-approval') === 'never' || hasFlag(argv, '--force', '-f')) {
      addNote(j, 'and approval prompts are turned off');
    }
    return withProduction(j, argv);
  }
  if (sub === 'destroy') {
    return withProduction(
      {
        capability: 'exec.iac',
        reach: 'external',
        reversibility: 'irreversible',
        scale: 'sweeping',
        note: 'tears down every resource in the stack',
        pathArgs: 'none',
      },
      argv,
    );
  }
  return { capability: 'exec.iac', reach: 'external', opaque: true, note: 'runs a cdk subcommand this module does not recognise', pathArgs: 'none' };
}

// ---------------------------------------------------------------------------
// pulumi
// ---------------------------------------------------------------------------

function pulumi(argv: string[]): Judgement {
  const words = nonFlags(argv, 1).map((w) => w.toLowerCase());
  const sub = words[0] ?? '';
  const op = words[1] ?? '';
  const skipsPrompt = hasFlag(argv, '--yes', '-y', '--skip-preview', '-f', '--force');
  const showSecrets = hasFlag(argv, '--show-secrets');

  if (sub === '' || sub === 'version' || sub === 'about' || sub === 'whoami' || sub === 'logs' || sub === 'help') {
    return { capability: 'exec.inspect', note: 'prints local pulumi information', pathArgs: 'none' };
  }
  if (sub === 'preview') {
    return {
      capability: 'exec.iac',
      reach: 'network',
      reversibility: 'trivial',
      // Without this the exec.iac default of `sweeping` puts preview two tiers
      // above `terraform plan`, though they are the same cheap question.
      scale: 'single',
      note: 'reads live infrastructure and prints what would change, without changing it',
      pathArgs: 'none',
    };
  }

  if (sub === 'config') {
    if (op === 'set' || op === 'rm' || op === 'set-all' || op === 'rm-all' || op === 'refresh') {
      return { capability: 'fs.write.workspace', reversibility: 'easy', note: 'changes stack configuration in the project files' };
    }
    // Bare `pulumi config` masks secrets, but `config get <key>` decrypts the
    // one value it was asked for whether or not --show-secrets is present.
    if (op === 'get') return credentialRead('prints one configuration value, decrypted if it is a secret');
    if (showSecrets) return credentialRead('prints stack configuration with the secret values decrypted');
    return cloudRead('prints stack configuration');
  }

  if (sub === 'stack') {
    if (op === 'output') {
      return showSecrets
        ? credentialRead('prints stack outputs with the secret values decrypted')
        : {
            capability: 'exec.cloud',
            reach: 'network',
            reversibility: 'trivial',
            exposure: 'reads-secrets',
            note: 'prints stack outputs, which commonly include connection strings',
            pathArgs: 'none',
          };
    }
    if (op === 'export') return credentialRead('dumps the whole state file, including its secret values');
    if (op === 'rm') {
      return withProduction(
        {
          capability: 'exec.iac',
          reach: 'external',
          reversibility: 'irreversible',
          scale: 'many',
          note: 'deletes a stack and the state that tracks its resources',
          pathArgs: 'none',
        },
        argv,
      );
    }
    if (op === 'import') {
      return withProduction(
        { capability: 'exec.iac', reach: 'external', reversibility: 'irreversible', scale: 'many', note: 'overwrites the stack state from a file', pathArgs: 'none' },
        argv,
      );
    }
    if (op === 'select' || op === 'init') {
      const j: Judgement = { capability: 'meta', note: 'switches which stack later commands target', pathArgs: 'none' };
      if (targetsProduction(argv)) addNote(j, 'onto one named like production');
      return j;
    }
    if (op === '' || op === 'ls' || op === 'list' || op === 'history' || op === 'graph' || op === 'unselect') {
      return cloudRead('lists stacks or their history');
    }
    // `rename`, `change-secrets-provider` and friends rewrite how the stack and
    // its secrets are stored, which is not something to guess is a read.
    return withProduction(
      {
        capability: 'exec.iac',
        reach: 'external',
        reversibility: 'hard',
        scale: 'many',
        note: 'changes how a stack or its secrets are stored',
        pathArgs: 'none',
      },
      argv,
    );
  }

  if (sub === 'up' || sub === 'update' || sub === 'destroy' || sub === 'refresh' || sub === 'import' || sub === 'watch' || sub === 'cancel') {
    const note =
      sub === 'destroy'
        ? 'destroys every resource in the stack'
        : sub === 'refresh'
          ? 'rewrites state from live infrastructure, which can drop resources out of it'
          : sub === 'cancel'
            ? 'interrupts an update in flight, which can leave resources half created'
            : sub === 'watch'
              ? 'redeploys automatically every time a file changes'
              : 'creates, changes and replaces real infrastructure';
    const j: Judgement = {
      capability: 'exec.iac',
      reach: 'external',
      reversibility: 'irreversible',
      scale: 'sweeping',
      note,
      pathArgs: 'none',
    };
    if (skipsPrompt && (sub === 'up' || sub === 'update' || sub === 'destroy')) {
      addNote(j, 'and the preview confirmation is skipped');
    }
    return withProduction(j, argv);
  }

  if (sub === 'state') {
    return withProduction(
      {
        capability: 'exec.iac',
        reach: 'external',
        reversibility: 'irreversible',
        scale: 'many',
        note: 'edits state directly, which changes what pulumi believes it owns',
        pathArgs: 'none',
      },
      argv,
    );
  }

  // Pulumi ESC: `env open` resolves and prints every value in an environment.
  if (sub === 'env') {
    // `env run -- cmd` does not print the values, it hands them to another
    // program, and what that program does with them is not visible here.
    if (op === 'run') {
      return {
        capability: 'exec.unknown',
        reach: 'machine',
        reversibility: 'hard',
        exposure: 'can-exfiltrate',
        opaque: true,
        note: 'runs another command with a pulumi environment resolved into it',
      };
    }
    if (op === 'open' || op === 'get') return credentialRead('resolves and prints the values in a pulumi environment');
    if (op === '' || op === 'ls' || op === 'list') return cloudRead('lists pulumi environments');
    // set / rm / edit / init / version tag all rewrite an environment that
    // other stacks and other people read their secrets out of.
    return withProduction(
      {
        capability: 'exec.cloud',
        reach: 'external',
        reversibility: 'hard',
        scale: 'many',
        note: 'changes a shared pulumi environment that other stacks read from',
        pathArgs: 'none',
      },
      argv,
    );
  }

  if (sub === 'new') {
    return { capability: 'exec.pkg', reach: 'machine', reversibility: 'easy', note: 'scaffolds a project and installs its dependencies' };
  }
  if (sub === 'plugin') {
    return { capability: 'exec.pkg', reach: 'machine', reversibility: 'easy', note: 'downloads plugins, which are code that will run on this machine', pathArgs: 'none' };
  }
  if (sub === 'login' || sub === 'logout') {
    return { capability: 'fs.write.outside', reach: 'machine', reversibility: 'easy', note: 'stores or clears a pulumi access token on this machine', pathArgs: 'none' };
  }

  return { capability: 'exec.iac', reach: 'external', opaque: true, note: 'runs a pulumi subcommand this module does not recognise', pathArgs: 'none' };
}

// ---------------------------------------------------------------------------
// object storage: `aws s3`, `gsutil`, `gcloud storage`
// ---------------------------------------------------------------------------

const REMOTE_URI = /^(s3|gs):\/\//i;

/** gsutil's top-level options that take a value, e.g. `gsutil -o a=b cp ...`. */
const GSUTIL_VALUE_FLAGS = new Set(['-o', '-h']);

function objectStorage(words: string[], argv: string[], ctx: KnowledgeCtx): Judgement {
  const op = (words[0] ?? '').toLowerCase();
  const operands = words.slice(1);
  const recursive = hasFlag(argv, '-r', '-R', '--recursive');
  // `--delete` on a sync is the dangerous half: it removes things at the
  // destination that are simply absent from the source.
  const mirrors =
    // `--delete-unmatched-destination-objects` is `gcloud storage rsync`'s
    // spelling of the same thing, and it is the one nobody recognises.
    hasFlag(argv, '--delete', '--delete-removed', '--delete-unmatched-destination-objects') ||
    (op === 'rsync' && argv.some((a, i) => i > 0 && /^-[a-z]*d[a-z]*$/.test(a)));
  const goesPublic = argv.some((a) => /allusers|allauthenticatedusers|public-read/i.test(a));
  // `aws s3 --dryrun` and `gcloud storage --dry-run` print the transfer plan
  // and move nothing. gsutil has no such spelling, so it would simply error.
  if (hasFlag(argv, '--dryrun', '--dry-run')) {
    return cloudRead('a dry run that prints what would be transferred or deleted, without doing it');
  }

  if (op === 'ls' || op === 'list' || op === 'du' || op === 'stat' || op === 'hash' || op === 'ver') {
    return cloudRead('lists objects in cloud storage');
  }
  if (op === 'cat' || op === 'head') {
    return {
      capability: 'exec.cloud',
      reach: 'network',
      reversibility: 'trivial',
      exposure: 'reads-secrets',
      note: 'prints the contents of a stored object, which may hold credentials',
      pathArgs: 'none',
    };
  }
  // A presigned link works for anyone who has it, with no credentials at all.
  if (op === 'presign' || op === 'signurl' || op === 'sign-url') {
    return {
      capability: 'exec.cloud',
      reach: 'external',
      reversibility: 'hard',
      exposure: 'can-exfiltrate',
      note: 'creates a link that lets anyone holding it read the object without credentials',
      pathArgs: 'none',
    };
  }

  if (op === 'cp' || op === 'mv' || op === 'sync' || op === 'rsync') {
    const src = operands[0] ?? '';
    const dst = operands[operands.length - 1] ?? '';
    const srcRemote = REMOTE_URI.test(src);
    const dstRemote = REMOTE_URI.test(dst);

    if (dstRemote && !srcRemote) {
      const abs = ctx.resolve(src);
      const secret = abs ? ctx.isSecret(abs) : false;
      const j: Judgement = {
        capability: 'exec.cloud',
        reach: 'external',
        reversibility: mirrors ? 'irreversible' : 'hard',
        scale: recursive || op === 'sync' || op === 'rsync' ? 'sweeping' : 'single',
        exposure: 'can-exfiltrate',
        note: 'copies local files into cloud storage',
        targets: [{ type: 'service', value: dst }],
      };
      if (secret) addNote(j, 'including a credential file');
      if (goesPublic) addNote(j, 'and makes them readable by anyone');
      if (mirrors) addNote(j, 'and deletes anything at the destination that is missing from the source');
      if (op === 'mv') addNote(j, 'and removes the local copy');
      return withProduction(j, argv);
    }

    if (srcRemote && !dstRemote) {
      const abs = ctx.resolve(dst);
      const outside = abs ? !ctx.inWorkspace(abs) : true;
      // Mirroring *into* a local directory deletes local files that are not in
      // the bucket, which is a filesystem delete wearing a download's clothes.
      if (mirrors) {
        return {
          capability: 'fs.delete',
          reach: outside ? 'machine' : 'workspace',
          reversibility: 'irreversible',
          scale: 'sweeping',
          note: 'mirrors a bucket down and deletes local files that are not in it',
        };
      }
      return {
        capability: outside ? 'fs.write.outside' : 'fs.write.workspace',
        reach: outside ? 'machine' : 'workspace',
        reversibility: 'easy',
        scale: recursive || op === 'sync' || op === 'rsync' ? 'many' : 'single',
        note: outside ? 'downloads objects to a path outside the project' : 'downloads objects into the working tree',
      };
    }

    const j: Judgement = {
      capability: 'exec.cloud',
      reach: 'external',
      reversibility: mirrors ? 'irreversible' : 'hard',
      scale: 'many',
      note: 'copies objects between cloud storage locations',
      pathArgs: 'none',
    };
    if (mirrors) addNote(j, 'and deletes anything at the destination that is missing from the source');
    return withProduction(j, argv);
  }

  if (op === 'rm' || op === 'remove' || op === 'delete' || op === 'rb') {
    // A bare bucket uri, or a recursive flag, means "everything under here".
    const sweeping =
      op === 'rb' ||
      recursive ||
      hasFlag(argv, '--all-versions', '--force') ||
      operands.some((o) => /^(s3|gs):\/\/[^/]+\/?$/.test(o));
    const note =
      op === 'rb'
        ? 'deletes a bucket, and with force it takes every object with it'
        : sweeping
          ? 'deletes every object under the prefix in one call'
          : 'deletes an object from cloud storage';
    return withProduction(
      {
        capability: 'exec.cloud',
        reach: 'external',
        reversibility: 'irreversible',
        scale: sweeping ? 'sweeping' : 'single',
        note,
        pathArgs: 'none',
        targets: operands.filter((o) => REMOTE_URI.test(o)).map((o) => ({ type: 'service' as const, value: o })),
      },
      argv,
    );
  }

  // `gcloud storage buckets|objects|folders <verb>` puts the verb one word
  // later than every other form, so read it. Treating the whole group as "mb"
  // turns `gcloud storage buckets delete gs://prod-data` into "creates a
  // bucket", easily reversible — which is the wrong answer twice over.
  if (op === 'buckets' || op === 'objects' || op === 'managed-folders' || op === 'folders') {
    const verb = (words[1] ?? '').toLowerCase();
    if (verb === 'list' || verb === 'describe') return cloudRead('lists buckets or objects in cloud storage');
    if (verb === 'delete') {
      return withProduction(
        {
          capability: 'exec.cloud',
          reach: 'external',
          reversibility: 'irreversible',
          scale: op === 'buckets' ? 'sweeping' : 'many',
          note: op === 'buckets' ? 'deletes a bucket along with every object stored in it' : 'deletes stored objects',
          pathArgs: 'none',
          targets: words.filter((o) => REMOTE_URI.test(o)).map((o) => ({ type: 'service' as const, value: o })),
        },
        argv,
      );
    }
    if (verb === 'create') {
      return withProduction(
        { capability: 'exec.cloud', reach: 'external', reversibility: 'easy', note: 'creates a bucket', pathArgs: 'none' },
        argv,
      );
    }
    const j: Judgement = {
      capability: 'exec.cloud',
      reach: 'external',
      reversibility: 'hard',
      note: 'changes bucket or object configuration',
      pathArgs: 'none',
    };
    if (goesPublic) {
      j.exposure = 'can-exfiltrate';
      addNote(j, 'in a way that exposes the data to anyone');
    }
    return withProduction(j, argv);
  }
  if (op === 'mb') {
    return withProduction(
      { capability: 'exec.cloud', reach: 'external', reversibility: 'easy', note: 'creates a bucket', pathArgs: 'none' },
      argv,
    );
  }

  const j: Judgement = {
    capability: 'exec.cloud',
    reach: 'external',
    reversibility: 'hard',
    note: 'changes bucket configuration',
    pathArgs: 'none',
  };
  if (goesPublic) {
    j.exposure = 'can-exfiltrate';
    addNote(j, 'in a way that exposes the data to anyone');
  }
  return withProduction(j, argv);
}

// ---------------------------------------------------------------------------
// aws cli v2
// ---------------------------------------------------------------------------

/** Operations whose whole job is to hand back a usable credential. */
const AWS_CREDENTIAL_OPS: Record<string, string[]> = {
  secretsmanager: ['get-secret-value', 'batch-get-secret-value'],
  ssm: ['get-parameter', 'get-parameters', 'get-parameters-by-path'],
  kms: ['decrypt', 'generate-data-key', 'generate-data-key-pair', 'generate-random'],
  sts: ['assume-role', 'assume-role-with-web-identity', 'assume-role-with-saml', 'get-session-token', 'get-federation-token'],
  ecr: ['get-login-password', 'get-authorization-token'],
  'ecr-public': ['get-login-password', 'get-authorization-token'],
  eks: ['get-token'],
  rds: ['generate-db-auth-token'],
  redshift: ['get-cluster-credentials'],
  // Reads like an ordinary `get-`, hands back a working access key pair.
  'sso-oidc': ['create-token'],
  ec2: ['get-password-data'],
  lightsail: ['get-instance-access-details'],
  iam: ['create-access-key', 'create-service-specific-credential', 'create-login-profile', 'update-login-profile', 'reset-service-specific-credential'],
  codeartifact: ['get-authorization-token'],
};

/** Operations that run code somewhere other than this machine. */
const AWS_REMOTE_OPS: Record<string, string[]> = {
  ssm: ['start-session', 'send-command', 'start-automation-execution', 'start-change-request-execution'],
  lambda: ['invoke', 'invoke-async', 'invoke-with-response-stream'],
  ecs: ['execute-command', 'run-task', 'start-task'],
  ec2: ['run-instances'],
  codebuild: ['start-build', 'start-build-batch', 'retry-build'],
  glue: ['start-job-run'],
  stepfunctions: ['start-execution', 'start-sync-execution'],
  batch: ['submit-job'],
};

/**
 * `aws` options that take a separate value and may appear before the service
 * name. Without stripping these, `aws --profile prod s3 rm ...` is read as
 * service `prod`, operation `s3`, and none of the tables above apply.
 */
const AWS_VALUE_FLAGS = new Set([
  '--profile', '--region', '--output', '--endpoint-url', '--query', '--color',
  '--ca-bundle', '--cli-read-timeout', '--cli-connect-timeout', '--cli-binary-format',
]);

/** Services where a delete takes stored data with it. */
const AWS_DATA_SERVICES = new Set([
  's3', 's3api', 'rds', 'dynamodb', 'efs', 'elasticache', 'redshift', 'docdb',
  'neptune', 'backup', 'glacier', 'timestream', 'memorydb', 'qldb', 'fsx',
]);

const AWS_READ_VERB = /^(describe|list|get|head|search|lookup|scan|query|select|simulate|test|validate|check|estimate|preview|batch-get|filter|count|export)-/;
const AWS_DELETE_VERB = /^(delete|terminate|remove|revoke|deregister|purge|destroy|expire|retire|erase|empty)-/;
const AWS_DISRUPT_VERB = /^(stop|cancel|abort|disable|detach|disassociate|reject|suspend|deactivate|reboot|reset|evict|fail)-/;
const AWS_WRITE_VERB = /^(create|put|update|modify|set|add|attach|associate|enable|register|start|run|invoke|publish|send|copy|import|upload|apply|replace|restore|tag|untag|promote|move|assign|activate|accept|initiate|request|provision|deploy|configure|allocate|authorize|batch-write|transact-write|generate)-/;
const AWS_BARE_READS = new Set(['wait', 'help', 'ls', 'tail', 'status', 'history', 'version', 'describe', 'list', 'show']);

/** iam-shaped services: changing these changes who can do what. */
const AWS_PRIVILEGE_SERVICES = new Set(['iam', 'organizations', 'sso-admin', 'identitystore', 'ram']);

/**
 * AWS read operations whose *output* contains credentials.
 *
 * These all use a `describe-` or `get-` verb, so the generic read heuristic
 * classifies them as harmless — but EC2 user-data is the instance bootstrap
 * script (routinely containing keys), a Lambda or ECS description carries the
 * environment block, and a CloudFormation template comes with its parameters.
 * Printing one of these to an agent's context is a credential read.
 */
const AWS_PRINTS_CREDENTIALS: { service: string; op: RegExp; what: string }[] = [
  { service: 'ec2', op: /^describe-instance-attribute$/, what: 'instance user-data, which usually contains bootstrap scripts and their keys' },
  { service: 'ec2', op: /^get-password-data$/, what: 'the administrator password for an instance' },
  { service: 'lambda', op: /^(get-function|get-function-configuration)$/, what: "a function's environment variables" },
  { service: 'ecs', op: /^describe-task-definition$/, what: "a task definition's environment variables" },
  { service: 'cloudformation', op: /^(get-template|describe-stacks|get-template-summary)$/, what: 'a template and its parameters' },
  { service: 'ssm', op: /^(get-parameter|get-parameters|get-parameters-by-path)$/, what: 'stored parameter values' },
  { service: 'secretsmanager', op: /^get-secret-value$/, what: 'a stored secret' },
  { service: 'apigateway', op: /^get-api-keys$/, what: 'API keys' },
  { service: 'rds', op: /^describe-db-instances$/, what: 'database endpoints and configuration' },
];

function awsPrintsCredentials(service: string, op: string): string | undefined {
  for (const r of AWS_PRINTS_CREDENTIALS) {
    if (r.service === service && r.op.test(op)) return r.what;
  }
  return undefined;
}

function aws(argv: string[], ctx: KnowledgeCtx): Judgement {
  // Checked before the verb heuristic: these are read verbs, and the whole
  // point is that reading them hands over a credential.
  {
    const svc = (argv[1] ?? '').toLowerCase();
    const operation = (argv[2] ?? '').toLowerCase();
    const what = awsPrintsCredentials(svc, operation);
    if (what) {
      return {
        capability: 'secret.read',
        reach: 'external',
        exposure: 'can-exfiltrate',
        note: `prints ${what}`,
        pathArgs: 'none',
      };
    }
  }

  const words = nonFlags(dropOptionValues(argv, AWS_VALUE_FLAGS), 1);
  const service = (words[0] ?? '').toLowerCase();
  const op = (words[1] ?? '').toLowerCase();
  // `--dry-run` is honoured server side by the services that accept it: the
  // call checks permissions and returns without doing the thing.
  const dryRun = hasFlag(argv, '--dry-run', '--dryrun');

  if (service === '' || service === 'help') {
    return { capability: 'exec.inspect', note: 'prints aws cli help', pathArgs: 'none' };
  }

  // Bare `aws s3` prints help; only pass it on once there is an operation.
  if (service === 's3') {
    if (op === '') return { capability: 'exec.inspect', note: 'prints aws s3 help', pathArgs: 'none' };
    return objectStorage(words.slice(1), argv, ctx);
  }

  // `aws configure` is the local credential file, not an api call.
  if (service === 'configure') {
    if (op === 'get' || op === 'export-credentials') {
      return {
        capability: 'secret.read',
        reach: 'machine',
        reversibility: 'trivial',
        exposure: 'can-exfiltrate',
        note: 'prints a stored aws credential',
        pathArgs: 'none',
      };
    }
    if (op === 'list' || op === 'list-profiles') return { capability: 'exec.inspect', note: 'lists configured profiles', pathArgs: 'none' };
    return {
      capability: 'fs.write.outside',
      reach: 'machine',
      reversibility: 'easy',
      note: 'writes credentials into the aws configuration on this machine',
      pathArgs: 'none',
    };
  }
  if (service === 'sso') {
    // The rest of the group only touches the local cache, but this one prints
    // an access key, secret key and session token for the chosen role.
    if (op === 'get-role-credentials') return credentialRead('prints a live set of aws access keys for a role');
    return {
      capability: 'fs.write.outside',
      reach: 'machine',
      reversibility: 'easy',
      note: 'signs in and caches a session token on this machine',
      pathArgs: 'none',
    };
  }

  // Harmless and extremely common: "who am I".
  if (service === 'sts' && op === 'get-caller-identity') {
    return cloudRead('shows which identity the cli is using');
  }

  const credentialOps = AWS_CREDENTIAL_OPS[service];
  if (credentialOps && credentialOps.includes(op)) {
    // Plain SecureString reads come back encrypted; --with-decryption is what
    // turns them into plaintext on the terminal.
    if (service === 'ssm' && !hasFlag(argv, '--with-decryption')) {
      return {
        capability: 'secret.read',
        reach: 'network',
        reversibility: 'trivial',
        exposure: 'reads-secrets',
        note: 'reads parameter store values, which are often credentials',
        pathArgs: 'none',
      };
    }
    if (service === 'iam') {
      return withProduction(
        {
          capability: 'secret.read',
          reach: 'external',
          reversibility: 'hard',
          exposure: 'can-exfiltrate',
          note: 'mints a long-lived credential and prints its secret half',
          pathArgs: 'none',
        },
        argv,
      );
    }
    return credentialRead('prints a live credential');
  }

  const remoteOps = AWS_REMOTE_OPS[service];
  if (remoteOps && remoteOps.includes(op) && !dryRun) {
    const fleetWide = op === 'send-command' && (hasFlag(argv, '--targets') || hasFlag(argv, '--instance-ids'));
    return withProduction(
      {
        capability: 'exec.remote',
        reach: 'external',
        reversibility: 'hard',
        scale: fleetWide ? 'sweeping' : 'many',
        opaque: true,
        note: 'runs code on cloud machines, and what that code does is not visible here',
        pathArgs: 'none',
      },
      argv,
    );
  }

  // Writing a kubeconfig is a local file write, but it is the file that decides
  // which cluster every later kubectl talks to.
  if (service === 'eks' && op === 'update-kubeconfig') {
    const j: Judgement = {
      capability: 'fs.write.outside',
      reach: 'machine',
      reversibility: 'easy',
      note: 'writes cluster credentials into the local kubeconfig',
      pathArgs: 'none',
    };
    if (targetsProduction(argv)) addNote(j, 'for a cluster named like production');
    return j;
  }

  if (AWS_PRIVILEGE_SERVICES.has(service)) {
    if (AWS_READ_VERB.test(op) || AWS_BARE_READS.has(op)) return cloudRead('reads permission settings');
    if (AWS_DELETE_VERB.test(op) || AWS_DISRUPT_VERB.test(op)) {
      return withProduction(
        {
          capability: 'exec.privilege',
          reach: 'external',
          reversibility: 'irreversible',
          scale: 'many',
          note: 'removes cloud permissions, which can lock people or services out',
          pathArgs: 'none',
        },
        argv,
      );
    }
    return withProduction(
      {
        capability: 'exec.privilege',
        reach: 'external',
        reversibility: 'hard',
        scale: 'many',
        note: 'grants or changes who can act in this cloud account',
        pathArgs: 'none',
      },
      argv,
    );
  }

  if (AWS_READ_VERB.test(op) || AWS_BARE_READS.has(op) || op === '') {
    return cloudRead('reads cloud state');
  }
  if (dryRun) {
    return cloudRead('a dry run that checks permissions without making the change');
  }
  if (AWS_DELETE_VERB.test(op)) {
    const data = AWS_DATA_SERVICES.has(service);
    const stack = service === 'cloudformation' || service === 'cloudcontrol';
    return withProduction(
      {
        capability: 'exec.cloud',
        reach: 'external',
        reversibility: 'irreversible',
        scale: data || stack ? 'sweeping' : 'many',
        note: stack
          ? 'deletes every resource in the stack'
          : data
            ? 'deletes a cloud resource, and the data stored in it goes too'
            : 'deletes a cloud resource',
        pathArgs: 'none',
      },
      argv,
    );
  }
  if (AWS_DISRUPT_VERB.test(op)) {
    return withProduction(
      {
        capability: 'exec.cloud',
        reach: 'external',
        reversibility: 'hard',
        scale: 'many',
        note: 'stops, detaches or disables a running cloud resource',
        pathArgs: 'none',
      },
      argv,
    );
  }
  if (AWS_WRITE_VERB.test(op) || op === 'deploy' || op === 'publish' || op === 'sync' || op === 'push') {
    return withProduction(
      {
        capability: 'exec.cloud',
        reach: 'external',
        reversibility: 'hard',
        scale: service === 'cloudformation' ? 'sweeping' : 'many',
        note: service === 'cloudformation' ? 'creates or replaces every resource in a stack' : 'changes cloud resources',
        pathArgs: 'none',
      },
      argv,
    );
  }

  return withProduction(
    {
      capability: 'exec.cloud',
      reach: 'external',
      opaque: true,
      note: 'runs an aws operation whose effect cannot be told from its name',
      pathArgs: 'none',
    },
    argv,
  );
}

// ---------------------------------------------------------------------------
// bigquery
// ---------------------------------------------------------------------------

function bq(argv: string[]): Judgement {
  const words = nonFlags(argv, 1).map((w) => w.toLowerCase());
  const sub = words[0] ?? '';

  if (sub === 'query') {
    if (hasFlag(argv, '--dry_run', '--dry-run')) return cloudRead('estimates a query without running it');
    // The sql decides whether this is a select or a DELETE, and we are not
    // going to parse sql to find out.
    return withProduction(
      {
        capability: 'exec.db',
        reach: 'external',
        reversibility: 'hard',
        scale: 'many',
        opaque: true,
        note: 'runs sql, which may read or may modify tables',
        pathArgs: 'none',
      },
      argv,
    );
  }
  if (sub === 'ls' || sub === 'show' || sub === 'head' || sub === 'get-iam-policy' || sub === 'version' || sub === 'help') {
    return cloudRead('reads dataset or table metadata');
  }
  if (sub === 'rm') {
    return withProduction(
      {
        capability: 'exec.db',
        reach: 'external',
        reversibility: 'irreversible',
        scale: hasFlag(argv, '-r', '--recursive') ? 'sweeping' : 'many',
        note: 'deletes a table or dataset along with everything in it',
        pathArgs: 'none',
      },
      argv,
    );
  }
  return withProduction(
    { capability: 'exec.db', reach: 'external', reversibility: 'hard', scale: 'many', note: 'changes bigquery data or configuration', pathArgs: 'none' },
    argv,
  );
}

// ---------------------------------------------------------------------------
// gcloud
// ---------------------------------------------------------------------------

const GCLOUD_READ_VERBS = new Set([
  'list', 'describe', 'get', 'get-iam-policy', 'read', 'tail', 'info', 'version',
  'help', 'search', 'check', 'validate', 'print', 'show', 'diagnose', 'test',
  'wait', 'status', 'preview', 'lookup', 'query',
]);
const GCLOUD_WRITE_VERBS = new Set([
  'create', 'update', 'set', 'add', 'enable', 'disable', 'import', 'attach',
  'start', 'stop', 'restart', 'reset', 'patch', 'apply', 'call', 'execute',
  'run', 'submit', 'deploy', 'promote', 'migrate', 'rollback', 'replace',
  'resize', 'scale', 'update-traffic', 'activate', 'suspend', 'restore',
]);
const GCLOUD_DELETE_VERBS = new Set([
  'delete', 'destroy', 'remove', 'purge', 'uninstall', 'clear', 'undeploy',
  'abandon', 'drain', 'detach', 'revoke', 'cancel', 'kill', 'expire',
]);

function gcloud(argv: string[], ctx: KnowledgeCtx): Judgement {
  const words = nonFlags(argv, 1).map((w) => w.toLowerCase());
  const path = words.join(' ');

  if (words[0] === 'storage' || ((words[0] === 'alpha' || words[0] === 'beta') && words[1] === 'storage')) {
    return objectStorage(words.slice(words[0] === 'storage' ? 1 : 2), argv, ctx);
  }

  // --- things that print credentials ---
  if (/\bauth\b.*\bprint-(access|identity|refresh)-token\b/.test(path)) {
    return credentialRead('prints an access token that grants this account rights until it expires');
  }
  if (/\bsecrets\b.*\bversions\b.*\baccess\b/.test(path)) {
    return credentialRead('prints the contents of a stored secret');
  }
  if (/\bkms\b.*\bdecrypt\b/.test(path)) {
    return credentialRead('decrypts ciphertext and prints the plaintext');
  }
  // A service account key is a permanent credential file; once created it can
  // be copied anywhere and rarely gets rotated.
  if (/\biam\b.*\bservice-accounts\b.*\bkeys\b.*\bcreate\b/.test(path)) {
    return withProduction(
      {
        capability: 'secret.read',
        reach: 'external',
        reversibility: 'hard',
        exposure: 'can-exfiltrate',
        note: 'creates a long-lived service account key and writes the private half to disk',
        pathArgs: 'none',
      },
      argv,
    );
  }

  // --- local credential and configuration handling ---
  if (words[0] === 'auth') {
    if (words[1] === 'list' || words[1] === 'describe') return { capability: 'exec.inspect', note: 'lists signed-in accounts', pathArgs: 'none' };
    return {
      capability: 'fs.write.outside',
      reach: 'machine',
      reversibility: 'easy',
      note: 'stores or clears google credentials on this machine',
      pathArgs: 'none',
    };
  }
  if (words[0] === 'config') {
    if (words[1] === 'list' || words[1] === 'get' || words[1] === 'get-value' || words[1] === 'describe') {
      return { capability: 'exec.inspect', note: 'prints the active gcloud configuration', pathArgs: 'none' };
    }
    const j: Judgement = { capability: 'meta', reach: 'machine', note: 'changes which project and account later commands use', pathArgs: 'none' };
    if (targetsProduction(argv)) addNote(j, 'pointing them at something named like production');
    return j;
  }
  if (words[0] === 'components') {
    return { capability: 'exec.pkg', reach: 'machine', reversibility: 'easy', note: 'installs or updates gcloud components, which are code that will run locally', pathArgs: 'none' };
  }

  // --- getting a shell somewhere else ---
  if (/\b(ssh|scp|start-iap-tunnel|interactive)\b/.test(path)) {
    return withProduction(
      {
        capability: 'exec.remote',
        reach: 'external',
        reversibility: 'hard',
        opaque: true,
        note: 'opens a session on a cloud machine, and what happens inside it is not visible here',
        pathArgs: 'none',
      },
      argv,
    );
  }
  if (/\bsql\b.*\bconnect\b/.test(path)) {
    return withProduction(
      { capability: 'exec.db', reach: 'external', reversibility: 'hard', opaque: true, note: 'opens a shell on a managed database', pathArgs: 'none' },
      argv,
    );
  }

  // --- permission changes ---
  if (/\b(add|remove|set)-iam-policy-binding\b/.test(path) || /\biam\b.*\b(roles|service-accounts)\b.*\b(create|update|delete|add|remove)\b/.test(path)) {
    const removing = /\bremove-iam-policy-binding\b|\bdelete\b/.test(path);
    return withProduction(
      {
        capability: 'exec.privilege',
        reach: 'external',
        reversibility: removing ? 'irreversible' : 'hard',
        scale: 'many',
        note: removing ? 'removes cloud permissions, which can lock people or services out' : 'grants rights on cloud resources',
        pathArgs: 'none',
      },
      argv,
    );
  }

  // Kubeconfig for a GKE cluster: local write, but it aims kubectl at a cluster.
  if (/\bcontainer\b.*\bclusters\b.*\bget-credentials\b/.test(path)) {
    const j: Judgement = {
      capability: 'fs.write.outside',
      reach: 'machine',
      reversibility: 'easy',
      note: 'writes cluster credentials into the local kubeconfig',
      pathArgs: 'none',
    };
    if (targetsProduction(argv)) addNote(j, 'for a cluster named like production');
    return j;
  }

  // The verb is whichever known word comes first; gcloud puts the resource
  // group before it (`gcloud compute instances delete NAME`).
  //
  // A destructive or writing word wins over a reading one wherever it appears,
  // because resource groups are named things like `test` and `preview`: taking
  // the first match outright made `gcloud firebase test android run` and
  // `gcloud preview app deploy` look like queries.
  // Cloud Run's product group is spelled the same as the verb `run`, so
  // `gcloud run services list` looked like an execution. Skip the leading word
  // when it is the product name and there is something after it to read.
  const verbWords = words[0] === 'run' && words.length > 1 ? words.slice(1) : words;
  let verb = '';
  for (const w of verbWords) {
    if (GCLOUD_DELETE_VERBS.has(w) || GCLOUD_WRITE_VERBS.has(w)) {
      verb = w;
      break;
    }
  }
  if (verb === '') {
    for (const w of verbWords) {
      if (GCLOUD_READ_VERBS.has(w)) {
        verb = w;
        break;
      }
    }
  }

  if (GCLOUD_READ_VERBS.has(verb)) return cloudRead('reads cloud state');
  if (GCLOUD_DELETE_VERBS.has(verb)) {
    const wholeProject = /\bprojects\b/.test(path);
    return withProduction(
      {
        capability: 'exec.cloud',
        reach: 'external',
        reversibility: 'irreversible',
        scale: wholeProject ? 'sweeping' : 'many',
        note: wholeProject ? 'schedules an entire cloud project for deletion' : 'deletes a cloud resource and whatever it stores',
        pathArgs: 'none',
      },
      argv,
    );
  }
  if (GCLOUD_WRITE_VERBS.has(verb)) {
    const deploying = verb === 'deploy' || verb === 'submit' || verb === 'promote' || verb === 'update-traffic';
    return withProduction(
      {
        capability: 'exec.cloud',
        reach: 'external',
        reversibility: 'hard',
        scale: deploying ? 'sweeping' : 'many',
        note: deploying ? 'ships a new version of a running service' : 'changes cloud resources',
        pathArgs: 'none',
      },
      argv,
    );
  }

  return withProduction(
    { capability: 'exec.cloud', reach: 'external', opaque: true, note: 'runs a gcloud command whose effect cannot be told from its name', pathArgs: 'none' },
    argv,
  );
}

// ---------------------------------------------------------------------------
// azure cli
// ---------------------------------------------------------------------------

const AZ_READ_VERBS = new Set([
  'show', 'list', 'get', 'exists', 'check-name', 'validate', 'what-if',
  'version', 'help', 'wait', 'query', 'preview', 'export', 'diagnose',
]);
const AZ_WRITE_VERBS = new Set([
  'create', 'update', 'set', 'add', 'deploy', 'publish', 'start', 'restart',
  'scale', 'import', 'sync', 'enable', 'assign', 'attach', 'swap', 'restore',
  'browse', 'config', 'upload', 'apply', 'invoke',
]);
const AZ_DELETE_VERBS = new Set([
  'delete', 'remove', 'purge', 'destroy', 'stop', 'deallocate', 'down',
  'disable', 'detach', 'revoke', 'cancel', 'reset',
]);

function az(argv: string[]): Judgement {
  const words = nonFlags(argv, 1).map((w) => w.toLowerCase());
  const path = words.join(' ');

  if (/\bkeyvault\b.*\b(secret|key|certificate)\b.*\b(show|download|backup)\b/.test(path)) {
    return credentialRead('prints or downloads a value stored in key vault');
  }
  if (/\baccount\b.*\bget-access-token\b/.test(path)) {
    return credentialRead('prints an access token that grants this account rights until it expires');
  }
  // A large family of azure reads is spelled `list` or `show` and hands back
  // the actual key: storage account keys, acr admin passwords, redis/cosmos/
  // servicebus keys, publishing credentials, and app settings. Matching on the
  // verb alone files all of these as ordinary cloud reads.
  if (
    /\b(keys?\s+list|list-keys|list-account-sas|list-service-sas|credential\s+show|show-connection-string|list-connection-strings?|list-publishing-credentials|list-publishing-profiles|appsettings\s+list)\b/.test(
      path,
    )
  ) {
    return credentialRead('prints a live key, password or connection string for the resource');
  }
  // `create-for-rbac` both mints a client secret and grants it a role.
  if (/\bad\b.*\b(create-for-rbac|credential reset)\b/.test(path)) {
    return withProduction(
      {
        capability: 'secret.read',
        reach: 'external',
        reversibility: 'hard',
        exposure: 'can-exfiltrate',
        note: 'creates a service principal secret and prints it',
        pathArgs: 'none',
      },
      argv,
    );
  }
  if (/\brole\b.*\b(assignment|definition)\b/.test(path) && !/\b(list|show)\b/.test(path)) {
    return withProduction(
      { capability: 'exec.privilege', reach: 'external', reversibility: 'hard', scale: 'many', note: 'changes who can act on azure resources', pathArgs: 'none' },
      argv,
    );
  }
  if (/\b(vm run-command|vmss run-command|container exec|webapp ssh|ssh vm|aks command invoke)\b/.test(path)) {
    return withProduction(
      {
        capability: 'exec.remote',
        reach: 'external',
        reversibility: 'hard',
        opaque: true,
        note: 'runs a command on a cloud machine, and what that command does is not visible here',
        pathArgs: 'none',
      },
      argv,
    );
  }
  if (/\baks\b.*\bget-credentials\b/.test(path) || /\bacr\b.*\blogin\b/.test(path)) {
    return { capability: 'fs.write.outside', reach: 'machine', reversibility: 'easy', note: 'writes cluster or registry credentials onto this machine', pathArgs: 'none' };
  }
  if (words[0] === 'login' || words[0] === 'logout') {
    return { capability: 'fs.write.outside', reach: 'machine', reversibility: 'easy', note: 'stores or clears azure credentials on this machine', pathArgs: 'none' };
  }
  if (words[0] === 'account' && words[1] === 'set') {
    const j: Judgement = { capability: 'meta', reach: 'machine', note: 'changes which subscription later commands use', pathArgs: 'none' };
    if (targetsProduction(argv)) addNote(j, 'pointing them at one named like production');
    return j;
  }
  // Deleting a resource group deletes everything anyone ever put in it.
  if (/^group delete\b/.test(path)) {
    return withProduction(
      {
        capability: 'exec.cloud',
        reach: 'external',
        reversibility: 'irreversible',
        scale: 'sweeping',
        note: 'deletes a resource group and every resource inside it',
        pathArgs: 'none',
      },
      argv,
    );
  }

  let verb = '';
  for (const w of words) {
    if (AZ_DELETE_VERBS.has(w) || AZ_WRITE_VERBS.has(w) || AZ_READ_VERBS.has(w) || /^(get|list|show)-/.test(w)) {
      verb = /^(get|list|show)-/.test(w) ? 'show' : w;
      break;
    }
  }

  if (AZ_READ_VERBS.has(verb)) return cloudRead('reads azure state');
  if (AZ_DELETE_VERBS.has(verb)) {
    return withProduction(
      {
        capability: 'exec.cloud',
        reach: 'external',
        reversibility: verb === 'stop' || verb === 'disable' || verb === 'deallocate' ? 'hard' : 'irreversible',
        scale: 'many',
        note: verb === 'stop' || verb === 'disable' || verb === 'deallocate' ? 'stops a running azure resource' : 'deletes an azure resource and whatever it stores',
        pathArgs: 'none',
      },
      argv,
    );
  }
  if (AZ_WRITE_VERBS.has(verb)) {
    const deploying = /\bdeployment\b/.test(path) || verb === 'deploy';
    return withProduction(
      {
        capability: 'exec.cloud',
        reach: 'external',
        reversibility: 'hard',
        scale: deploying ? 'sweeping' : 'many',
        note: deploying ? 'applies a template that creates or replaces many resources' : 'changes azure resources',
        pathArgs: 'none',
      },
      argv,
    );
  }

  return withProduction(
    { capability: 'exec.cloud', reach: 'external', opaque: true, note: 'runs an azure command whose effect cannot be told from its name', pathArgs: 'none' },
    argv,
  );
}

// ---------------------------------------------------------------------------
// kubectl / oc
// ---------------------------------------------------------------------------

const KUBE_READ = new Set([
  'get', 'describe', 'logs', 'log', 'top', 'explain', 'api-resources',
  'api-versions', 'version', 'cluster-info', 'diff', 'events', 'wait',
  'kustomize', 'completion', 'options', 'help', 'status',
]);
const KUBE_WRITE = new Set([
  'apply', 'create', 'patch', 'edit', 'set', 'scale', 'rollout', 'annotate',
  'label', 'expose', 'autoscale', 'cordon', 'uncordon', 'taint', 'rollback',
  'new-app', 'new-project', 'import', 'wait-for',
]);
const KUBE_DESTROY = new Set(['delete', 'drain', 'evict', 'prune', 'destroy']);
const KUBE_REMOTE = new Set(['exec', 'attach', 'port-forward', 'proxy', 'debug', 'run', 'rsh', 'rsync']);

/** Resources whose deletion takes data or a whole environment with it. */
const KUBE_HEAVY_TARGETS = /^(namespace|ns|persistentvolumeclaim|pvc|persistentvolume|pv|statefulset|sts|crd|customresourcedefinition|node)s?(\/|$|\.)/;

/**
 * kubectl options that take a separate value and routinely come before the
 * subcommand. `--dry-run` is deliberately absent: its value is optional, so
 * skipping the next token would swallow the verb.
 */
const KUBE_VALUE_FLAGS = new Set([
  '-n', '--namespace', '--context', '--cluster', '--user', '--kubeconfig',
  '-o', '--output', '-f', '--filename', '-k', '--kustomize', '-l', '--selector',
  '--server', '--token', '--as', '--as-group', '--field-selector', '-c', '--container',
]);

function kubectl(argv: string[]): Judgement {
  const words = nonFlags(dropOptionValues(argv, KUBE_VALUE_FLAGS), 1).map((w) => w.toLowerCase());
  const sub = words[0] ?? '';
  const rest = words.slice(1);
  // `--dry-run=client` and `=server` both stop short of persisting anything.
  const dryRun = hasFlag(argv, '--dry-run') && flagValue(argv, '--dry-run') !== 'none';
  const explicitContext = flagValue(argv, '--context') !== undefined;

  if (sub === '' || sub === 'version' || sub === 'help' || sub === 'options') {
    return { capability: 'exec.inspect', note: 'prints client information', pathArgs: 'none' };
  }

  // Kubeconfig handling is local file work, but `use-context` decides which
  // cluster every later command in the session hits.
  if (sub === 'config') {
    const op = rest[0] ?? '';
    if (op === 'view') {
      if (hasFlag(argv, '--raw')) {
        return {
          capability: 'secret.read',
          reach: 'machine',
          reversibility: 'trivial',
          exposure: 'can-exfiltrate',
          note: 'prints the kubeconfig including client certificates and tokens',
          pathArgs: 'none',
        };
      }
      return { capability: 'fs.read.outside', reach: 'machine', note: 'prints the kubeconfig with credentials redacted', pathArgs: 'none' };
    }
    if (op === 'current-context' || op === 'get-contexts' || op === 'get-clusters') {
      return { capability: 'exec.inspect', note: 'lists the configured clusters', pathArgs: 'none' };
    }
    const j: Judgement = {
      capability: 'fs.write.outside',
      reach: 'machine',
      reversibility: 'easy',
      note: op === 'use-context' ? 'switches which cluster later commands talk to' : 'edits the local kubeconfig',
      pathArgs: 'none',
    };
    if (targetsProduction(argv)) addNote(j, 'onto one named like production');
    return j;
  }

  // Secret objects are only base64 encoded, so any output format that prints
  // their data prints the credential itself.
  // Resource lists are comma separated, so split before matching: without this
  // `kubectl get all,secrets -o yaml` hides the secrets behind the `all`.
  const touchesSecrets = rest.some((w) => w.split(',').some((r) => /^secrets?(\/|$|\.)/.test(r)));
  // `-o jsonpath={.data.password}` prints the value just as surely as `-o yaml`
  // does, so the separated form has to match on prefix, not equality.
  const dumpsValues =
    argv.some((a) => /^-o=?(yaml|json|jsonpath|go-template|template|custom-columns)/.test(a)) ||
    hasFlag(argv, '--template') ||
    /^(yaml|json|jsonpath|go-template|template|custom-columns)/.test(flagValue(argv, '-o', '--output') ?? '');

  if (KUBE_READ.has(sub)) {
    if (touchesSecrets && (sub === 'get' || sub === 'describe')) {
      if (dumpsValues) return credentialRead('prints secret objects, whose values are only base64 encoded');
      return {
        capability: 'exec.cloud',
        reach: 'network',
        reversibility: 'trivial',
        exposure: 'reads-secrets',
        note: 'lists secret objects in the cluster',
        pathArgs: 'none',
      };
    }
    if (sub === 'logs' || sub === 'log') return cloudRead('streams container logs out of the cluster');
    return cloudRead('reads cluster state');
  }
  if (sub === 'auth') {
    // `auth can-i` and `auth whoami` ask questions. `auth reconcile` is the odd
    // one out: it writes the roles and bindings in a manifest into the cluster,
    // which is a permission change wearing a read's subcommand.
    if (rest[0] === 'reconcile') {
      return withProduction(
        {
          capability: 'exec.privilege',
          reach: 'external',
          reversibility: 'hard',
          scale: 'many',
          note: 'creates or widens the rbac roles and bindings named in a manifest',
          pathArgs: 'auto',
        },
        argv,
      );
    }
    return cloudRead('checks what this account is allowed to do');
  }

  if (KUBE_REMOTE.has(sub)) {
    if (sub === 'run' && dryRun) return cloudRead('renders a pod definition without creating it');
    const note =
      sub === 'port-forward' || sub === 'proxy'
        ? 'opens a tunnel between this machine and the cluster network'
        : sub === 'run'
          ? 'starts a container in the cluster'
          : sub === 'rsync'
            ? 'copies files between this machine and a running container'
            : 'runs a command inside a running container, and what it does there is not visible here';
    return withProduction(
      {
        capability: 'exec.remote',
        reach: 'external',
        reversibility: 'hard',
        scale: 'single',
        opaque: sub !== 'port-forward' && sub !== 'proxy',
        note,
        pathArgs: 'none',
      },
      argv,
    );
  }

  if (sub === 'cp') {
    // Direction is `pod:path` on one side; either way a file crosses the boundary.
    return withProduction(
      { capability: 'exec.remote', reach: 'external', reversibility: 'hard', note: 'copies files in or out of a running container' },
      argv,
    );
  }

  if (KUBE_DESTROY.has(sub)) {
    if (dryRun) return cloudRead('reports what would be deleted without deleting it');
    const sweeping =
      hasFlag(argv, '--all', '--all-namespaces', '-A') ||
      flagValue(argv, '-l', '--selector') !== undefined ||
      rest.some((w) => KUBE_HEAVY_TARGETS.test(w));
    const note =
      sub === 'drain'
        ? 'evicts every pod off a node'
        : rest.some((w) => /^(namespace|ns)s?(\/|$)/.test(w))
          ? 'deletes a namespace and everything inside it'
          : rest.some((w) => /^(persistentvolumeclaim|pvc|persistentvolume|pv)s?(\/|$)/.test(w))
            ? 'deletes storage volumes, and the data on them goes too'
            : 'deletes running workloads from the cluster';
    const j: Judgement = {
      capability: 'exec.cloud',
      reach: 'external',
      reversibility: 'irreversible',
      scale: sweeping ? 'sweeping' : 'many',
      note,
      pathArgs: 'none',
    };
    if (!explicitContext) addNote(j, 'in whichever cluster the current context points at');
    return withProduction(j, argv);
  }

  if (KUBE_WRITE.has(sub) || sub === 'replace' || sub === 'adm') {
    if (dryRun) return cloudRead('renders the change without sending it to the cluster');
    // `oc adm` is the cluster-administration surface.
    if (sub === 'adm') {
      return withProduction(
        { capability: 'exec.privilege', reach: 'external', reversibility: 'hard', scale: 'many', note: 'performs a cluster administration action', pathArgs: 'none' },
        argv,
      );
    }
    const forced = sub === 'replace' && hasFlag(argv, '--force');
    const manifests = [flagValue(argv, '-f', '--filename'), flagValue(argv, '-k', '--kustomize')].filter(
      (v): v is string => typeof v === 'string',
    );
    // `hostOf` reads any `name.ext` as a bare hostname, so without the scheme
    // test every `-f deployment.yaml` claimed to be fetched over the network
    // and filed the filename as a host target. kubectl only accepts real urls.
    const fromNetwork = manifests.filter((m) => /^[a-z][a-z0-9+.-]*:\/\//i.test(m) && hostOf(m) !== undefined);
    const fromStdin = manifests.includes('-');

    const j: Judgement = {
      capability: 'exec.cloud',
      reach: 'external',
      reversibility: forced ? 'irreversible' : 'hard',
      scale: hasFlag(argv, '-R', '--recursive', '--all') ? 'sweeping' : 'many',
      note: forced
        ? 'deletes and recreates the resource rather than updating it'
        : sub === 'rollout'
          ? 'restarts or rolls back a running deployment'
          : 'creates or changes workloads running in the cluster',
      pathArgs: manifests.length > 0 ? 'auto' : 'none',
    };
    if (fromNetwork.length > 0) {
      addNote(j, 'from a manifest fetched over the network');
      j.targets = fromNetwork.map((m) => ({ type: 'host' as const, value: hostOf(m) ?? m }));
    }
    if (fromStdin) {
      j.opaque = true;
      addNote(j, 'from a manifest piped in, whose contents are not visible here');
    }
    // Secrets created on the command line end up in shell history too.
    if (touchesSecrets && sub === 'create') addNote(j, 'and stores a credential in the cluster');
    if (!explicitContext) addNote(j, 'in whichever cluster the current context points at');
    return withProduction(j, argv);
  }

  if (sub === 'login' || sub === 'logout') {
    return { capability: 'fs.write.outside', reach: 'machine', reversibility: 'easy', note: 'stores or clears a cluster token on this machine', pathArgs: 'none' };
  }
  if (sub === 'project' || sub === 'ctx' || sub === 'ns') {
    const j: Judgement = { capability: 'meta', note: 'switches which cluster or namespace later commands target', pathArgs: 'none' };
    if (targetsProduction(argv)) addNote(j, 'onto one named like production');
    return j;
  }

  return withProduction(
    { capability: 'exec.cloud', reach: 'external', opaque: true, note: 'runs a kubectl subcommand this module does not recognise', pathArgs: 'none' },
    argv,
  );
}

// ---------------------------------------------------------------------------
// helm
// ---------------------------------------------------------------------------

/** helm options that take a separate value and often precede the subcommand. */
const HELM_VALUE_FLAGS = new Set([
  '-n', '--namespace', '--kube-context', '--kubeconfig', '-f', '--values',
  '--set', '--set-string', '--set-file', '--set-json', '--version', '--repo',
  '-o', '--output', '--post-renderer', '--description', '--timeout',
]);

function helm(argv: string[]): Judgement {
  const words = nonFlags(dropOptionValues(argv, HELM_VALUE_FLAGS), 1).map((w) => w.toLowerCase());
  const sub = words[0] ?? '';
  const op = words[1] ?? '';
  const dryRun = hasFlag(argv, '--dry-run');
  // `--post-renderer` pipes the rendered manifests through a program named on
  // the command line, so even `helm template` becomes "run this binary".
  const postRenderer = flagValue(argv, '--post-renderer') !== undefined;

  if (sub === '' || sub === 'version' || sub === 'env' || sub === 'help' || sub === 'completion') {
    return { capability: 'exec.inspect', note: 'prints local helm information', pathArgs: 'none' };
  }
  // `template` and `lint` never contact a cluster; they are the safe way to see
  // what a chart would produce.
  if (sub === 'template' || sub === 'lint') {
    const j: Judgement = { capability: 'exec.build', reach: 'workspace', reversibility: 'easy', note: 'renders the chart locally without touching a cluster' };
    if (postRenderer) {
      j.opaque = true;
      addNote(j, 'and pipes the result through a program of its own choosing');
    }
    return j;
  }
  if (sub === 'get') {
    // `get values` / `get all` print the values a release was installed with,
    // which is where passwords tend to live.
    return {
      capability: 'exec.cloud',
      reach: 'network',
      reversibility: 'trivial',
      exposure: 'reads-secrets',
      note: 'prints the stored values of a release, which often include passwords',
      pathArgs: 'none',
    };
  }
  if (sub === 'list' || sub === 'ls' || sub === 'history' || sub === 'status' || sub === 'show' || sub === 'search' || sub === 'verify') {
    return cloudRead('reads what is installed in the cluster');
  }
  if (sub === 'repo' || sub === 'pull' || sub === 'dependency' || sub === 'dep' || sub === 'plugin') {
    if (op === 'list' || op === 'ls') return { capability: 'exec.inspect', note: 'lists configured repositories', pathArgs: 'none' };
    return {
      capability: 'exec.pkg',
      reach: 'machine',
      reversibility: 'easy',
      opaque: sub === 'plugin',
      note: sub === 'plugin' ? 'installs a helm plugin, which runs its own install script' : 'downloads charts, which are templates that will be applied to a cluster',
      pathArgs: 'none',
    };
  }
  if (sub === 'create') {
    return { capability: 'fs.write.workspace', reversibility: 'easy', scale: 'many', note: 'scaffolds a new chart in the working tree' };
  }
  if (sub === 'push' || sub === 'package') {
    return sub === 'package'
      ? { capability: 'exec.build', reach: 'workspace', reversibility: 'easy', note: 'packages a chart into an archive' }
      : withProduction(
          { capability: 'exec.pkg.publish', reach: 'external', reversibility: 'irreversible', note: 'publishes a chart to a registry where others will pull it', pathArgs: 'none' },
          argv,
        );
  }
  if (sub === 'registry') {
    return { capability: 'fs.write.outside', reach: 'machine', reversibility: 'easy', note: 'stores registry credentials on this machine', pathArgs: 'none' };
  }

  if (sub === 'install' || sub === 'upgrade' || sub === 'rollback' || sub === 'test') {
    if (dryRun && !postRenderer) return cloudRead('renders what would be installed without applying it');
    const j: Judgement = {
      capability: 'exec.cloud',
      reach: 'external',
      reversibility: 'hard',
      scale: 'sweeping',
      note:
        sub === 'rollback'
          ? 'puts a release back to an earlier revision'
          : 'applies every resource in a chart to the cluster, replacing what is there',
      pathArgs: 'auto',
    };
    if (postRenderer) {
      j.opaque = true;
      addNote(j, 'after piping the manifests through a program of its own choosing');
    }
    return withProduction(j, argv);
  }
  if (sub === 'uninstall' || sub === 'delete' || sub === 'un') {
    if (dryRun) return cloudRead('reports what would be removed without removing it');
    return withProduction(
      {
        capability: 'exec.cloud',
        reach: 'external',
        reversibility: 'irreversible',
        scale: 'sweeping',
        note: 'removes every resource the release created, including its volumes',
        pathArgs: 'none',
      },
      argv,
    );
  }

  return withProduction(
    { capability: 'exec.cloud', reach: 'external', opaque: true, note: 'runs a helm subcommand this module does not recognise', pathArgs: 'none' },
    argv,
  );
}

// ---------------------------------------------------------------------------
// hosting platforms: vercel, netlify, fly, heroku, railway, wrangler, ...
// ---------------------------------------------------------------------------

const PAAS_NAMES = new Set([
  'vercel', 'now', 'netlify', 'ntl', 'fly', 'flyctl', 'heroku', 'railway',
  'render', 'wrangler', 'supabase', 'firebase', 'amplify', 'sst', 'serverless',
  'sls', 'eb', 'doctl', 'surge',
]);

/**
 * These CLIs share a shape: a verb somewhere in the subcommand decides
 * everything, and the two spellings `env pull` and `env:pull` mean the same
 * thing. Normalising the colon lets one set of rules cover both.
 */
function paas(name: string, argv: string[]): Judgement {
  const words = nonFlags(argv, 1).map((w) => w.toLowerCase());
  const path = words.join(' ').replace(/:/g, ' ');
  const prodFlag = hasFlag(argv, '--prod', '--production');

  // --- pulling deployed configuration down, which means secrets ---
  // `vercel env pull` writes the project's real environment variables into a
  // local .env file: a credential read and a file that then sits in the tree.
  if (/\b(env|environment|config|secrets?|variables?|vars)\b\s+\b(pull|get|download|export|open|reveal)\b/.test(path)) {
    return {
      capability: 'secret.read',
      reach: 'network',
      reversibility: 'trivial',
      exposure: 'can-exfiltrate',
      note: 'copies the deployed environment variables down, writing live credentials into the working tree',
    };
  }
  // Bare `heroku config` and `railway variables` print every value.
  if (/^(config|variables|vars|secrets)$/.test(path) && (name === 'heroku' || name === 'railway' || name === 'doppler')) {
    return credentialRead('prints every configured environment variable, including credentials');
  }
  if (/\bfunctions\s+config\s+get\b/.test(path)) {
    return credentialRead('prints stored function configuration, which usually holds api keys');
  }
  // `vercel pull` and `amplify pull` never say the word `env`, but what they
  // fetch is the linked project's real environment, written into a dotfile in
  // the working tree. Reading this as "scaffolds project files" is the
  // difference between a workspace write and a live credential landing on disk.
  if (/^pull\b/.test(path)) {
    return {
      capability: 'secret.read',
      reach: 'network',
      reversibility: 'trivial',
      exposure: 'can-exfiltrate',
      note: 'pulls the linked project settings down, which includes its deployed environment variables',
    };
  }

  // --- pushing configuration up: a write, and usually a restart ---
  if (/\b(env|environment|config|secrets?|variables?|vars)\b\s+\b(set|add|put|push|import|unset|rm|remove|delete)\b/.test(path)) {
    return withProduction(
      {
        capability: 'exec.cloud',
        reach: 'external',
        reversibility: 'hard',
        note: 'changes the deployed configuration, which normally restarts the running service',
        pathArgs: 'none',
      },
      argv,
    );
  }

  // --- databases ---
  if (/\b(db|database|pg|postgres|sql|d1|mysql)\b/.test(path)) {
    if (/\b(reset|drop|destroy|delete|wipe|purge)\b/.test(path)) {
      return withProduction(
        {
          capability: 'exec.db',
          reach: 'external',
          reversibility: 'irreversible',
          scale: 'sweeping',
          note: 'drops the database contents, and there is no undo for that',
          pathArgs: 'none',
        },
        argv,
      );
    }
    if (/\b(execute|query|psql|shell|connect|exec)\b/.test(path)) {
      return withProduction(
        {
          capability: 'exec.db',
          reach: 'external',
          reversibility: 'hard',
          opaque: true,
          note: 'runs sql against a hosted database, and the statement decides what happens',
          pathArgs: 'none',
        },
        argv,
      );
    }
    if (/\b(push|migrate|migration|deploy|apply|seed)\b/.test(path)) {
      return withProduction(
        {
          capability: 'exec.db',
          reach: 'external',
          reversibility: 'hard',
          scale: 'many',
          note: 'applies schema migrations to a hosted database',
          pathArgs: 'none',
        },
        argv,
      );
    }
    if (/\b(dump|backup|pull)\b/.test(path)) {
      return { capability: 'fs.write.workspace', reach: 'workspace', reversibility: 'easy', exposure: 'reads-secrets', note: 'downloads a copy of hosted data into the working tree' };
    }
  }

  // --- getting a shell, or borrowing production credentials locally ---
  // `railway run` and `heroku local` inject the deployed environment into a
  // local process, so the secrets end up on this machine either way.
  if (/\b(ssh|console|rsh|attach)\b/.test(path) || /^run\b/.test(path) || /\bexec\b/.test(path)) {
    const localWithRemoteEnv = name === 'railway';
    return withProduction(
      {
        capability: 'exec.remote',
        reach: 'external',
        reversibility: 'hard',
        exposure: localWithRemoteEnv ? 'can-exfiltrate' : 'none',
        opaque: true,
        note: localWithRemoteEnv
          ? 'runs a command with the deployed secrets injected into its environment'
          : 'opens a session on the hosting platform, and what happens inside it is not visible here',
        pathArgs: 'none',
      },
      argv,
    );
  }

  // --- taking things away ---
  if (/\b(destroy|delete|remove|rm|down|teardown|terminate|purge|nuke|uninstall|undeploy)\b/.test(path)) {
    return withProduction(
      {
        capability: 'exec.cloud',
        reach: 'external',
        reversibility: 'irreversible',
        scale: 'sweeping',
        note: 'tears down a deployed application and the resources behind it',
        pathArgs: 'none',
      },
      argv,
    );
  }

  // --- shipping ---
  // `vercel` with no subcommand deploys. `promote` and `alias` move live
  // traffic without deploying anything, which is a production change too.
  const bareDeploy = path === '' && (name === 'vercel' || name === 'now' || name === 'surge');
  if (bareDeploy || /\b(deploy|publish|release|promote|alias|launch|redeploy|rollback|ship|up)\b/.test(path)) {
    const trafficMove = /\b(promote|alias|rollback)\b/.test(path);
    const j: Judgement = {
      capability: 'exec.cloud',
      reach: 'external',
      reversibility: 'hard',
      scale: 'many',
      note: trafficMove ? 'points live traffic at a different version' : 'ships new code to the hosting platform',
      pathArgs: 'none',
    };
    // A promotion is by definition into whatever users are hitting.
    if (prodFlag || trafficMove) {
      j.reach = 'production';
      if (prodFlag) addNote(j, 'straight into production');
    }
    return withProduction(j, argv);
  }

  // --- scaling, restarts and domains: real but recoverable ---
  if (/\b(scale|restart|resize|maintenance|domains|certs|cert|ps|dyno|open-console)\b/.test(path) && /\b(add|set|create|update|on|off|restart|resize)\b/.test(path)) {
    return withProduction(
      { capability: 'exec.cloud', reach: 'external', reversibility: 'hard', note: 'changes how the deployed service runs', pathArgs: 'none' },
      argv,
    );
  }

  // --- local and read-only ---
  if (/^(dev|serve|start|emulators|preview|watch)\b/.test(path)) {
    return { capability: 'exec.process', reach: 'machine', reversibility: 'easy', note: 'starts a local development server', pathArgs: 'none' };
  }
  if (/^(init|new|scaffold|template|link|unlink|build|generate|add)\b/.test(path)) {
    return { capability: 'fs.write.workspace', reversibility: 'easy', scale: 'many', note: 'writes project files into the working tree' };
  }
  if (/^(login|logout|auth|signin|signout|token|whoami|switch|account)\b/.test(path)) {
    return { capability: 'fs.write.outside', reach: 'machine', reversibility: 'easy', note: 'stores or clears platform credentials on this machine', pathArgs: 'none' };
  }
  // These words are matched anywhere in the path, so a resource group is enough
  // to trigger them: `doctl apps create --spec app.yaml` matched on `apps` and
  // came back a read. Require that nothing on the line is asking for a change.
  if (
    /\b(list|ls|status|info|show|logs|log|tail|inspect|history|version|help|doctor|projects|apps|sites|orgs|teams|releases)\b/.test(path) &&
    !/\b(create|new|add|set|update|patch|import|attach|enable|disable|reset|restart|scale|deploy|destroy|delete|remove)\b/.test(path)
  ) {
    return cloudRead('reads the state of deployed applications');
  }

  return withProduction(
    { capability: 'exec.cloud', reach: 'external', opaque: true, note: 'runs a deployment cli subcommand this module does not recognise', pathArgs: 'none' },
    argv,
  );
}

// ---------------------------------------------------------------------------
// ansible
// ---------------------------------------------------------------------------

function ansible(name: string, argv: string[]): Judgement {
  const words = nonFlags(argv, 1).map((w) => w.toLowerCase());
  const sub = words[0] ?? '';

  if (name === 'ansible-vault') {
    if (sub === 'view' || sub === 'decrypt' || sub === 'edit' || sub === 'rekey') {
      return {
        capability: 'secret.read',
        reach: 'machine',
        reversibility: 'trivial',
        exposure: 'can-exfiltrate',
        note: 'decrypts a vault file and shows what is inside it',
      };
    }
    return { capability: 'fs.write.workspace', reversibility: 'easy', note: 'encrypts a file with the vault password' };
  }
  if (name === 'ansible-galaxy') {
    if (sub === 'search' || sub === 'info' || sub === 'list') return { capability: 'exec.inspect', note: 'lists or searches roles', pathArgs: 'none' };
    return {
      capability: 'exec.pkg',
      reach: 'machine',
      reversibility: 'easy',
      note: 'downloads roles and collections, which are code that will run against hosts',
      pathArgs: 'none',
    };
  }
  if (name === 'ansible-doc' || name === 'ansible-config' || name === 'ansible-lint') {
    // ansible-lint reports by default, but `--fix` (formerly `--write`)
    // rewrites every playbook and yaml file it decides it can repair.
    if (name === 'ansible-lint' && hasFlag(argv, '--fix', '--write')) {
      return { capability: 'fs.write.workspace', reversibility: 'easy', scale: 'many', note: 'rewrites playbooks and yaml files in place' };
    }
    return { capability: 'exec.inspect', note: 'reads local ansible configuration or documentation' };
  }
  if (name === 'ansible-inventory') {
    return {
      capability: 'exec.inspect',
      exposure: 'reads-secrets',
      note: 'prints the inventory, including any variables stored with it',
    };
  }

  // `--check` connects to every host and reports what would change. Some
  // modules cannot be simulated, but nothing is written on purpose.
  const check = hasFlag(argv, '--check', '-C');
  const become = hasFlag(argv, '--become', '-b', '--become-user');
  const module = flagValue(argv, '-m', '--module-name') ?? '';
  const readOnlyModule = ['setup', 'ping', 'debug', 'gather_facts', 'stat'].includes(module);

  if (check || (name === 'ansible' && readOnlyModule)) {
    return {
      capability: 'exec.remote',
      reach: 'network',
      reversibility: 'trivial',
      scale: 'sweeping',
      note: check ? 'a check run that reports what would change without applying it' : 'gathers facts from every matching host',
      pathArgs: 'auto',
    };
  }

  const j: Judgement = {
    capability: 'exec.remote',
    reach: 'external',
    reversibility: 'irreversible',
    scale: 'sweeping',
    // The tasks live in a yaml file we never see, so the real effect is the
    // playbook's, not the command line's.
    opaque: true,
    note:
      name === 'ansible'
        ? 'runs a module on every host the pattern matches'
        : 'runs a playbook against every host in the inventory, and the tasks are not visible here',
  };
  if (become) addNote(j, 'as root on those hosts');
  if (flagValue(argv, '--limit', '-l') !== undefined) j.scale = 'many';
  return withProduction(j, argv);
}

// ---------------------------------------------------------------------------
// hashicorp vault
// ---------------------------------------------------------------------------

function vault(argv: string[]): Judgement {
  const words = nonFlags(argv, 1).map((w) => w.toLowerCase());
  const sub = words[0] ?? '';
  const op = words[1] ?? '';

  if (sub === 'status' || sub === 'version' || sub === 'path-help' || sub === 'monitor') {
    return cloudRead('reads vault status');
  }
  if (sub === 'read' || (sub === 'kv' && (op === 'get' || op === 'read'))) {
    return credentialRead('prints a stored secret');
  }
  // `kv metadata` is not one thing: `get`/`list` read it, while `delete`
  // permanently destroys every version of the secret. Claiming the whole group
  // is a listing let `vault kv metadata delete secret/prod` through as a read.
  if (sub === 'list' || (sub === 'kv' && (op === 'list' || (op === 'metadata' && (words[2] === 'get' || words[2] === 'list'))))) {
    return cloudRead('lists secret paths without printing their values');
  }
  if (sub === 'unwrap' || (sub === 'print' && op === 'token')) {
    return credentialRead('prints a live vault token');
  }
  // A freshly minted token is a working credential for whatever it can reach.
  if ((sub === 'token' && op === 'create') || sub === 'login' || (sub === 'write' && /auth\//.test(op))) {
    return {
      capability: 'secret.read',
      reach: 'network',
      reversibility: 'hard',
      exposure: 'can-exfiltrate',
      note: 'mints a vault token and prints it',
      pathArgs: 'none',
    };
  }
  if (sub === 'operator') {
    if (op === 'init') {
      return {
        capability: 'secret.read',
        reach: 'external',
        reversibility: 'irreversible',
        exposure: 'can-exfiltrate',
        note: 'initialises vault and prints the root token and unseal keys once',
        pathArgs: 'none',
      };
    }
    // Unseal keys passed as arguments end up in shell history and process lists.
    return withProduction(
      {
        capability: 'exec.cloud',
        reach: 'external',
        reversibility: 'hard',
        scale: 'sweeping',
        note:
          op === 'seal'
            ? 'seals vault, which cuts every consumer off from its secrets until it is unsealed again'
            : 'performs a vault operator action, and any key given on the command line is left in shell history',
        pathArgs: 'none',
      },
      argv,
    );
  }
  if (sub === 'delete' || (sub === 'kv' && (op === 'delete' || op === 'destroy' || op === 'metadata')) || sub === 'lease' || (sub === 'secrets' && op === 'disable') || (sub === 'auth' && op === 'disable')) {
    return withProduction(
      {
        capability: 'exec.cloud',
        reach: 'external',
        reversibility: 'irreversible',
        scale: sub === 'secrets' || sub === 'auth' ? 'sweeping' : 'many',
        note:
          sub === 'secrets' || sub === 'auth'
            ? 'disables a whole mount, taking every secret under it with it'
            : 'deletes stored secrets that running services may still be reading',
        pathArgs: 'none',
      },
      argv,
    );
  }
  if (sub === 'policy' && op !== 'read' && op !== 'list') {
    return withProduction(
      { capability: 'exec.privilege', reach: 'external', reversibility: 'hard', scale: 'many', note: 'changes who can read which secrets', pathArgs: 'none' },
      argv,
    );
  }
  if (sub === 'write' || sub === 'put' || (sub === 'kv' && (op === 'put' || op === 'patch'))) {
    return withProduction(
      { capability: 'exec.cloud', reach: 'external', reversibility: 'hard', note: 'changes a stored secret that running services depend on', pathArgs: 'none' },
      argv,
    );
  }
  if (sub === 'server' || sub === 'agent') {
    return { capability: 'exec.process', reach: 'machine', reversibility: 'easy', note: 'starts a long-running vault process', pathArgs: 'none' };
  }

  return withProduction(
    { capability: 'exec.cloud', reach: 'external', opaque: true, note: 'runs a vault subcommand this module does not recognise', pathArgs: 'none' },
    argv,
  );
}

// ---------------------------------------------------------------------------
// file-level encryption: sops, age, gpg
// ---------------------------------------------------------------------------

function sops(argv: string[]): Judgement {
  const words = nonFlags(argv, 1).map((w) => w.toLowerCase());
  const sub = words[0] ?? '';

  // exec-env / exec-file hand the decrypted values to another program.
  if (sub === 'exec-env' || sub === 'exec-file') {
    return {
      capability: 'exec.unknown',
      reach: 'machine',
      reversibility: 'hard',
      exposure: 'can-exfiltrate',
      opaque: true,
      note: 'runs another command with the decrypted secrets handed to it',
    };
  }
  if (hasFlag(argv, '-e', '--encrypt') || sub === 'encrypt') {
    return { capability: 'fs.write.workspace', reversibility: 'easy', note: 'encrypts a file in place' };
  }
  if (sub === 'updatekeys' || sub === 'rotate' || hasFlag(argv, '-r', '--rotate')) {
    return { capability: 'fs.write.workspace', reversibility: 'hard', note: 'rewrites which keys can open an encrypted file' };
  }
  // Everything else, including bare `sops file.yaml`, decrypts.
  return {
    capability: 'secret.read',
    reach: 'machine',
    reversibility: 'trivial',
    exposure: 'can-exfiltrate',
    note: 'decrypts a secrets file and shows what is inside it',
  };
}

function age(name: string, argv: string[]): Judgement {
  if (name === 'age-keygen') {
    return { capability: 'fs.write.workspace', reversibility: 'hard', note: 'writes a new private key' };
  }
  if (hasFlag(argv, '-d', '--decrypt')) {
    return { capability: 'secret.read', reach: 'machine', reversibility: 'trivial', exposure: 'can-exfiltrate', note: 'decrypts a file and prints the plaintext' };
  }
  return { capability: 'fs.write.workspace', reversibility: 'easy', note: 'encrypts a file' };
}

function gpg(argv: string[]): Judgement {
  if (hasFlag(argv, '--export-secret-keys', '--export-secret-subkeys')) {
    return {
      capability: 'secret.read',
      reach: 'machine',
      reversibility: 'trivial',
      exposure: 'can-exfiltrate',
      note: 'exports private keys, which are the keys themselves and not just signatures',
    };
  }
  if (hasFlag(argv, '--delete-secret-keys', '--delete-secret-and-public-key')) {
    return { capability: 'fs.delete', reach: 'machine', reversibility: 'irreversible', note: 'deletes a private key from the keyring' };
  }
  if (hasFlag(argv, '--list-keys', '--list-secret-keys', '--fingerprint', '--verify', '--version', '-k', '-K')) {
    return { capability: 'exec.inspect', note: 'lists keys or verifies a signature' };
  }
  if (hasFlag(argv, '--send-keys')) {
    return { capability: 'net.send', note: 'publishes a key to a public keyserver' };
  }
  if (hasFlag(argv, '--recv-keys', '--refresh-keys', '--locate-keys', '--search-keys')) {
    return { capability: 'net.fetch', note: 'fetches keys from a keyserver' };
  }
  if (hasFlag(argv, '--import')) {
    return { capability: 'fs.write.outside', reach: 'machine', reversibility: 'easy', note: 'adds a key to the local keyring' };
  }
  if (hasFlag(argv, '-e', '--encrypt', '-s', '--sign', '--clear-sign', '--detach-sign', '-c', '--symmetric', '--gen-key', '--full-generate-key')) {
    return { capability: 'fs.write.workspace', reversibility: 'easy', note: 'encrypts or signs a file' };
  }
  // Bare `gpg secrets.gpg` decrypts, so decryption is the default reading.
  return {
    capability: 'secret.read',
    reach: 'machine',
    reversibility: 'trivial',
    exposure: 'can-exfiltrate',
    note: 'decrypts a file and prints the plaintext',
  };
}

// ---------------------------------------------------------------------------
// secret managers with a cli: doppler, 1password, infisical
// ---------------------------------------------------------------------------

function secretCli(argv: string[]): Judgement {
  const words = nonFlags(argv, 1).map((w) => w.toLowerCase());
  const path = words.join(' ');
  const sub = words[0] ?? '';

  // `doppler run -- cmd` / `op run -- cmd` inject live secrets into another
  // program's environment. We can see the wrapper, not what it does with them.
  if (sub === 'run') {
    return {
      capability: 'exec.unknown',
      reach: 'machine',
      reversibility: 'hard',
      exposure: 'can-exfiltrate',
      opaque: true,
      note: 'runs another command with live secrets injected into its environment',
    };
  }
  // `op inject` renders a template with real secret values into a file.
  if (sub === 'inject') {
    return {
      capability: 'secret.read',
      reach: 'workspace',
      reversibility: 'easy',
      exposure: 'can-exfiltrate',
      note: 'writes live secret values into a file in the working tree',
    };
  }
  if (sub === 'read' || /^(item|document)\s+get\b/.test(path) || /^secrets?\s*(get|download|export)?$/.test(path) || sub === 'export') {
    return credentialRead('prints a stored secret');
  }
  if (/\b(list|ls)\b/.test(path) || sub === 'whoami' || sub === 'account' || sub === 'vault' || sub === 'projects' || sub === 'configs') {
    return cloudRead('lists what is stored without printing the values');
  }
  if (/\b(create|edit|set|update|put|delete|remove|rm|archive|share)\b/.test(path)) {
    const removing = /\b(delete|remove|rm|archive)\b/.test(path);
    return withProduction(
      {
        capability: 'exec.cloud',
        reach: 'external',
        reversibility: removing ? 'irreversible' : 'hard',
        note: removing
          ? 'deletes stored secrets that running services may still be reading'
          : 'changes a stored secret that running services depend on',
        pathArgs: 'none',
      },
      argv,
    );
  }
  if (sub === 'signin' || sub === 'signout' || sub === 'login' || sub === 'logout' || sub === 'setup' || sub === 'configure' || sub === 'init') {
    return { capability: 'fs.write.outside', reach: 'machine', reversibility: 'easy', note: 'stores or clears secret manager credentials on this machine', pathArgs: 'none' };
  }
  // Anything unrecognised in a secret manager is assumed to touch secrets.
  return {
    capability: 'secret.read',
    reach: 'network',
    reversibility: 'trivial',
    exposure: 'can-exfiltrate',
    opaque: true,
    note: 'runs a secret manager subcommand this module does not recognise, so assume it can reach secrets',
    pathArgs: 'none',
  };
}

// ---------------------------------------------------------------------------

export const cloud: ProgramKnowledge = {
  names: [
    // infrastructure as code
    'terraform', 'tofu', 'terragrunt', 'pulumi', 'cdk', 'cdktf',
    // provider clis
    'aws', 'gcloud', 'gsutil', 'bq', 'az',
    // kubernetes
    'kubectl', 'oc', 'helm',
    // hosting platforms
    'vercel', 'now', 'netlify', 'ntl', 'fly', 'flyctl', 'heroku', 'railway',
    'render', 'wrangler', 'supabase', 'firebase', 'amplify', 'sst',
    'serverless', 'sls', 'eb', 'doctl', 'surge',
    // configuration management
    'ansible', 'ansible-playbook', 'ansible-galaxy', 'ansible-vault',
    'ansible-inventory', 'ansible-doc', 'ansible-config', 'ansible-lint',
    // secrets
    'vault', 'sops', 'age', 'age-keygen', 'gpg', 'gpg2', 'doppler', 'op',
    'infisical',
  ],
  describe: 'Cloud and infrastructure tools, split by whether they read, plan, or actually change live systems',

  classify(argv, ctx) {
    // Never index argv[0] unguarded: an empty argv used to throw out of
    // `name.startsWith` below rather than declining politely.
    const name = argv[0] ?? '';
    if (name === '') return null;

    if (name === 'terraform' || name === 'tofu' || name === 'terragrunt') return terraform(name, argv);
    if (name === 'cdk' || name === 'cdktf') return cdk(argv);
    if (name === 'pulumi') return pulumi(argv);

    if (name === 'aws') return aws(argv, ctx);
    if (name === 'gcloud') return gcloud(argv, ctx);
    if (name === 'gsutil') return objectStorage(nonFlags(dropOptionValues(argv, GSUTIL_VALUE_FLAGS), 1), argv, ctx);
    if (name === 'bq') return bq(argv);
    if (name === 'az') return az(argv);

    if (name === 'kubectl' || name === 'oc') return kubectl(argv);
    if (name === 'helm') return helm(argv);

    if (PAAS_NAMES.has(name)) return paas(name, argv);
    if (name === 'ansible' || name.startsWith('ansible-')) return ansible(name, argv);

    if (name === 'vault') return vault(argv);
    if (name === 'sops') return sops(argv);
    if (name === 'age' || name === 'age-keygen') return age(name, argv);
    if (name === 'gpg' || name === 'gpg2') return gpg(argv);
    if (name === 'doppler' || name === 'op' || name === 'infisical') return secretCli(argv);

    return null;
  },
};
