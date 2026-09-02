/**
 * CLI entry point.
 *
 * Commands are loaded with dynamic imports so that a run of `leastgrant check`
 * does not pay for the miner, and — more importantly — so that the `hook`
 * path, which runs before every single tool call, loads almost nothing.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { help, parseArgv, unknownCommand } from './cli/index.js';
import { c } from './cli/ui.js';

/**
 * The version, read from the package rather than typed here.
 *
 * It was a literal, and `npm version` does not edit source — so a release
 * bumped package.json, shipped, and the CLI went on reporting the previous
 * number. For a tool whose own docs tell you to quote your version in a bug
 * report, and whose release pipeline verifies that what reached the registry is
 * what it built, having two versions of the truth is the wrong kind of irony.
 *
 * Read lazily. The hook path returns above this and runs before every tool
 * call; it should not pay for a file read to answer a question nobody asked.
 */
function version(): string {
  try {
    const here = path.dirname(fileURLToPath(import.meta.url));
    // dist/src/main.js -> ../../package.json
    const pkg = JSON.parse(fs.readFileSync(path.resolve(here, '..', '..', 'package.json'), 'utf8')) as {
      version?: string;
    };
    return pkg.version ?? 'unknown';
  } catch {
    return 'unknown';
  }
}

export async function main(rawArgs: string[]): Promise<number> {
  const argv = parseArgv(rawArgs);

  // The hook path is checked first and returns immediately: nothing else in
  // this file should be reachable before it.
  if (argv.command === 'hook') {
    const { runHook } = await import('./adapters/claude-code/hook.js');
    await runHook();
    return 0;
  }

  if (argv.flags['version'] || argv.flags['v'] || argv.command === 'version') {
    process.stdout.write(`leastgrant ${version()}\n`);
    return 0;
  }

  if (!argv.command || argv.flags['help'] || argv.flags['h'] || argv.command === 'help') {
    // A bare `leastgrant` or an explicit `--help` is a success. A *typo'd*
    // flag is not: `leastgrant --nonsense` used to print the help and exit 0,
    // so a mistyped flag in a script looked like it had worked.
    const known = new Set(['help', 'h', 'version', 'v', 'json', 'no-color', 'color']);
    const unknownFlag = Object.keys(argv.flags).find((f) => !known.has(f));
    if (!argv.command && unknownFlag) {
      process.stderr.write(`
  ${c.red('Unknown option')} --${unknownFlag}
  ${c.gray('Run `leastgrant --help` for the list.')}

`);
      return 2;
    }
    process.stdout.write(help());
    return 0;
  }

  try {
    switch (argv.command) {
      case 'check': {
        const { checkCommand } = await import('./cli/commands/check.js');
        return checkCommand(argv);
      }
      case 'init': {
        const { initCommand } = await import('./cli/commands/init.js');
        return await initCommand(argv);
      }
      case 'status': {
        const { statusCommand } = await import('./cli/commands/status.js');
        return statusCommand(argv);
      }
      case 'trail': {
        const { trailCommand } = await import('./cli/commands/trail.js');
        return trailCommand(argv);
      }
      case 'why': {
        const { whyCommand } = await import('./cli/commands/why.js');
        return whyCommand(argv);
      }
      case 'simulate': {
        const { simulateCommand } = await import('./cli/commands/simulate.js');
        return simulateCommand(argv);
      }
      case 'allow':
      case 'deny':
      case 'forget':
      case 'rules': {
        const { rulesCommand } = await import('./cli/commands/rules.js');
        return rulesCommand(argv);
      }
      case 'doctor': {
        const { doctorCommand } = await import('./cli/commands/doctor.js');
        return doctorCommand(argv);
      }
      case 'benchmark': {
        const { benchmarkCommand } = await import('./cli/commands/benchmark.js');
        return benchmarkCommand(argv);
      }
      case 'install':
      case 'uninstall': {
        const { installCommand } = await import('./cli/commands/install.js');
        return await installCommand(argv);
      }
      default:
        process.stderr.write(unknownCommand(argv.command));
        return 2;
    }
  } catch (err) {
    const e = err as Error;
    process.stderr.write(`\n  ${c.red('Something went wrong.')} ${e.message}\n`);
    if (process.env['LEASTGRANT_DEBUG']) process.stderr.write(`\n${e.stack}\n`);
    else process.stderr.write(c.gray('  Set LEASTGRANT_DEBUG=1 for the stack trace.\n\n'));
    return 1;
  }
}
