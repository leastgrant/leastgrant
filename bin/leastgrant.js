#!/usr/bin/env node
// Thin launcher. Kept free of logic so that the hook path — which runs before
// every tool call your agent makes — loads as little as possible.
//
// The one thing that has to happen here is the colour decision. The renderer
// reads NO_COLOR when its module is first evaluated, so a `--no-color` flag has
// to be turned into the environment variable *before* anything imports it —
// which means before the static import graph is built. Hence the dynamic
// import below.

const argv = process.argv.slice(2);
if (argv.includes('--no-color') || argv.includes('--no-colour')) {
  process.env.NO_COLOR = '1';
  delete process.env.FORCE_COLOR;
} else if (argv.includes('--color') || argv.includes('--colour')) {
  process.env.FORCE_COLOR = '1';
  delete process.env.NO_COLOR;
}

const { main } = await import('../dist/src/main.js');

try {
  process.exitCode = await main(argv);
} catch (err) {
  console.error(err?.stack ?? String(err));
  process.exitCode = 1;
}
