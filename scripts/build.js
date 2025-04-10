#!/usr/bin/env node

import * as esbuild from 'esbuild';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const isWatch = process.argv.includes('--watch');

// Use console.error for all logging to avoid interfering with stdio transport
console.error('=== BUILD SCRIPT EXECUTION STARTED ===');
console.error(`Script executed from: ${process.cwd()}`);
console.error(`Script path: ${import.meta.url}`);
console.error(`Arguments: ${process.argv.join(', ')}`);
console.error(`Execution context: ${process.env.npm_lifecycle_event || 'direct'}`);

/** @type {import('esbuild').BuildOptions} */
const buildOptions = {
  entryPoints: [join(__dirname, '../src/index.ts')],
  bundle: true,
  platform: 'node',
  target: 'node18',
  outfile: join(__dirname, '../build/index.js'),
  format: 'esm',
  banner: {
    js: '#!/usr/bin/env node\n',
  },
  packages: 'external', // Don't bundle node_modules
  sourcemap: true,
};

/** @type {import('esbuild').BuildOptions} */
const authServerBuildOptions = {
  entryPoints: [join(__dirname, '../src/auth-server.ts')],
  bundle: true,
  platform: 'node',
  target: 'node18',
  outfile: join(__dirname, '../build/auth-server.js'),
  format: 'esm',
  packages: 'external', // Don't bundle node_modules
  sourcemap: true,
};

if (isWatch) {
  const context = await esbuild.context(buildOptions);
  const authContext = await esbuild.context(authServerBuildOptions);
  await Promise.all([context.watch(), authContext.watch()]);
  console.log('Watching for changes...');
} else {
  console.error('Building main server and auth server...');
  await Promise.all([
    esbuild.build(buildOptions),
    esbuild.build(authServerBuildOptions)
  ]);
  console.error('Build completed successfully.');
  
  // Make the file executable on non-Windows platforms
  if (process.platform !== 'win32') {
    const { chmod } = await import('fs/promises');
    await chmod(buildOptions.outfile, 0o755);
  }
  console.error('=== BUILD SCRIPT EXECUTION COMPLETED ===');
} 