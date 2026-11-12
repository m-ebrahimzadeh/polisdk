import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execSync } from 'node:child_process';
import * as esbuild from 'esbuild';

const pkgDir = path.dirname(fileURLToPath(import.meta.url));
const distDir = path.join(pkgDir, 'dist');

fs.rmSync(distDir, { recursive: true, force: true });

// 1. Compile TypeScript sources and .d.ts declarations
execSync('npx tsc -p tsconfig.json', {
  cwd: pkgDir,
  stdio: 'inherit'
});

// 2. Create root dist/index.js and dist/index.d.ts forwarding to dist/src/index.js
fs.writeFileSync(
  path.join(distDir, 'index.js'),
  `export * from './src/index.js';\n`,
  'utf8'
);
fs.writeFileSync(
  path.join(distDir, 'index.d.ts'),
  `export * from './src/index.js';\n`,
  'utf8'
);

// 3. Pre-bundle the browser-injected DOM adapter IIFE script
await esbuild.build({
  entryPoints: [path.join(pkgDir, 'adapters/injected-auth-entry.ts')],
  bundle: true,
  outfile: path.join(distDir, 'injected-auth-adapters.iife.js'),
  format: 'iife',
  platform: 'browser',
  target: ['es2022']
});

console.log('✅ @polisdk/poliauth built successfully into dist/');
