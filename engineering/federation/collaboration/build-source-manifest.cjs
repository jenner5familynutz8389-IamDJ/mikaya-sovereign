#!/usr/bin/env node
'use strict';
// Run in a development checkout. The manifest itself is intentionally excluded:
// its independent SHA-256 is the installer trust input, avoiding self-reference.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {execFileSync} = require('node:child_process');
const root = path.resolve(__dirname, '../../..');
const output = path.join(root, 'COLLABORATION-SOURCE-MANIFEST.json');
const names = execFileSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], {cwd: root, encoding: 'utf8'}).split('\0').filter(Boolean);
const dependencies = new Set(['engineering/federation/live/federation-node.cjs', 'engineering/federation/live/security-tollbooth.cjs', 'ahava/core.js']);
const files = [...new Set(names)].filter(name => (name.startsWith('engineering/federation/collaboration/') || dependencies.has(name)) && name !== 'COLLABORATION-SOURCE-MANIFEST.json' &&
  name !== 'engineering/federation/collaboration/ACCEPTANCE.md' &&
  !name.startsWith('engineering/federation/collaboration/evidence/')).sort().map(name => {
  if (name.includes('..') || path.isAbsolute(name)) throw Error('UNSAFE_SOURCE_PATH');
  const file = path.join(root, name), stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 4 * 1024 * 1024) throw Error('UNSAFE_SOURCE_FILE');
  return {path: name, sha256: crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex')};
});
const body = {schema: 'mikaya.collaboration.source-manifest.v1',
  baselineCommit: '1da7fbdd79e63f857b07af0738278156c19a9966',
  entrypoint: 'engineering/federation/collaboration/gateway-adapter.cjs', files};
const bytes = Buffer.from(JSON.stringify(body, null, 2) + '\n');
fs.writeFileSync(output, bytes, {mode: 0o644});
console.log(JSON.stringify({file: output, files: files.length, sha256: crypto.createHash('sha256').update(bytes).digest('hex')}));
