/**
 * Install this project's preset into the DSH user preset root, where the agent
 * roster discovers it.
 *
 * The roster reads one directory per preset under
 * `${DSH_HOME:-$HOME/.dsh}/.agent-presets/<id>/`, containing `agent.cordis.yml`
 * and (optionally) `preset.yml`. Installing is a plain directory copy: the
 * preset ships its own plugin, so there is no package to `dsh plugin add`.
 *
 * Usage:
 *   node scripts/install-preset.mjs [--id <preset-id>] [--force] [--dry-run]
 *
 * The preset only becomes visible to NEW sessions; restart the host or start a
 * fresh session after installing.
 */

import { cpSync, existsSync, rmSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const PROJECT = resolve(dirname(fileURLToPath(import.meta.url)), '..')

/**
 * Parse `--flag value` and boolean `--flag` arguments.
 * @param {string[]} argv - `process.argv.slice(2)`.
 * @returns {{ id: string, force: boolean, dryRun: boolean }} the parsed options.
 */
function parseArgs(argv) {
  const options = { id: 'security-review', force: false, dryRun: false }
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]
    if (arg === '--id') {
      options.id = argv[++i]
      if (options.id === undefined) throw new Error('--id needs a value')
    } else if (arg === '--force') {
      options.force = true
    } else if (arg === '--dry-run') {
      options.dryRun = true
    } else {
      throw new Error(`unexpected argument ${arg}`)
    }
  }
  if (!/^[a-z0-9][a-z0-9-]*$/.test(options.id)) {
    throw new Error(`--id must match [a-z0-9][a-z0-9-]* (got ${options.id})`)
  }
  return options
}

const options = parseArgs(process.argv.slice(2))
const source = resolve(PROJECT, 'preset')
const home = process.env.DSH_HOME ?? join(homedir(), '.dsh')
const presetsRoot = join(home, '.agent-presets')
const target = join(presetsRoot, options.id)

if (!existsSync(resolve(source, 'agent.cordis.yml'))) {
  throw new Error(`${source}/agent.cordis.yml is missing — run \`npm run build\` first`)
}
if (existsSync(target) && !options.force) {
  console.error(`refusing to overwrite ${target}`)
  console.error('pass --force to replace the existing preset directory')
  process.exit(1)
}

console.log(`source: ${source}`)
console.log(`target: ${target}`)
if (options.dryRun) {
  console.log('dry run: nothing written')
  process.exit(0)
}

if (existsSync(target)) rmSync(target, { recursive: true, force: true })
cpSync(source, target, { recursive: true })
console.log(`installed preset "${options.id}" — restart the host or start a new session to select it`)
