/**
 * Regenerate `preset/agent.cordis.yml`: the deployment's shipped `standard`
 * composition plus this project's one extra row.
 *
 * Copying `standard` rather than authoring a composition from scratch is
 * deliberate. A preset decides an agent's entire tool surface, so a
 * hand-written minimal composition would silently drop the shell, filesystem,
 * search, skill, plan, goal, and delegation rows a review actually needs. The
 * shipped file is known to mount, and the only local change is the final row —
 * which publishes no service, so per the preset rules it needs no `isolate`
 * realm.
 *
 * Usage:
 *   node scripts/sync-preset.mjs <path/to/standard/agent.cordis.yml>
 *   DSH_STANDARD_PRESET=<path> node scripts/sync-preset.mjs
 *
 * The shipped composition lives beside the deployment's own config, inside the
 * installed harness: `packages/preset/agent-presets/presets/standard/`.
 */

import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const PROJECT = resolve(dirname(fileURLToPath(import.meta.url)), '..')

/** Prefixed to the copied composition so the derivation is visible in place. */
const HEADER = `# The \`security-review\` agent preset: the deployment's shipped \`standard\`
# composition plus one row for this project's security-review plugin.
#
# Everything after the \`standard\` header below is a verbatim copy of
# \`packages/preset/agent-presets/presets/standard/agent.cordis.yml\` from the
# installed harness; the only local change is the final \`security-review\` row
# appended at the end of the file. Re-run \`node scripts/sync-preset.mjs <path>\`
# after a harness upgrade to re-copy \`standard\` and re-append that row.
#
# The appended row contributes one scoped prompt section and four tools, and
# publishes no service, so it sits loose in the composition rather than inside a
# group carrying an \`isolate\` realm.
#
`

/** Appended after the copied composition: the only local row. */
const ROW = `
# ── security review (VulnHuntr playbook) ────────────────────────────────────

# Ships inside this preset directory, so the row's relative specifier resolves
# against the composition itself (a preset's own files travel with it). The
# module is dependency-free by design: a locally authored preset sits outside
# the installed harness, where a bare \`@deepseek-ai/dsh-*\` import cannot
# resolve.
- id: security-review
  name: ./plugin/security-review.mjs
`

const standardPath = process.argv[2] ?? process.env.DSH_STANDARD_PRESET
if (standardPath === undefined) {
  console.error('usage: node scripts/sync-preset.mjs <path/to/standard/agent.cordis.yml>')
  console.error('   or: DSH_STANDARD_PRESET=<path> node scripts/sync-preset.mjs')
  process.exit(2)
}

const source = readFileSync(resolve(standardPath), 'utf8')
if (!source.includes('@deepseek-ai/dsh-persona')) {
  throw new Error(`${standardPath} does not look like the shipped standard composition`)
}
if (source.includes('security-review')) {
  throw new Error(`${standardPath} already contains the security-review row`)
}

const target = resolve(PROJECT, 'preset/agent.cordis.yml')
const composed = `${HEADER}\n# ── copied from the shipped \`standard\` preset ──────────────────────────────\n\n${source.replace(/\s*$/, '\n')}${ROW}`
writeFileSync(target, composed, 'utf8')
console.log(`wrote ${target} (${composed.length} chars, ${composed.split('\n').length} lines)`)
