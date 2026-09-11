/**
 * Smoke tests for both halves of the plugin, with no dependencies beyond Node's
 * built-in test runner:
 *
 *   - `preset/plugin/security-review.mjs`, mounted the way a preset row mounts it
 *     (a scope context exposing `systemPrompt` and `tools`); and
 *   - `dynamic/host.js`, evaluated the way the dynamic Cordis Host runner
 *     evaluates a `cordis_define` half (a function body receiving `ctx` and
 *     `harness`, returning a Plugin object).
 *
 * Usage: node --test tests
 */

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { describe, it } from 'node:test'
import { fileURLToPath, pathToFileURL } from 'node:url'

const PROJECT = resolve(dirname(fileURLToPath(import.meta.url)), '..')

/**
 * Build a stand-in Cordis context recording every registration.
 * @returns {{ ctx: object, sections: object[], tools: Map<string, object> }} the fake context and its records.
 */
function fakeContext() {
  const sections = []
  const tools = new Map()
  const disposers = []
  const ctx = {
    effect(callback, label) {
      const dispose = callback()
      disposers.push({ label, dispose })
      return typeof dispose === 'function' ? dispose : () => {}
    },
    systemPrompt: {
      section(section) {
        sections.push(section)
        return () => {}
      },
    },
    tools: {
      register(tool) {
        if (tools.has(tool.name)) throw new Error(`duplicate tool ${tool.name}`)
        tools.set(tool.name, tool)
        return () => tools.delete(tool.name)
      },
    },
  }
  return { ctx, sections, tools, disposers }
}

/**
 * Mount the preset module's plugin in a fake scope.
 * @returns {Promise<{ tools: Map<string, object>, sections: object[], name: string, inject: string[] }>} what it registered.
 */
async function mountPresetPlugin() {
  const module = await import(pathToFileURL(resolve(PROJECT, 'preset/plugin/security-review.mjs')).href)
  const { ctx, sections, tools } = fakeContext()
  module.apply(ctx)
  return { tools, sections, name: module.name, inject: module.inject }
}

/**
 * Evaluate the generated dynamic half the way the sandbox does.
 * @returns {Promise<{ tools: Map<string, object>, sections: object[], name: string, inject: string[] }>} what it registered.
 */
async function mountDynamicPlugin() {
  const body = readFileSync(resolve(PROJECT, 'dynamic/host.js'), 'utf8')
  const { ctx, sections, tools } = fakeContext()
  const harness = {
    defineTool: definition => definition,
    registerTool(target, tool) {
      return target.tools.register(tool)
    },
  }
  // eslint-disable-next-line no-new-func -- this is exactly how the dynamic runner evaluates a Host half.
  const plugin = new Function('ctx', 'harness', body)(ctx, harness)
  plugin.apply(ctx)
  return { tools, sections, name: plugin.name, inject: plugin.inject }
}

/** The sample finding every finding-tool test builds on. */
const SAMPLE = {
  vulnerability_types: ['RCE'],
  file_path: 'server/llm_app.py',
  confidence_score: 8,
  analysis: 'req["llm_factory"] indexes a class table and is instantiated unvalidated.',
  poc: 'POST /add_llm {"llm_factory": "__import__(\'os\').system", "llm_name": "id"}',
  entry_point: 'POST /add_llm (JSON body)',
}

for (const [label, mount] of [['preset module', mountPresetPlugin], ['dynamic half', mountDynamicPlugin]]) {
  describe(`security-review (${label})`, () => {
    it('declares a name and injects both registries', async () => {
      const { name, inject } = await mount()
      assert.equal(name, 'security-review')
      assert.deepEqual(inject, ['tools', 'systemPrompt'])
    })

    it('registers one prompt section stating the review rules', async () => {
      const { sections } = await mount()
      assert.equal(sections.length, 1)
      assert.equal(sections[0].name, 'security-review:guidance')
      assert.equal(typeof sections[0].order, 'number')
      assert.match(sections[0].text, /remote user-input entry points/)
      assert.match(sections[0].text, /caps the confidence score at 6/)
      assert.match(sections[0].text, /sec_review_finding/)
    })

    it('registers the four review tools', async () => {
      const { tools } = await mount()
      assert.deepEqual([...tools.keys()].sort(), [
        'sec_review_finding',
        'sec_review_findings',
        'sec_review_methodology',
        'sec_review_playbook',
      ])
    })

    it('returns the cross-class inventory for a bare playbook call', async () => {
      const { tools } = await mount()
      const text = await tools.get('sec_review_playbook').execute({})
      assert.match(text, /INITIAL_ANALYSIS_PROMPT_TEMPLATE/)
      assert.match(text, /Locate potential vulnerability sinks/)
      assert.match(text, /LFI, RCE, XSS, AFO, SSRF, SQLI, IDOR/)
    })

    it('returns a verbatim class template with its upstream bypass examples', async () => {
      const { tools } = await mount()
      const text = await tools.get('sec_review_playbook').execute({ vulnerability_type: 'RCE' })
      assert.match(text, /RCE-Specific Focus Areas/)
      assert.match(text, /eval\(\), exec\(\), subprocess modules/)
      assert.match(text, /__import__\('os'\)\.system\('id'\)/)
      assert.match(text, /Example RCE-Specific Bypass Techniques/)
    })

    it('omits bypass examples when asked and rejects an unknown class', async () => {
      const { tools } = await mount()
      const tool = tools.get('sec_review_playbook')
      const text = await tool.execute({ vulnerability_type: 'SSRF', include_bypasses: false })
      assert.doesNotMatch(text, /0\.0\.0\.0:22/)
      await assert.rejects(() => tool.execute({ vulnerability_type: 'CSRF' }), /unknown vulnerability_type/)
    })

    it('appends the shared methodology only when requested', async () => {
      const { tools } = await mount()
      const tool = tools.get('sec_review_playbook')
      const plain = await tool.execute({ vulnerability_type: 'LFI' })
      assert.doesNotMatch(plain, /Reporting Guidelines/)
      const full = await tool.execute({ vulnerability_type: 'LFI', include_methodology: true })
      assert.match(full, /Reporting Guidelines/)
      assert.match(full, /Analysis Instructions/)
    })

    it('indexes the shared prompts and returns one verbatim', async () => {
      const { tools } = await mount()
      const tool = tools.get('sec_review_methodology')
      const index = await tool.execute({})
      assert.match(index, /INITIAL_ANALYSIS_PROMPT_TEMPLATE/)
      assert.match(index, /SYS_PROMPT_TEMPLATE/)
      const system = await tool.execute({ part: 'system' })
      assert.match(system, /world's foremost expert in Python security analysis/)
      const all = await tool.execute({ part: 'all' })
      for (const variable of ['ANALYSIS_APPROACH_TEMPLATE', 'GUIDELINES_TEMPLATE', 'README_SUMMARY_PROMPT_TEMPLATE']) {
        assert.match(all, new RegExp(variable))
      }
    })

    it('records a finding and reports it back', async () => {
      const { tools } = await mount()
      const exec = { agent: { id: 'session-1' } }
      const recorded = await tools.get('sec_review_finding').execute(SAMPLE, exec)
      assert.match(recorded, /Recorded finding #1/)
      assert.match(recorded, /\[high\] RCE — server\/llm_app\.py/)
      assert.match(recorded, /confidence_score: 8\/10/)
      const report = await tools.get('sec_review_findings').execute({}, exec)
      assert.match(report, /# Security review report/)
      assert.match(report, /1 finding\(s\): 1 high/)
      assert.match(report, /RCE: 1/)
      assert.match(report, /server\/llm_app\.py/)
    })

    it('validates findings instead of storing junk', async () => {
      const { tools } = await mount()
      const tool = tools.get('sec_review_finding')
      const exec = { agent: { id: 'session-1' } }
      await assert.rejects(() => tool.execute({ ...SAMPLE, confidence_score: 11 }, exec), /confidence_score/)
      await assert.rejects(() => tool.execute({ ...SAMPLE, confidence_score: 7.5 }, exec), /confidence_score/)
      await assert.rejects(() => tool.execute({ ...SAMPLE, poc: '  ' }, exec), /poc/)
      await assert.rejects(() => tool.execute({ ...SAMPLE, vulnerability_types: [] }, exec), /at least one class/)
      await assert.rejects(() => tool.execute({ ...SAMPLE, vulnerability_types: ['CSRF'] }, exec), /unknown vulnerability type/)
      const empty = await tools.get('sec_review_findings').execute({}, exec)
      assert.match(empty, /No findings recorded/)
    })

    it('keeps findings per session and exports lossless JSON', async () => {
      const { tools } = await mount()
      const one = { agent: { id: 'session-1' } }
      const two = { agent: { id: 'session-2' } }
      await tools.get('sec_review_finding').execute({ ...SAMPLE, confidence_score: 6 }, one)
      await tools.get('sec_review_finding').execute({ ...SAMPLE, confidence_score: 9, vulnerability_types: ['SSRF'] }, one)
      const exported = JSON.parse(await tools.get('sec_review_findings').execute({ format: 'json' }, one))
      assert.equal(exported.summary.total, 2)
      assert.deepEqual(exported.summary.byClass, { RCE: 1, SSRF: 1 })
      assert.equal(exported.findings[0].confidence_score, 9)
      assert.equal(exported.findings[0].severity, 'high')
      assert.match(await tools.get('sec_review_findings').execute({ min_confidence: 9 }, one), /1 finding/)

      const other = await tools.get('sec_review_findings').execute({}, two)
      assert.match(other, /No findings recorded/)

      const cleared = await tools.get('sec_review_findings').execute({ clear: true }, one)
      assert.match(cleared, /2 finding/)
      assert.match(await tools.get('sec_review_findings').execute({}, one), /No findings recorded/)
    })

    it('declares model-facing schemas for every tool', async () => {
      const { tools } = await mount()
      for (const tool of tools.values()) {
        assert.equal(typeof tool.description, 'string')
        assert.ok(tool.description.length > 40, `${tool.name} needs a real description`)
        assert.equal(tool.parameters.type, 'object')
        assert.equal(typeof tool.parameters.properties, 'object')
        assert.deepEqual(tool.output.schema, { type: 'string' })
        const blocks = tool.output.render({}, 'rendered')
        assert.deepEqual(blocks, [{ type: 'text', text: 'rendered' }])
      }
      const playbook = tools.get('sec_review_playbook')
      assert.deepEqual(playbook.parameters.properties.vulnerability_type.enum,
        ['LFI', 'RCE', 'XSS', 'AFO', 'SSRF', 'SQLI', 'IDOR'])
      assert.deepEqual(tools.get('sec_review_finding').parameters.required,
        ['vulnerability_types', 'file_path', 'confidence_score', 'analysis', 'poc'])
    })
  })
}
