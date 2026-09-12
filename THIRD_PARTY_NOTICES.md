# Third-party notices

This project is a derivative work of **VulnHuntr**. It contains no VulnHuntr
source code, but it reproduces, verbatim, the text of several prompt string
literals that VulnHuntr defines.

## Upstream project

| | |
| --- | --- |
| Project | VulnHuntr |
| Repository | https://github.com/protectai/vulnhuntr |
| Owner | Protect AI (`protectai`) |
| Authors | Dan McInerney `<dan@protectai.com>` ([@DanHMcinerney](https://x.com/DanHMcinerney)), Marcello Salvati `<marcello@protectai.com>` ([@byt3bl33d3r](https://x.com/byt3bl33d3r)) |
| License | GNU Affero General Public License v3.0 (AGPL-3.0) |
| License text | https://github.com/protectai/vulnhuntr/blob/main/LICENSE |

## What was copied

Source file: `vulnhuntr/prompts.py` at upstream commit state whose SHA-256 is

```
101c6d48fb787cd684a3fa1e8bc94e0ec584b08aff38a217d87f0a188fb55374
```

Reproduced verbatim — the **values** of these string literals, byte for byte,
including leading and trailing newlines:

| Kind | Upstream names | Count |
| --- | --- | --- |
| Per-class analysis templates | `LFI_TEMPLATE`, `RCE_TEMPLATE`, `XSS_TEMPLATE`, `AFO_TEMPLATE`, `SSRF_TEMPLATE`, `SQLI_TEMPLATE`, `IDOR_TEMPLATE` | 7 (8,390 chars together) |
| Shared prompts | `INITIAL_ANALYSIS_PROMPT_TEMPLATE`, `README_SUMMARY_PROMPT_TEMPLATE`, `GUIDELINES_TEMPLATE`, `ANALYSIS_APPROACH_TEMPLATE`, `SYS_PROMPT_TEMPLATE` | 5 (5,974 chars together) |
| Example bypass payload strings | the `bypasses` lists inside `VULN_SPECIFIC_BYPASSES_AND_PROMPTS` | 32 strings |

Total reproduced prompt text: **14,364 characters**.

Where that text now lives in this repository:

- `src/prompts.json` — the extracted dataset, with the upstream source name and
  the SHA-256 above recorded inside it;
- `preset/plugin/prompts.mjs` — generated from that dataset;
- `dynamic/host.js` — generated from the same module, with the dataset inlined;
- `tests/plugin.spec.mjs` — quotes a few **short phrases** from the prompts as
  regression assertions (e.g. to prove extraction did not mangle a template).

## What was not copied

- No VulnHuntr source file is copied, vendored, or modified. The extraction is
  performed by `scripts/extract-prompts.mjs`, which parses the Python string
  literals in `vulnhuntr/prompts.py` without executing Python; upstream is read
  only at extraction time and is not redistributed here.
- No VulnHuntr code (its analyzers, `symbol_finder.py`, `LLMs.py`, CLI, or
  prompts-assembly logic) is present in this project. The Cordis plugin, the
  build and install scripts, the tests, and the documentation are original work.

## Why this project is AGPL-3.0-only

VulnHuntr is distributed under the AGPL-3.0 license text and states no "or any
later version" grant, so the derivative as a whole is licensed under
**AGPL-3.0-only** — the version VulnHuntr grants, and no later one. The full
license text is in `LICENSE`.

If you redistribute this project or a modified version of it, the AGPL's
obligations apply to the whole distribution: ship the license text, keep these
notices, mark your changes, and provide the corresponding source. If you run a
modified version as a network service, section 13 requires you to offer its
source to the users of that service.

## Disclaimer

This project is an independent work. It is **not affiliated with, sponsored by,
or endorsed by Protect AI** or the VulnHuntr authors. "VulnHuntr" is used only
to identify the origin of the prompt text and the methodology it implements.
