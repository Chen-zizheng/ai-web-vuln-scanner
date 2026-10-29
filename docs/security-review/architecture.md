# Architecture summary — ai-web-vuln-scanner

Source ref d86d1eea119e4372a8cea878729e767451eb3a15. Quick profile, one all-in-scope subsystem
identity, single wave. 13 in-scope files, 980 lines of Python.

## Product, principals, protected resources

A local Tk desktop application. One principal: the analyst sitting at the machine. They pick an
HTML file, the app extracts structural features, asks a hosted model (DeepSeek chat completions,
model "deepseek-flash") to name XSS and SQL-injection risks, and writes a JSON plus a Markdown
report into ./output. There is no server, no account, no second user, no tenant, no stored state
beyond the generated reports and the eval cache.

Protected resources: (1) the contents of the HTML file the analyst scans, (2) the analyst's
DeepSeek API credential, (3) the integrity of the verdict the analyst acts on, (4) the analyst's
API quota and workstation memory.

## Comparable baseline

Comparable local scanners (e.g. desktop wrappers around an LLM) typically accept the same trade-off:
page text goes to a hosted model because the analysis needs it, and the tool documents that. The
trade-off this repository does not make explicit is the *volume*: there is no statement that whole
script bodies leave the machine, no payload preview, and no size cap, so the analyst cannot tell
what was disclosed or whether a scan was even served.

## Tech stack and offline limits

Pure Python 3.9+, requirements requests / beautifulsoup4 / pytest, all unpinned. Tkinter UI, no
packaging metadata, no setup.py or pyproject. CI is GitHub Actions on ubuntu-latest running pytest.
Offline limit: no DEEPSEEK_API_KEY and no outbound network in the audit environment, so every
model-behaviour claim is needs_validation rather than confirmed.

## Entry surfaces and important paths

- main.py:99 start_scan -> main.py:104 is_file -> main.py:109 worker thread -> main.py:114
  read_text -> scanner_core.py:13 extract_features -> scanner_core.py:43 build_prompt ->
  scanner_core.py:61 call_llm (HTTPS to api.deepseek.com) -> main.py:10 save_report.
- eval.py:131 main (CLI) -> eval.py:107 load_dataset -> eval.py:84 backend_heuristic or the
  DeepSeek backend -> eval/results.json + eval/report.md.
- .github/workflows/test.yml:23-31 pip install -r requirements.txt, then pytest.

## Trust boundaries and strongest source-visible control on each

1. Local file -> process memory: main.py:104 is_file only. No size limit, no content restriction.
2. Process -> third-party API: scanner_core.py:62-63 checks that a key exists. Nothing else filters
   the outbound body, and nothing records what was sent.
3. Unattributed page text -> model instruction turn: none. One f-string, no delimiters, no data
   notice, no second channel.
4. Model reply -> report file: main.py:17 writes it as JSON data (safe), main.py:25-28 interpolates
   it into Markdown (no escaping, but the sink is a local data file).
5. Upstream packages -> workstation and CI: none. No pins, no hashes, actions on moving major tags.

## Repository-relative starting paths

main.py, scanner_core.py, requirements.txt, .github/workflows/test.yml, eval.py.

## Prior coverage and exclusions

No prior run. Excluded: 扫描器.png (screenshot). Not applicable by construction: memory safety (pure
Python, no native extension), inbound network service (no socket).

## Companion selection

AI-AND-LLM.md — the decisive path is untrusted page text entering a model context and the model
reply becoming a security verdict. SUPPLY-CHAIN-AND-RELEASE.md — unpinned runtime and CI inputs.
RESOURCE-EXHAUSTION-AND-AVAILABILITY.md — unbounded input to a request-assembly sink and a
cross-thread UI failure mode.
