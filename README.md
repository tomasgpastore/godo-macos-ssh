# godo

`godo` is a guarded macOS CLI for natural-language automation over SSH.
It always shows the exact script first and only runs after explicit approval.

## Requirements
- macOS (tested for SSH use on Mac mini)
- Python 3.11+
- Ollama running locally on `http://localhost:11434`
- A local model pulled in Ollama (default in code: `ministral-3:8b`)

## Install
```bash
cd /Users/server/Documents/projects/godo_macmini
chmod +x godo.py
ln -sf "$(pwd)/godo.py" /usr/local/bin/godo
```

If `/usr/local/bin` is not writable, use another PATH directory.

## Usage
```bash
godo "natural language request"
godo --dry-run "natural language request"
godo --json "natural language request"
```

Output flow:
1. Restated intent
2. Risk level (`LOW`, `MEDIUM`, `HIGH`)
3. Proposed script in one copy-paste block
4. Approval prompt: `Run this now? (y/N)`

Only `y` or `yes` executes.

## Examples
```bash
godo "pause spotify"
godo "set spotify volume to 30"
godo "what is using ram"
godo "open obsidian"
```

## Safety Model
- The model returns JSON only and is schema-validated.
- `godo` compiles deterministic scripts from templates.
- `sudo` operations are never executed by `godo`.
- Banned tokens cause hard refusal (`sudo`, `rm`, `chmod`, `chown`, `diskutil`, `shutdown`, `reboot`, `launchctl system`, `curl`, `wget`, `python -c`, `node -e`).
- `osascript` plans containing `do shell script` are refused.
- Approved plans are logged to `/Users/server/.godo/logs`.

## Config (in `godo.py`)
The `CONFIG` dictionary controls:
- `allowed_roots`: default file-listing roots
- `ollama_base_url`: local Ollama endpoint
- `ollama_model`: model name
- `banned_tokens`: hard safety deny-list
- `log_dir`: audit log location

To add additional file roots, edit `CONFIG["allowed_roots"]` directly.

## Notes
- AppleScript actions target the active console user session; `godo` uses direct `osascript` when already in that user context and otherwise uses `launchctl asuser`.
- If Ollama is unreachable or returns invalid JSON twice, `godo` exits with an error.
- For local non-Ollama testing, you can inject a plan with `GODO_PLAN_JSON`.
