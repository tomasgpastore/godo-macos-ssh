#!/usr/bin/env python3
"""godo: guarded natural-language macOS automation over SSH."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shlex
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

CONFIG = {
    "allowed_roots": [
        "/Users/server/Documents",
        "/Users/server/Downloads",
    ],
    "ollama_base_url": os.getenv("GODO_OLLAMA_BASE_URL", "http://localhost:11434"),
    "ollama_model": os.getenv("GODO_OLLAMA_MODEL", "llama3.1:8b"),
    "banned_tokens": [
        "sudo",
        "rm",
        "chmod",
        "chown",
        "diskutil",
        "shutdown",
        "reboot",
        "launchctl system",
        "curl",
        "wget",
        "python -c",
        "node -e",
    ],
    "log_dir": "/Users/server/.godo/logs",
}

SYSTEM_PROMPT = """You are godo, a macOS command planner.
Return exactly one JSON object and no other text.
No markdown. No explanation.

Required schema:
{
  "intent": "string",
  "risk": "LOW|MEDIUM|HIGH",
  "category": "spotify|app|sysinfo|files",
  "action": "string",
  "args": { ... },
  "requires_gui_session": true|false
}

Rules:
- args must always be a JSON object.
- Supported spotify actions: play, pause, playpause, next, previous, set_volume, current_track.
- Supported app actions: open, quit. Use args.app_name.
- Supported sysinfo actions: memory_summary, cpu_top, disk_usage, processes_by_memory.
- Supported files actions: list_files with optional args.path and args.max_depth.
- If the request needs administrator privileges or is unsupported/destructive, set risk HIGH, keep a best-fit category, set action to manual_admin_required, and add args.reason.
- requires_gui_session should be true for AppleScript app-control/spotify actions.
"""

REPAIR_PROMPT = """Your previous response was invalid.
Return one valid JSON object only.
Do not include markdown or commentary.
"""

RISK_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
REQUIRED_PLAN_KEYS = {
    "intent",
    "risk",
    "category",
    "action",
    "args",
    "requires_gui_session",
}
ALLOWED_CATEGORIES = {"spotify", "app", "sysinfo", "files"}
ALLOWED_RISKS = {"LOW", "MEDIUM", "HIGH"}


class GodoError(Exception):
    """Application-level error with clear user-facing messaging."""


@dataclass(frozen=True)
class Plan:
    intent: str
    risk: str
    category: str
    action: str
    args: dict[str, Any]
    requires_gui_session: bool


@dataclass(frozen=True)
class CompiledPlan:
    script: str
    risk: str
    executable: bool


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="godo",
        description="Plan safe macOS commands from natural language and ask before execution.",
    )
    parser.add_argument("request", help="Natural language request")
    parser.add_argument("--dry-run", action="store_true", help="Never execute; print plan only")
    parser.add_argument("--json", action="store_true", help="Print model JSON and compiled script")
    return parser.parse_args()


def post_ollama_chat(messages: list[dict[str, str]]) -> str:
    payload = {
        "model": CONFIG["ollama_model"],
        "stream": False,
        "format": "json",
        "messages": messages,
    }
    data = json.dumps(payload).encode("utf-8")
    base_url = str(CONFIG["ollama_base_url"]).rstrip("/")
    request = urllib.request.Request(
        f"{base_url}/api/chat",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            body = response.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as exc:
        raise GodoError(
            f"Failed to reach Ollama at {base_url}. "
            "Ensure Ollama is running and the model is available."
        ) from exc

    try:
        parsed = json.loads(body)
        content = parsed["message"]["content"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise GodoError("Unexpected Ollama response format.") from exc

    if not isinstance(content, str) or not content.strip():
        raise GodoError("Ollama returned an empty plan.")
    return content.strip()


def parse_json_object(raw_text: str) -> dict[str, Any] | None:
    text = raw_text.strip()
    candidates = [text]
    if "{" in text and "}" in text and (not text.startswith("{") or not text.endswith("}")):
        candidates.append(text[text.find("{") : text.rfind("}") + 1])

    for candidate in candidates:
        try:
            obj = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            return obj
    return None


def normalize_token(token: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", token.strip().lower()).strip("_")


def normalize_action(category: str, action: str) -> str:
    token = normalize_token(action)
    maps = {
        "spotify": {
            "resume": "play",
            "toggle": "playpause",
            "play_pause": "playpause",
            "next_track": "next",
            "prev": "previous",
            "previous_track": "previous",
            "volume": "set_volume",
            "setvolume": "set_volume",
            "now_playing": "current_track",
            "get_current_track": "current_track",
            "track": "current_track",
        },
        "app": {
            "open_app": "open",
            "launch": "open",
            "quit_app": "quit",
            "close": "quit",
            "exit": "quit",
        },
        "sysinfo": {
            "memory": "memory_summary",
            "ram": "memory_summary",
            "cpu": "cpu_top",
            "cpu_processes": "cpu_top",
            "disk": "disk_usage",
            "storage": "disk_usage",
            "processes": "processes_by_memory",
            "ram_processes": "processes_by_memory",
            "top_memory": "processes_by_memory",
        },
        "files": {
            "list": "list_files",
            "ls": "list_files",
            "list_directory": "list_files",
            "show_files": "list_files",
        },
    }
    return maps.get(category, {}).get(token, token)


def validate_plan(obj: dict[str, Any]) -> Plan:
    keys = set(obj.keys())
    if keys != REQUIRED_PLAN_KEYS:
        missing = REQUIRED_PLAN_KEYS - keys
        extras = keys - REQUIRED_PLAN_KEYS
        raise GodoError(
            "Invalid model JSON schema. "
            f"Missing keys: {sorted(missing)}. Extra keys: {sorted(extras)}."
        )

    intent = obj["intent"]
    risk = obj["risk"]
    category = obj["category"]
    action = obj["action"]
    args = obj["args"]
    requires_gui_session = obj["requires_gui_session"]

    if not isinstance(intent, str) or not intent.strip():
        raise GodoError("Invalid plan: 'intent' must be a non-empty string.")
    if not isinstance(risk, str) or risk.upper() not in ALLOWED_RISKS:
        raise GodoError("Invalid plan: 'risk' must be LOW, MEDIUM, or HIGH.")
    if not isinstance(category, str) or category.lower() not in ALLOWED_CATEGORIES:
        raise GodoError("Invalid plan: unsupported 'category'.")
    if not isinstance(action, str) or not action.strip():
        raise GodoError("Invalid plan: 'action' must be a non-empty string.")
    if not isinstance(args, dict):
        raise GodoError("Invalid plan: 'args' must be an object.")
    if not isinstance(requires_gui_session, bool):
        raise GodoError("Invalid plan: 'requires_gui_session' must be boolean.")

    normalized_category = category.lower()
    normalized_action = normalize_action(normalized_category, action)
    return Plan(
        intent=intent.strip(),
        risk=risk.upper(),
        category=normalized_category,
        action=normalized_action,
        args=args,
        requires_gui_session=requires_gui_session,
    )


def plan_from_model(request_text: str) -> tuple[Plan, dict[str, Any]]:
    injected_json = os.getenv("GODO_PLAN_JSON", "").strip()
    if injected_json:
        parsed = parse_json_object(injected_json)
        if parsed is None:
            raise GodoError("GODO_PLAN_JSON is set but not valid JSON.")
        plan = validate_plan(parsed)
        return plan, parsed

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": request_text},
    ]
    first_response = post_ollama_chat(messages)
    parsed = parse_json_object(first_response)

    if parsed is None:
        repair_messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "system", "content": REPAIR_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Original user request: {request_text}\n"
                    f"Invalid response: {first_response}"
                ),
            },
        ]
        second_response = post_ollama_chat(repair_messages)
        parsed = parse_json_object(second_response)
        if parsed is None:
            raise GodoError("Model returned invalid JSON twice. Refusing execution.")

    plan = validate_plan(parsed)
    return plan, parsed


def stronger_risk(risk_a: str, risk_b: str) -> str:
    return risk_a if RISK_ORDER[risk_a] >= RISK_ORDER[risk_b] else risk_b


def build_asuser_osascript(applescript_body: str) -> str:
    return "\n".join(
        [
            "CONSOLE_USER=$(stat -f%Su /dev/console)",
            "CONSOLE_UID=$(id -u \"$CONSOLE_USER\")",
            'launchctl asuser "$CONSOLE_UID" osascript <<\'APPLESCRIPT\'',
            applescript_body,
            "APPLESCRIPT",
        ]
    )


def escape_applescript_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def extract_app_name(args: dict[str, Any]) -> str:
    for key in ("app_name", "app", "name"):
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    raise GodoError("App action requires args.app_name.")


def extract_volume(args: dict[str, Any]) -> int:
    for key in ("volume", "level", "value"):
        if key in args:
            try:
                value = int(args[key])
            except (TypeError, ValueError) as exc:
                raise GodoError("Spotify volume must be an integer between 0 and 100.") from exc
            if 0 <= value <= 100:
                return value
            raise GodoError("Spotify volume must be between 0 and 100.")
    raise GodoError("Spotify set_volume requires args.volume.")


def resolve_allowed_path(path_input: str) -> str:
    requested = os.path.realpath(os.path.expanduser(path_input))
    allowed_roots = [os.path.realpath(root) for root in CONFIG["allowed_roots"]]

    for root in allowed_roots:
        try:
            if os.path.commonpath([requested, root]) == root:
                return requested
        except ValueError:
            continue

    roots_text = ", ".join(CONFIG["allowed_roots"])
    raise GodoError(
        f"Refusing path outside allowed roots: {requested}. "
        f"Allowed roots are: {roots_text}."
    )


def compile_spotify_script(action: str, args: dict[str, Any]) -> str:
    if action == "play":
        applescript = 'tell application "Spotify" to play'
    elif action == "pause":
        applescript = 'tell application "Spotify" to pause'
    elif action == "playpause":
        applescript = 'tell application "Spotify" to playpause'
    elif action == "next":
        applescript = 'tell application "Spotify" to next track'
    elif action == "previous":
        applescript = 'tell application "Spotify" to previous track'
    elif action == "set_volume":
        volume = extract_volume(args)
        applescript = f'tell application "Spotify" to set sound volume to {volume}'
    elif action == "current_track":
        applescript = "\n".join(
            [
                'tell application "Spotify"',
                "  if player state is stopped then",
                '    return "Nothing is playing"',
                "  end if",
                "  set trackName to name of current track",
                "  set artistName to artist of current track",
                '  return trackName & " - " & artistName',
                "end tell",
            ]
        )
    else:
        raise GodoError(f"Unsupported Spotify action: {action}")

    return build_asuser_osascript(applescript)


def compile_app_script(action: str, args: dict[str, Any]) -> tuple[str, bool]:
    app_name = extract_app_name(args)
    if action == "open":
        script = f"open -a {shlex.quote(app_name)}"
        return script, False

    if action == "quit":
        escaped = escape_applescript_string(app_name)
        applescript = f'tell application "{escaped}" to quit'
        return build_asuser_osascript(applescript), True

    raise GodoError(f"Unsupported app action: {action}")


def compile_sysinfo_script(action: str) -> str:
    if action == "memory_summary":
        return "\n".join(
            [
                "top -l 1 | grep PhysMem",
                "vm_stat",
            ]
        )
    if action == "cpu_top":
        return "ps -Ao pid,ppid,%cpu,%mem,comm -r | head -n 15"
    if action == "disk_usage":
        return "df -h"
    if action == "processes_by_memory":
        return "ps -Ao pid,ppid,%mem,%cpu,rss,comm -r | head -n 20"
    raise GodoError(f"Unsupported sysinfo action: {action}")


def compile_files_script(action: str, args: dict[str, Any]) -> str:
    if action != "list_files":
        raise GodoError(f"Unsupported files action: {action}")

    path_input = str(args.get("path", CONFIG["allowed_roots"][0]))
    resolved = resolve_allowed_path(path_input)

    depth_raw = args.get("max_depth", 2)
    try:
        depth = int(depth_raw)
    except (TypeError, ValueError) as exc:
        raise GodoError("files.list_files max_depth must be an integer.") from exc
    depth = max(1, min(depth, 8))

    return (
        f"find {shlex.quote(resolved)} -maxdepth {depth} -mindepth 1 -print | sort"
    )


def compile_manual_plan(reason: str) -> str:
    _ = reason
    return "\n".join(
        [
            "cat <<'EOF'",
            "godo will not execute this request.",
            "This request requires administrator privileges or is outside godo v1 scope.",
            "Manual steps:",
            "1) Open an administrator shell on the Mac mini.",
            "2) Review the intended command for safety.",
            "3) Run it manually if you approve the impact.",
            "EOF",
        ]
    )


def compile_plan(plan: Plan) -> CompiledPlan:
    requested_risk = plan.risk
    action = plan.action

    admin_requested = bool(plan.args.get("requires_admin")) or bool(
        plan.args.get("requires_sudo")
    )
    if action == "manual_admin_required" or admin_requested:
        reason = str(plan.args.get("reason", "Administrator-level work requested."))
        return CompiledPlan(script=compile_manual_plan(reason), risk="HIGH", executable=False)

    if plan.category == "spotify":
        script = compile_spotify_script(action, plan.args)
        minimum_risk = "LOW"
    elif plan.category == "app":
        script, _requires_gui = compile_app_script(action, plan.args)
        minimum_risk = "LOW"
    elif plan.category == "sysinfo":
        script = compile_sysinfo_script(action)
        minimum_risk = "LOW"
    elif plan.category == "files":
        script = compile_files_script(action, plan.args)
        minimum_risk = "MEDIUM"
    else:
        script = compile_manual_plan("Unsupported category for this version.")
        minimum_risk = "HIGH"
        return CompiledPlan(script=script, risk="HIGH", executable=False)

    final_risk = stronger_risk(requested_risk, minimum_risk)
    return CompiledPlan(script=script, risk=final_risk, executable=True)


def detect_banned_tokens(script: str) -> list[str]:
    lowered = script.lower()
    found: list[str] = []

    checks = {
        "sudo": r"\bsudo\b",
        "rm": r"\brm\b",
        "chmod": r"\bchmod\b",
        "chown": r"\bchown\b",
        "diskutil": r"\bdiskutil\b",
        "shutdown": r"\bshutdown\b",
        "reboot": r"\breboot\b",
        "launchctl system": r"\blaunchctl\s+system\b",
        "curl": r"\bcurl\b",
        "wget": r"\bwget\b",
        "python -c": r"\bpython(?:3)?\s+-c\b",
        "node -e": r"\bnode\s+-e\b",
    }

    for token in CONFIG["banned_tokens"]:
        pattern = checks.get(token)
        if pattern and re.search(pattern, lowered):
            found.append(token)

    if "osascript" in lowered and "do shell script" in lowered:
        found.append('osascript with "do shell script"')

    return found


def print_plan(plan: Plan, compiled: CompiledPlan, plan_json: dict[str, Any], show_json: bool) -> None:
    print(f"Intent: {plan.intent}")
    print(f"Risk: {compiled.risk}")
    print("Proposed script:")
    print("```bash")
    print(compiled.script)
    print("```")

    if show_json:
        print("Model JSON:")
        print(json.dumps(plan_json, indent=2, sort_keys=True))
        print("Compiled script (debug):")
        print("```bash")
        print(compiled.script)
        print("```")


def log_approved_command(plan: Plan, plan_json: dict[str, Any], compiled: CompiledPlan) -> None:
    timestamp = dt.datetime.now(dt.timezone.utc).astimezone().isoformat()
    entry = {
        "timestamp": timestamp,
        "intent": plan.intent,
        "risk": compiled.risk,
        "json": plan_json,
        "script": compiled.script,
    }

    log_dir = str(CONFIG["log_dir"])
    date_part = dt.date.today().isoformat()
    log_path = os.path.join(log_dir, f"godo-{date_part}.jsonl")

    try:
        os.makedirs(log_dir, exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=True) + "\n")
    except OSError as exc:
        raise GodoError(
            f"Failed to write audit log at {log_path}. Refusing execution."
        ) from exc


def run_script(script: str) -> int:
    result = subprocess.run(  # noqa: S602 - deterministic template script
        script,
        shell=True,
        executable="/bin/bash",
        capture_output=True,
        text=True,
    )

    if result.stdout:
        print(result.stdout, end="" if result.stdout.endswith("\n") else "\n")
    if result.stderr:
        print(
            result.stderr,
            end="" if result.stderr.endswith("\n") else "\n",
            file=sys.stderr,
        )

    return result.returncode


def prompt_for_approval() -> bool:
    answer = input("Run this now? (y/N): ").strip().lower()
    return answer in {"y", "yes"}


def main() -> int:
    args = parse_args()

    try:
        plan, plan_json = plan_from_model(args.request)
        compiled = compile_plan(plan)

        banned_hits = detect_banned_tokens(compiled.script)
        if banned_hits:
            raise GodoError(
                "Refusing plan due to banned token(s): " + ", ".join(sorted(set(banned_hits)))
            )

        print_plan(plan, compiled, plan_json, args.json)

        if compiled.risk in {"MEDIUM", "HIGH"}:
            print(
                f"WARNING: {compiled.risk} risk action. Review every line before approval."
            )

        if args.dry_run:
            print("Dry run mode: not executing.")
            return 0

        if not prompt_for_approval():
            print("Not executed.")
            return 0

        log_approved_command(plan, plan_json, compiled)

        if not compiled.executable:
            print("Execution disabled for this plan.")
            return 0

        return run_script(compiled.script)
    except GodoError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
