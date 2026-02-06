#!/usr/bin/env python3
"""godo: guarded natural-language macOS automation over SSH."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pwd
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
    "ollama_model": os.getenv("GODO_OLLAMA_MODEL", "ministral-3:8b"),
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
  "category": "spotify|app|sysinfo|files|shell",
  "action": "string",
  "args": { ... },
  "requires_gui_session": true|false
}

Rules:
- args must always be a JSON object.
- Never add extra keys beyond the required schema keys.
- Never return arrays or markdown. Return exactly one JSON object.
- Never include sudo, destructive actions, or unsupported shell operators in args.
- If the request needs administrator privileges, privileged file mutation, destructive operations, or unsupported shell syntax, set risk HIGH, set action to manual_admin_required, and set args.reason.
- requires_gui_session must be true for Spotify and AppleScript app quit actions.

Category instructions:
- spotify:
  - actions: play, pause, playpause, next, previous, set_volume, current_track
  - set_volume requires args.volume integer 0-100
- app:
  - actions: open, quit
  - args.app_name required
- sysinfo:
  - actions: memory_summary, cpu_top, disk_usage, processes_by_memory
- files:
  - action: list_files
  - optional args.path string, args.max_depth integer
- shell:
  - action: run_shell
  - args.executable required string (single binary/command name, no spaces)
  - args.arguments optional array of strings
  - args.working_directory optional string
  - if needed, args.raw_command allowed only for a single command with no shell operators

Reliability guidance:
- Prefer built-in categories over shell when possible.
- For user intents that map to shell, choose standard macOS CLI commands.
- Keep args deterministic and minimal.
- Example shell mappings:
  - "show git status" -> {"category":"shell","action":"run_shell","args":{"executable":"git","arguments":["status","-sb"]}}
  - "list home directory" -> {"category":"shell","action":"run_shell","args":{"executable":"ls","arguments":["-la","/Users/server"]}}
  - "show python version" -> {"category":"shell","action":"run_shell","args":{"executable":"python3","arguments":["--version"]}}
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
ALLOWED_CATEGORIES = {"spotify", "app", "sysinfo", "files", "shell"}
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
    display_script: str
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
        "shell": {
            "run": "run_shell",
            "execute": "run_shell",
            "command": "run_shell",
            "shell": "run_shell",
            "run_command": "run_shell",
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
            "CURRENT_UID=$(id -u)",
            'CONSOLE_USER=$(stat -f%Su /dev/console 2>/dev/null || true)',
            'if launchctl print "gui/$CURRENT_UID" >/dev/null 2>&1; then',
            "  TARGET_UID=\"$CURRENT_UID\"",
            'elif [[ -n "$CONSOLE_USER" && "$CONSOLE_USER" != "root" && "$CONSOLE_USER" != "loginwindow" ]]; then',
            "  TARGET_UID=$(id -u \"$CONSOLE_USER\")",
            "else",
            '  echo "No active GUI console user session found." >&2',
            "  exit 1",
            "fi",
            'if [[ "$CURRENT_UID" -eq "$TARGET_UID" ]]; then',
            "  osascript <<'APPLESCRIPT'",
            applescript_body,
            "APPLESCRIPT",
            "else",
            '  launchctl asuser "$TARGET_UID" osascript <<\'APPLESCRIPT\'',
            applescript_body,
            "APPLESCRIPT",
            "fi",
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


def build_display_osascript(applescript_body: str) -> str:
    lines = [line.strip() for line in applescript_body.splitlines() if line.strip()]
    inline = "; ".join(lines)
    return f"osascript -e {shlex.quote(inline)}"


def compile_spotify_script(action: str, args: dict[str, Any]) -> tuple[str, str]:
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

    return build_asuser_osascript(applescript), build_display_osascript(applescript)


def compile_app_script(action: str, args: dict[str, Any]) -> tuple[str, str]:
    app_name = extract_app_name(args)
    if action == "open":
        script = f"open -a {shlex.quote(app_name)}"
        return script, script

    if action == "quit":
        escaped = escape_applescript_string(app_name)
        applescript = f'tell application "{escaped}" to quit'
        return build_asuser_osascript(applescript), build_display_osascript(applescript)

    raise GodoError(f"Unsupported app action: {action}")


def compile_sysinfo_script(action: str) -> tuple[str, str]:
    if action == "memory_summary":
        script = "\n".join(
            [
                "top -l 1 | grep PhysMem",
                "vm_stat",
            ]
        )
        return script, "top -l 1 | grep PhysMem && vm_stat"
    if action == "cpu_top":
        script = "ps -Ao pid,ppid,%cpu,%mem,comm -r | head -n 15"
        return script, script
    if action == "disk_usage":
        script = "df -h"
        return script, script
    if action == "processes_by_memory":
        script = "ps -Ao pid,ppid,%mem,%cpu,rss,comm -r | head -n 20"
        return script, script
    raise GodoError(f"Unsupported sysinfo action: {action}")


def compile_files_script(action: str, args: dict[str, Any]) -> tuple[str, str]:
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

    script = f"find {shlex.quote(resolved)} -maxdepth {depth} -mindepth 1 -print | sort"
    return script, script


def extract_shell_command_parts(args: dict[str, Any]) -> tuple[str, list[str]]:
    raw_command = args.get("raw_command")
    if isinstance(raw_command, str) and raw_command.strip():
        raw = raw_command.strip()
        if any(op in raw for op in ("|", ";", "&&", "||", "`", "$(", "<", ">")):
            raise GodoError(
                "shell.raw_command may only contain a single command without shell operators."
            )
        try:
            parts = shlex.split(raw)
        except ValueError as exc:
            raise GodoError("Invalid shell.raw_command format.") from exc
        if not parts:
            raise GodoError("shell.raw_command did not produce a valid command.")
        return parts[0], parts[1:]

    executable = args.get("executable")
    if not isinstance(executable, str) or not executable.strip():
        raise GodoError("shell.run_shell requires args.executable.")
    executable = executable.strip()
    if any(ch in executable for ch in (" ", "\t", "\n", "|", "&", ";", "<", ">")):
        raise GodoError("shell.executable must be a single command name without operators.")

    arguments_raw = args.get("arguments", [])
    if not isinstance(arguments_raw, list):
        raise GodoError("shell.arguments must be an array of strings.")

    arguments: list[str] = []
    for value in arguments_raw:
        if not isinstance(value, str):
            raise GodoError("shell.arguments must contain strings only.")
        arguments.append(value)
    return executable, arguments


def get_shell_minimum_risk(executable: str) -> str:
    low_risk = {
        "cat",
        "date",
        "df",
        "du",
        "echo",
        "find",
        "grep",
        "head",
        "id",
        "ls",
        "ps",
        "pwd",
        "rg",
        "stat",
        "sw_vers",
        "sysctl",
        "tail",
        "top",
        "uname",
        "uptime",
        "vm_stat",
        "whoami",
        "which",
    }
    high_risk = {
        "brew",
        "defaults",
        "kill",
        "killall",
        "launchctl",
        "ln",
        "mkdir",
        "mv",
        "networksetup",
        "osascript",
        "pkill",
        "softwareupdate",
        "touch",
    }
    if executable in high_risk:
        return "HIGH"
    if executable in low_risk:
        return "LOW"
    return "MEDIUM"


def compile_shell_script(action: str, args: dict[str, Any]) -> tuple[str, str, str]:
    if action != "run_shell":
        raise GodoError(f"Unsupported shell action: {action}")

    executable, arguments = extract_shell_command_parts(args)
    command = " ".join([shlex.quote(executable), *[shlex.quote(arg) for arg in arguments]])
    display = command

    working_directory = args.get("working_directory")
    if working_directory is not None:
        if not isinstance(working_directory, str) or not working_directory.strip():
            raise GodoError("shell.working_directory must be a non-empty string.")
        resolved_dir = os.path.realpath(os.path.expanduser(working_directory))
        command = f"cd {shlex.quote(resolved_dir)} && {command}"
        display = command

    return command, display, get_shell_minimum_risk(executable)


def compile_manual_plan(reason: str) -> str:
    _ = reason
    return "\n".join(
        [
            "cat <<'EOF'",
            "godo will not execute this request.",
            "This request requires administrator privileges or is outside godo v1.1 scope.",
            "Manual steps:",
            "1) Open an administrator shell on the Mac mini.",
            "2) Review the intended command for safety.",
            "3) Run it manually if you approve the impact.",
            "EOF",
        ]
    )


def compile_no_gui_session_plan() -> str:
    return "\n".join(
        [
            "cat <<'EOF'",
            "godo will not execute this request.",
            "No active macOS GUI console session is available.",
            "Manual steps:",
            "1) Sign in to the Mac mini desktop as the target user.",
            "2) Keep that desktop session active and unlocked.",
            "3) Run the godo command again from SSH.",
            "EOF",
        ]
    )


def get_console_user() -> str | None:
    current_uid = os.getuid()
    try:
        gui_check = subprocess.run(
            ["/bin/launchctl", "print", f"gui/{current_uid}"],
            capture_output=True,
            text=True,
            check=False,
        )
        if gui_check.returncode == 0:
            return pwd.getpwuid(current_uid).pw_name
    except (OSError, KeyError):
        pass

    try:
        result = subprocess.run(
            ["/usr/bin/stat", "-f%Su", "/dev/console"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None

    if result.returncode != 0:
        return None

    user = result.stdout.strip()
    if not user or user in {"root", "loginwindow"}:
        return None
    return user


def compile_plan(plan: Plan) -> CompiledPlan:
    requested_risk = plan.risk
    action = plan.action

    admin_requested = bool(plan.args.get("requires_admin")) or bool(
        plan.args.get("requires_sudo")
    )
    if action == "manual_admin_required" or admin_requested:
        reason = str(plan.args.get("reason", "Administrator-level work requested."))
        script = compile_manual_plan(reason)
        return CompiledPlan(
            script=script,
            display_script="manual_admin_required",
            risk="HIGH",
            executable=False,
        )

    if plan.category == "spotify":
        script, display_script = compile_spotify_script(action, plan.args)
        minimum_risk = "LOW"
    elif plan.category == "app":
        script, display_script = compile_app_script(action, plan.args)
        minimum_risk = "LOW"
    elif plan.category == "sysinfo":
        script, display_script = compile_sysinfo_script(action)
        minimum_risk = "LOW"
    elif plan.category == "files":
        script, display_script = compile_files_script(action, plan.args)
        minimum_risk = "MEDIUM"
    elif plan.category == "shell":
        script, display_script, minimum_risk = compile_shell_script(action, plan.args)
    else:
        script = compile_manual_plan("Unsupported category for this version.")
        return CompiledPlan(
            script=script,
            display_script="manual_unsupported_category",
            risk="HIGH",
            executable=False,
        )

    final_risk = stronger_risk(requested_risk, minimum_risk)
    return CompiledPlan(
        script=script,
        display_script=display_script,
        risk=final_risk,
        executable=True,
    )


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
    print(f"Script: {compiled.display_script}")

    if show_json:
        print("Model JSON:")
        print(json.dumps(plan_json, indent=2, sort_keys=True))
        print(f"Compiled script: {compiled.script}")


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

        if plan.requires_gui_session and get_console_user() is None:
            compiled = CompiledPlan(
                script=compile_no_gui_session_plan(),
                display_script="manual_no_gui_session",
                risk="HIGH",
                executable=False,
            )

        banned_hits = detect_banned_tokens(compiled.script)
        if banned_hits:
            raise GodoError(
                "Refusing plan due to banned token(s): " + ", ".join(sorted(set(banned_hits)))
            )

        print_plan(plan, compiled, plan_json, args.json)

        if args.dry_run:
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
