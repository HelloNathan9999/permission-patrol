#!/usr/bin/env python3
"""
Permission Guard Hook for Claude Code
======================================
This script runs as a PermissionRequest hook, using Claude CLI (Haiku) to review permission requests.
Uses subscription quota via CLI - no separate API key required.

Security Policy:
- Delete operations: Deny
- Upload operations: Deny
- Access paths outside project: Ask user
- Trusted domains: Auto-approve
- Other cases: Call Claude CLI for review
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from datetime import datetime

# Debug log file
DEBUG_LOG = Path("/tmp/permission-guard.log")

def log_debug(msg: str):
    """Write debug message to log file."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    with open(DEBUG_LOG, "a") as f:
        f.write(f"[{timestamp}] {msg}\n")

# Sensitive path patterns (accessing these requires user confirmation)
SENSITIVE_PATHS = [
    r"^/etc/",
    r"^/root/",
    r"^~/.ssh/",
    r"^~/.gnupg/",
    r"^~/.aws/",
    r"^~/.config/gcloud/",
    r"\.env$",
    r"credentials",
    r"secrets?\.ya?ml$",
    r"\.pem$",
    r"\.key$",
]

# Dangerous command patterns (directly denied)
DANGEROUS_PATTERNS = [
    # Delete operations
    r"\brm\s+(-[rfRvid]+\s+)*(/|~|/home)",  # rm targeting root or home
    r"\bunlink\s+",
    r"\bshred\s+",
    # Upload operations
    r"\bcurl\s+.*(-X\s*POST|-d\s|--data|--upload-file|-F\s|--form)",
    r"\bwget\s+.*--post",
    r"\bscp\s+[^:]+\s+\S+:",  # scp to remote
    r"\brsync\s+.*\s+\S+:",   # rsync to remote
    # System destruction
    r"\bmkfs\b",
    r"\bdd\s+.*of=/dev/",
    r"\bchmod\s+777\s+/",
    r"\bchown\s+.*\s+/",
    # Reverse shell / data exfiltration
    r"\bnc\s+.*-e\s+",
    r"\bbash\s+-i\s+",
    r"/dev/tcp/",
    r"\|\s*nc\s+\S+\s+\d+",  # pipe to nc (data exfiltration)
    r"\|\s*curl\s+",         # pipe to curl
    r"\|\s*wget\s+",         # pipe to wget
    r"base64.*\|\s*nc\s+",   # base64 encode then send
]

# Dangerous patterns in code (reference for Claude review)
CODE_DANGER_PATTERNS = [
    r"os\.remove",
    r"os\.unlink",
    r"shutil\.rmtree",
    r"pathlib\.Path.*\.unlink",
    r"requests\.(post|put|patch)",
    r"urllib.*urlopen.*data=",
    r"subprocess.*rm\s",
    r"eval\s*\(",
    r"exec\s*\(",
    r"__import__",
]


# ============================================================================
# Utility Functions
# ============================================================================

def is_path_in_project(path: str, cwd: str, additional_dirs: list) -> bool:
    """Check if path is within project scope."""
    try:
        # Expand ~ and environment variables
        path = os.path.expanduser(os.path.expandvars(path))
        path = os.path.abspath(path)

        # Check if under cwd
        if path.startswith(os.path.abspath(cwd)):
            return True

        # Check if under additionalDirectories
        for add_dir in additional_dirs:
            add_dir = os.path.expanduser(os.path.expandvars(add_dir))
            add_dir = os.path.abspath(add_dir)
            if path.startswith(add_dir):
                return True

        return False
    except Exception:
        return False


def is_sensitive_path(path: str) -> bool:
    """Check if path is sensitive."""
    path = os.path.expanduser(path)
    for pattern in SENSITIVE_PATHS:
        if re.search(pattern, path, re.IGNORECASE):
            return True
    return False


def is_dangerous_command(command: str) -> tuple[bool, str]:
    """Check if command contains dangerous patterns."""
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return True, f"Dangerous pattern detected: {pattern}"
    return False, ""


def has_code_danger_patterns(code: str) -> list:
    """Check if code contains dangerous patterns."""
    found = []
    for pattern in CODE_DANGER_PATTERNS:
        if re.search(pattern, code, re.IGNORECASE):
            found.append(pattern)
    return found


# ============================================================================
# Claude CLI Review
# ============================================================================

def call_claude_for_review(request: dict, script_content: str = "") -> dict:
    """Call Claude CLI (Haiku) for intelligent security review. Uses subscription quota."""
    tool_name = request.get("tool_name", "Unknown")
    tool_input = request.get("tool_input", {})
    cwd = request.get("cwd", "")

    # Build script content section if provided
    script_section = ""
    if script_content:
        script_section = f"""
## Script Content
```
{script_content}
```
"""

    # Build review prompt
    prompt = f"""You are a security reviewer for Claude Code. Analyze the following permission request and determine if it should be auto-approved.

## Request Information
- Tool: {tool_name}
- Working Directory: {cwd}
- Parameters:
```json
{json.dumps(tool_input, indent=2, ensure_ascii=False)}
```
{script_section}
## Security Checklist
1. **Delete operations**: Will it delete files/directories? (including os.remove, shutil.rmtree in code)
2. **Upload/Send data**: Will it send data externally? (POST requests, scp, rsync to remote, etc.)
3. **Sensitive paths**: Does it access ~/.ssh, ~/.gnupg, .env, credentials, etc.?
4. **Command injection**: Are there suspicious semicolons, backticks, $() that could be injection attacks?
5. **Path traversal**: Are there ../../ path traversal attack patterns?

## Decision Criteria
- If it's **clearly a normal development operation** (reading files, git operations, running tests) → allow
- If there's **any security risk** but uncertain if malicious → ask (let user confirm)
- If it's **clearly dangerous/malicious** → deny

## Response Format (pure JSON, no other text)
{{"decision": "allow"}}
or {{"decision": "ask", "reason": "reason for confirmation"}}
or {{"decision": "deny", "reason": "reason for denial"}}
"""

    text = ""  # Initialize for error handling
    try:
        log_debug("Calling Claude CLI (haiku)...")

        # Call claude CLI with print mode
        result = subprocess.run(
            ["claude", "-p", prompt, "--model", "haiku", "--output-format", "text"],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            log_debug(f"CLI error: {result.stderr}")
            return {"decision": "ask", "reason": f"CLI error: {result.stderr}"}

        text = result.stdout.strip()
        log_debug(f"Claude response: {text[:200]}")

        # Try to parse JSON (may be wrapped in markdown)
        if "```" in text:
            # Extract content between ```
            match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
            if match:
                text = match.group(1)

        # Find JSON object in response
        json_match = re.search(r'\{[^{}]*"decision"[^{}]*\}', text)
        if json_match:
            text = json_match.group(0)

        parsed = json.loads(text)
        log_debug(f"Claude decision: {parsed}")
        return parsed

    except subprocess.TimeoutExpired:
        log_debug("ERROR: CLI timeout")
        return {"decision": "ask", "reason": "CLI timeout"}
    except json.JSONDecodeError:
        log_debug(f"ERROR: Could not parse response: {text[:100]}")
        return {"decision": "ask", "reason": "Could not parse Claude response"}
    except FileNotFoundError:
        log_debug("ERROR: claude CLI not found")
        return {"decision": "ask", "reason": "claude CLI not found in PATH"}
    except Exception as e:
        log_debug(f"ERROR: Review error: {e}")
        return {"decision": "ask", "reason": f"Review error: {e}"}


# ============================================================================
# Output Functions
# ============================================================================

def allow():
    """Approve the request."""
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": {"behavior": "allow"}
        }
    }
    print(json.dumps(output))
    sys.exit(0)


def deny(reason: str):
    """Deny the request."""
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": {
                "behavior": "deny",
                "message": reason
            }
        }
    }
    print(json.dumps(output))
    sys.exit(0)


def ask_user(context: str = ""):
    """Let user decide (don't return decision).

    Args:
        context: Optional context message explaining why user confirmation is needed.
                 Will be shown via desktop notification on Linux.
    """
    if context:
        # Send desktop notification on Linux only
        if sys.platform.startswith("linux"):
            try:
                subprocess.run(
                    ["notify-send", "-u", "normal", "-t", "10000",
                     "Permission Patrol", context],
                    capture_output=True,
                    timeout=2
                )
            except Exception:
                pass  # Notification is optional

        log_debug(f"Asking user: {context}")

    # exit 0 without outputting decision, Claude Code will show standard permission dialog
    sys.exit(0)


def handle_claude_decision(decision: str, reason: str, path: str, cwd: str, additional_dirs: list):
    """Handle Claude's decision with path-aware logic.

    - deny → deny with warning
    - allow + inside project → allow
    - allow + outside project → ask user (double confirmation)
    - ask → ask user
    """
    if decision == "deny":
        deny(f"⛔ Claude: {reason}")
    elif decision == "allow":
        # Check if path is outside project
        if path and not is_path_in_project(path, cwd, additional_dirs):
            log_debug(f"Claude approved but path outside project: {path}, asking user")
            ask_user(f"✅ Claude approved, but path outside project:\n{path}\n\nPlease confirm.")
        else:
            allow()
    else:
        log_debug("Claude unsure, asking user")
        ask_user(f"🤔 Claude uncertain: {reason}" if reason else "🤔 Claude needs your decision")


# ============================================================================
# Main Logic
# ============================================================================

def main():
    log_debug("=" * 50)
    log_debug("Hook started")

    # 1. Read JSON input from stdin
    try:
        request = json.load(sys.stdin)
    except json.JSONDecodeError:
        log_debug("ERROR: Cannot parse JSON input")
        ask_user("⚠️ Hook error: cannot parse input")
        return

    tool_name = request.get("tool_name", "")
    tool_input = request.get("tool_input", {})
    cwd = request.get("cwd", "")

    log_debug(f"Tool: {tool_name}")
    log_debug(f"Input: {json.dumps(tool_input, ensure_ascii=False)[:200]}")

    # Read additionalDirectories from settings.json
    additional_dirs = []
    settings_path = Path.home() / ".claude" / "settings.json"
    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text())
            additional_dirs = settings.get("permissions", {}).get("additionalDirectories", [])
        except Exception:
            pass

    # ========================================================================
    # PHASE 1: AUTO DENY (fast reject, no API call)
    # ========================================================================
    # Note: AUTO ALLOW is handled by settings.json rules before hook is called

    # 1.1 Dangerous command regex patterns
    if tool_name == "Bash":
        command = tool_input.get("command", "")
        is_dangerous, reason = is_dangerous_command(command)
        if is_dangerous:
            log_debug(f"Dangerous command detected: {reason}")
            deny(f"⛔ {reason}")
            return

    # ========================================================================
    # PHASE 2: OPUS REVIEW (AI decision)
    # ========================================================================

    # 2.1 Script execution (python/node/bash + file)
    if tool_name == "Bash":
        command = tool_input.get("command", "")
        script_match = re.search(r'\b(python|python3|node|bash|sh)\s+([^\s;|&]+)', command)
        if script_match:
            script_path = script_match.group(2)
            log_debug(f"Detected script execution: {script_path}")

            # Try to read the script content
            script_content = ""
            script_full_path = os.path.expanduser(script_path)
            try:
                if not os.path.isabs(script_full_path):
                    script_full_path = os.path.join(cwd, script_full_path)
                if os.path.exists(script_full_path):
                    with open(script_full_path, "r") as f:
                        script_content = f.read()[:5000]  # Limit to 5000 chars
                    log_debug(f"Read script content: {len(script_content)} chars")
                else:
                    log_debug(f"Script file not found: {script_full_path}")
            except Exception as e:
                log_debug(f"Could not read script: {e}")

            log_debug("Calling Claude for script review...")
            result = call_claude_for_review(request, script_content)
            decision = result.get("decision", "ask")
            reason = result.get("reason", "")

            log_debug(f"Claude decision: {decision}, reason: {reason}")
            handle_claude_decision(decision, reason, script_full_path, cwd, additional_dirs)
            return

    # 2.2 Write/Edit with dangerous code patterns
    if tool_name in ("Write", "Edit"):
        content = tool_input.get("content", "") or tool_input.get("new_string", "")
        file_path = tool_input.get("file_path", "")
        danger_patterns = has_code_danger_patterns(content)
        if danger_patterns:
            log_debug(f"Dangerous code patterns in Write/Edit: {danger_patterns}")
            log_debug("Calling Claude for code review...")
            result = call_claude_for_review(request)
            decision = result.get("decision", "ask")
            reason = result.get("reason", "")

            log_debug(f"Claude decision: {decision}, reason: {reason}")
            handle_claude_decision(decision, reason, file_path, cwd, additional_dirs)
            return

    # ========================================================================
    # PHASE 3: CLAUDE REVIEW FOR OTHER CASES
    # ========================================================================
    # Instead of directly asking user, let Claude review first

    # 3.1 Collect paths to check
    paths_to_check = []
    if "file_path" in tool_input:
        paths_to_check.append(tool_input["file_path"])
    if "path" in tool_input:
        paths_to_check.append(tool_input["path"])

    if tool_name == "Bash":
        command = tool_input.get("command", "")
        path_matches = re.findall(r'(?:^|\s)([~/][^\s;|&<>]+)', command)
        paths_to_check.extend(path_matches)

    # 3.2 Check for sensitive paths - always ask user (even if Claude approves)
    for path in paths_to_check:
        if is_sensitive_path(path):
            log_debug(f"Sensitive path: {path}, calling Claude then asking user")
            result = call_claude_for_review(request)
            decision = result.get("decision", "ask")
            reason = result.get("reason", "")

            if decision == "deny":
                deny(f"⛔ Claude: {reason}")
            else:
                # Even if Claude allows, sensitive paths need user confirmation
                log_debug("Sensitive path requires user confirmation")
                ask_user(f"✅ Claude approved, but sensitive path:\n{path}\n\nPlease confirm.")
            return

    # 3.3 Check if any path is outside project
    has_outside_path = False
    outside_path = ""
    for path in paths_to_check:
        if not is_path_in_project(path, cwd, additional_dirs):
            has_outside_path = True
            outside_path = path
            break

    # 3.4 For complex Bash commands or unknown operations, let Claude review
    if tool_name == "Bash":
        command = tool_input.get("command", "")
        # Complex command detection: multiple operations, pipes, redirects
        is_complex = (
            "&&" in command or
            "||" in command or
            "|" in command or
            ";" in command or
            len(command) > 100
        )
        if is_complex or has_outside_path:
            log_debug(f"Complex Bash or outside path, calling Claude for review...")
            result = call_claude_for_review(request)
            decision = result.get("decision", "ask")
            reason = result.get("reason", "")

            log_debug(f"Claude decision: {decision}, reason: {reason}")
            handle_claude_decision(decision, reason, outside_path if has_outside_path else "", cwd, additional_dirs)
            return

    # 3.5 WebFetch unknown domain - let Claude review
    if tool_name == "WebFetch":
        log_debug("Unknown domain, calling Claude for review...")
        result = call_claude_for_review(request)
        decision = result.get("decision", "ask")
        reason = result.get("reason", "")

        log_debug(f"Claude decision: {decision}, reason: {reason}")
        # WebFetch to unknown domains: if Claude allows, still ask user
        if decision == "deny":
            deny(f"⛔ Claude: {reason}")
        else:
            url = tool_input.get("url", "unknown")
            ask_user(f"✅ Claude approved, but unknown domain:\n{url}\n\nPlease confirm.")
        return

    # 3.6 Path outside project - let Claude review first
    if has_outside_path:
        log_debug(f"Path outside project: {outside_path}, calling Claude for review...")
        result = call_claude_for_review(request)
        decision = result.get("decision", "ask")
        reason = result.get("reason", "")

        log_debug(f"Claude decision: {decision}, reason: {reason}")
        if decision == "deny":
            deny(f"⛔ Claude: {reason}")
        else:
            ask_user(f"✅ Claude approved, but path outside project:\n{outside_path}\n\nPlease confirm.")
        return

    # 3.7 Default: simple operations in project - allow
    log_debug("Simple operation in project scope, allowing")
    allow()


if __name__ == "__main__":
    main()
