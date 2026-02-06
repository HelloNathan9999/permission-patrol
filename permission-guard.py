#!/usr/bin/env python3
"""
Permission Guard Hook for Claude Code
======================================
This script runs as a PermissionRequest hook, using Opus 4.5 to review permission requests.

Security Policy:
- Delete operations: Deny
- Upload operations: Deny
- Access paths outside project: Ask user
- Trusted domains: Auto-approve
- Other cases: Call Opus for review
"""

import json
import os
import re
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

# ============================================================================
# Configuration
# ============================================================================

# API key file path (chmod 600 for security)
API_KEY_FILE = Path.home() / ".claude" / "anthropic-api-key"


def load_api_key() -> str | None:
    """Load API key from file."""
    if API_KEY_FILE.exists():
        return API_KEY_FILE.read_text().strip()
    return None

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
    # Reverse shell
    r"\bnc\s+.*-e\s+",
    r"\bbash\s+-i\s+",
    r"/dev/tcp/",
]

# Dangerous patterns in code (reference for Opus review)
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
# Opus API Review
# ============================================================================

def call_opus_for_review(request: dict, script_content: str = "") -> dict:
    """Call Opus 4.5 for intelligent security review."""
    try:
        import anthropic
    except ImportError:
        # If anthropic not installed, skip Opus review
        return {"decision": "ask", "reason": "anthropic SDK not installed, cannot perform intelligent review"}

    tool_name = request.get("tool_name", "Unknown")
    tool_input = request.get("tool_input", {})
    cwd = request.get("cwd", "")

    # Build script content section if provided
    script_section = ""
    if script_content:
        script_section = f"""
## Script Content
```python
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

    try:
        api_key = load_api_key()
        if not api_key:
            log_debug("ERROR: API key not found")
            return {"decision": "ask", "reason": "API key not found in ~/.claude/anthropic-api-key"}

        log_debug("Calling Opus API...")
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model="claude-opus-4-5-20251101",
            max_tokens=500,
            messages=[{"role": "user", "content": prompt}]
        )

        # Extract text content
        text = response.content[0].text.strip()
        log_debug(f"Opus response: {text[:200]}")

        # Try to parse JSON (may be wrapped in markdown)
        if "```" in text:
            # Extract content between ```
            match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
            if match:
                text = match.group(1)

        result = json.loads(text)
        log_debug(f"Opus decision: {result}")
        return result

    except json.JSONDecodeError:
        log_debug("ERROR: Could not parse Opus response")
        return {"decision": "ask", "reason": "Could not parse Opus response"}
    except anthropic.APIError as e:
        log_debug(f"ERROR: Opus API error: {e}")
        return {"decision": "ask", "reason": f"Opus API error: {e}"}
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


def ask_user():
    """Let user decide (don't return decision)."""
    # exit 0 without outputting decision, Claude Code will show standard permission dialog
    sys.exit(0)


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
        ask_user()
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
            try:
                script_full_path = os.path.expanduser(script_path)
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

            log_debug("Calling Opus for script review...")
            result = call_opus_for_review(request, script_content)
            decision = result.get("decision", "ask")
            reason = result.get("reason", "")

            log_debug(f"Opus decision: {decision}, reason: {reason}")
            if decision == "allow":
                allow()
            elif decision == "deny":
                deny(f"⛔ Opus: {reason}")
            else:
                log_debug("Opus unsure, asking user")
                ask_user()
            return

    # 2.2 Write/Edit with dangerous code patterns
    if tool_name in ("Write", "Edit"):
        content = tool_input.get("content", "") or tool_input.get("new_string", "")
        danger_patterns = has_code_danger_patterns(content)
        if danger_patterns:
            log_debug(f"Dangerous code patterns in Write/Edit: {danger_patterns}")
            log_debug("Calling Opus for code review...")
            result = call_opus_for_review(request)
            decision = result.get("decision", "ask")
            reason = result.get("reason", "")

            log_debug(f"Opus decision: {decision}, reason: {reason}")
            if decision == "allow":
                allow()
            elif decision == "deny":
                deny(f"⛔ Opus: {reason}")
            else:
                log_debug("Opus unsure, asking user")
                ask_user()
            return

    # ========================================================================
    # PHASE 3: ASK USER (fallback)
    # ========================================================================

    # 3.1 WebFetch unknown domain (not in settings.json allow list)
    if tool_name == "WebFetch":
        log_debug(f"Unknown domain, asking user")
        ask_user()
        return

    # 3.2 Sensitive paths
    paths_to_check = []
    if "file_path" in tool_input:
        paths_to_check.append(tool_input["file_path"])
    if "path" in tool_input:
        paths_to_check.append(tool_input["path"])

    if tool_name == "Bash":
        command = tool_input.get("command", "")
        path_matches = re.findall(r'(?:^|\s)([~/][^\s;|&<>]+)', command)
        paths_to_check.extend(path_matches)

    for path in paths_to_check:
        if is_sensitive_path(path):
            log_debug(f"Sensitive path: {path}, asking user")
            ask_user()
            return

        if not is_path_in_project(path, cwd, additional_dirs):
            log_debug(f"Path outside project: {path}, asking user")
            ask_user()
            return

    # 3.3 Default: anything else goes to user
    log_debug("No rule matched, asking user")
    ask_user()


if __name__ == "__main__":
    main()
