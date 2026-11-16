"""Defensive sanitization; callers must still avoid logging arbitrary sensitive payloads."""
import json
import re

_SENSITIVE = re.compile(r"(?i)(password|passwd|authorization|cookie|token|secret|api[_-]?key)")


def redact(text: str) -> str:
    def scrub(value):
        if isinstance(value, dict):
            return {k: "[REDACTED]" if _SENSITIVE.search(k) else scrub(v) for k, v in value.items()}
        if isinstance(value, list):
            return [scrub(v) for v in value]
        if isinstance(value, str):
            return plain(value)
        return value

    def plain(value):
        value = re.sub(r"(?i)\bBearer\s+[^\s,;\"']+", "Bearer [REDACTED]", value)
        value = re.sub(r'''(?ix)(["']?(?:password|passwd|authorization|cookie|token|secret|api[_-]?key)["']?\s*[:=]\s*)(?:"(?:[^"\\]|\\.)*"|'[^']*'|[^\s,;]+)''', r"\1[REDACTED]", value)
        value = re.sub(r"(?:dzt_|dzk_)[A-Za-z0-9_.-]+", "[REDACTED]", value)
        # Prevent multiline/control-character log injection.
        return re.sub(r"[\x00-\x1f\x7f]", " ", value)

    try:
        parsed = json.loads(text)
    except (ValueError, TypeError):
        return plain(str(text))
    return json.dumps(scrub(parsed), ensure_ascii=False)
