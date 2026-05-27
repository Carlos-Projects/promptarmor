import re
from dataclasses import dataclass, field

INJECTION_MARKERS: list[re.Pattern] = [
    re.compile(r"<\|im_start\|>.*?<\|im_end\|>", re.DOTALL),
    re.compile(r"<<[Ss][Yy][Ss][Tt][Ee][Mm]>>.*?<<\s*/\s*[Ss][Yy][Ss][Tt][Ee][Mm]\s*>>", re.DOTALL),
    re.compile(r"\[\s*INST\s*\].*?\[\s*/\s*INST\s*\]", re.DOTALL),
    re.compile(r"role\s*[:=]\s*(system|assistant)", re.IGNORECASE),
    re.compile(r"\[\s*system\s*\].*?(?=\n|$)", re.IGNORECASE),
]


@dataclass
class SanitizationResult:
    """Result of context sanitization.

    Attributes:
        sanitized: Whether any content was removed or modified.
        cleaned_text: The sanitized text.
        removed_blocks: Number of injection blocks removed.
        removed_markers: List of marker strings that were removed.
    """

    sanitized: bool
    cleaned_text: str
    removed_blocks: int = 0
    removed_markers: list[str] = field(default_factory=list)


class ContextSanitizer:
    """Removes injected tokens, system markers, and role spoofing from text.

    Strips common LLM-injection markers (``<|im_start|>``, ``<<SYSTEM>>``,
    ``[INST]``) and role-prefixed lines (``user:``, ``system:``) from
    conversation history.
    """

    def __init__(self, strip_markers: bool = True, max_history_length: int | None = None):
        self.strip_markers = strip_markers
        self.max_history_length = max_history_length

    def sanitize(self, text: str) -> SanitizationResult:
        """Sanitize ``text`` by removing injection markers and role prefixes.

        Returns a ``SanitizationResult`` with the cleaned text and a count
        of removed blocks.
        """
        if not text:
            return SanitizationResult(sanitized=False, cleaned_text=text)

        cleaned = text
        removed: list[str] = []
        total_removed = 0

        for pattern in INJECTION_MARKERS:
            matches = pattern.findall(cleaned)
            if matches:
                total_removed += len(matches)
                for m in matches:
                    truncated = m[:80] + "..." if len(m) > 80 else m
                    removed.append(truncated)
                cleaned = pattern.sub("", cleaned)

        if self.strip_markers:
            cleaned = self._strip_common_markers(cleaned)

        if self.max_history_length:
            chars_per_turn = 200
            max_chars = self.max_history_length * chars_per_turn
            if len(cleaned) > max_chars:
                cleaned = cleaned[-max_chars:]

        sanitized = total_removed > 0 or cleaned != text
        return SanitizationResult(
            sanitized=sanitized,
            cleaned_text=cleaned,
            removed_blocks=total_removed,
            removed_markers=removed,
        )

    @staticmethod
    def _strip_common_markers(text: str) -> str:
        """Remove lines that start with a role prefix (user:, system:, etc.)."""
        lines = text.split("\n")
        filtered: list[str] = []
        for line in lines:
            stripped = line.strip()
            if re.match(r"^(user|assistant|system|human|ai)\s*[:\-]\s*", stripped, re.IGNORECASE):
                continue
            filtered.append(line)
        return "\n".join(filtered)
