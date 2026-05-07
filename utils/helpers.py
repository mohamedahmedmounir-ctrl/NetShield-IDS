"""
utils/helpers.py
=================
Miscellaneous helper functions used across the application.
"""


def format_bytes(byte_count: int) -> str:
    """Convert raw byte count to a human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if byte_count < 1024:
            return f"{byte_count:.1f} {unit}"
        byte_count /= 1024
    return f"{byte_count:.1f} PB"


def get_severity_color(severity: str) -> str:
    """Return a hex color string for a given severity level."""
    mapping = {
        "CRITICAL": "#ff2d55",
        "HIGH":     "#ff6b35",
        "MEDIUM":   "#ffd60a",
        "LOW":      "#30d158",
    }
    return mapping.get(severity.upper(), "#6e6e73")


def severity_to_badge(severity: str) -> str:
    """Return a Bootstrap-compatible badge class for a severity level."""
    mapping = {
        "CRITICAL": "danger",
        "HIGH":     "warning",
        "MEDIUM":   "info",
        "LOW":      "success",
    }
    return mapping.get(severity.upper(), "secondary")


def truncate(text: str, max_len: int = 60) -> str:
    """Truncate a string to max_len characters."""
    if len(text) <= max_len:
        return text
    return text[:max_len - 3] + "..."


def ip_is_private(ip: str) -> bool:
    """Return True if the IP is in a private / RFC-1918 range."""
    return (
        ip.startswith("192.168.") or
        ip.startswith("10.")      or
        ip.startswith("172.")     or
        ip == "127.0.0.1"
    )
