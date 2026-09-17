CRITICAL = "critical"
WARNING = "warning"
INFO = "info"

ORDER = {CRITICAL: 0, WARNING: 1, INFO: 2}

ICONS = {
    CRITICAL: "🔴",
    WARNING:  "🟡",
    INFO:     "🔵",
}

LABELS = {
    CRITICAL: "Críticos",
    WARNING:  "Warnings",
    INFO:     "Info",
}


def sort_key(item):
    """Ordena hallazgos por severidad (critical primero)."""
    return ORDER.get(item.get("severity", INFO), 99)


def count_by_severity(findings):
    """Cuenta hallazgos por severidad. Devuelve {critical: N, warning: M, info: K}."""
    counts = {CRITICAL: 0, WARNING: 0, INFO: 0}
    for f in findings:
        sev = f.get("severity", INFO)
        counts[sev] = counts.get(sev, 0) + 1
    return counts
