from pathlib import Path
import json

from utils import severity
from utils.logger import log


def _collect_findings(services, enum_results):
    """Recoge todos los findings de los handlers y les asocia puerto/servicio."""
    findings = []
    for svc in services:
        port = svc["port"]
        enum = enum_results.get(port) or {}
        for f in enum.get("findings", []) or []:
            item = dict(f)
            item["port"] = port
            item["service"] = svc.get("name", "?")
            item.setdefault("severity", severity.INFO)
            findings.append(item)
    return findings


def _render_findings_summary(findings):
    """Genera la sección de resumen de hallazgos para el Markdown."""
    lines = ["## Resumen de hallazgos\n"]

    if not findings:
        lines.append("_Sin hallazgos destacados._\n")
        return lines

    counts = severity.count_by_severity(findings)

    for sev in (severity.CRITICAL, severity.WARNING, severity.INFO):
        n = counts.get(sev, 0)
        if n == 0:
            continue
        icon = severity.ICONS[sev]
        label = severity.LABELS[sev]
        lines.append(f"### {icon} {label} ({n})\n")

        subset = [f for f in findings if f.get("severity") == sev]
        subset.sort(key=lambda x: x.get("port", 0))
        for f in subset:
            title = f.get("title", "(sin título)")
            detail = f.get("detail", "")
            port = f.get("port", "?")
            svc = f.get("service", "?")
            if detail:
                lines.append(f"- **{svc} :{port}** — {title}. {detail}")
            else:
                lines.append(f"- **{svc} :{port}** — {title}")
        lines.append("")

    return lines


def _log_findings_summary(findings):
    """Imprime el resumen de hallazgos por consola."""
    if not findings:
        log.info("[*] Sin hallazgos destacados")
        return

    counts = severity.count_by_severity(findings)

    log.info("")
    log.info("=" * 60)
    log.info("  RESUMEN DE HALLAZGOS")
    log.info("=" * 60)

    for sev in (severity.CRITICAL, severity.WARNING, severity.INFO):
        n = counts.get(sev, 0)
        if n == 0:
            continue

        icon = severity.ICONS[sev]
        label = severity.LABELS[sev]
        log.info(f"  {icon} {label} ({n})")

        subset = [f for f in findings if f.get("severity") == sev]
        subset.sort(key=lambda x: x.get("port", 0))
        for f in subset:
            title = f.get("title", "(sin título)")
            port = f.get("port", "?")
            svc = f.get("service", "?")
            log.info(f"      - {svc}:{port} — {title}")
        log.info("")

    log.info("=" * 60)


def build_report(outdir: Path, target, services, enum_results, exploits):
    lines = [f"# Reporte de reconocimiento — {target}\n"]

    # --- Resumen de hallazgos ---
    findings = _collect_findings(services, enum_results)
    lines.extend(_render_findings_summary(findings))

    # --- Puertos y servicios ---
    lines.append("## Puertos y servicios\n")
    lines.append("| Puerto | Servicio | Versión |")
    lines.append("|--------|----------|---------|")
    for s in services:
        ver = f"{s['product']} {s['version']}".strip() or "-"
        lines.append(f"| {s['port']} | {s['name']} | {ver} |")

    # --- Enumeración por servicio ---
    lines.append("\n## Enumeración por servicio\n")
    for port, data in enum_results.items():
        lines.append(f"### Puerto {port}\n```json")
        lines.append(json.dumps(data, indent=2, default=str))
        lines.append("```\n")

    # --- Exploits ---
    lines.append("\n## Exploits potenciales\n")
    if not exploits:
        lines.append(
            "_No se realizaron búsquedas: ningún servicio con producto identificado._\n"
        )
    else:
        for term, hits in exploits.items():
            if hits:
                lines.append(f"### {term} — {len(hits)} resultado(s)\n")
                for h in hits:
                    title = h.get("Title", "?")
                    path = h.get("Path", "?")
                    lines.append(f"- `{title}` — {path}")
                lines.append("")
            else:
                lines.append(
                    f"- **{term}**: sin vulnerabilidades conocidas "
                    f"en ExploitDB / searchsploit."
                )

    (outdir / "report.md").write_text("\n".join(lines))

    # --- Resumen por consola (al final) ---
    _log_findings_summary(findings)