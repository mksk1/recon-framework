from pathlib import Path
import json


def build_report(outdir: Path, target, services, enum_results, exploits):
    lines = [f"# Reporte de reconocimiento — {target}\n"]

    lines.append("## Puertos y servicios\n")
    lines.append("| Puerto | Servicio | Versión |")
    lines.append("|--------|----------|---------|")
    for s in services:
        ver = f"{s['product']} {s['version']}".strip() or "-"
        lines.append(f"| {s['port']} | {s['name']} | {ver} |")

    lines.append("\n## Enumeración por servicio\n")
    for port, data in enum_results.items():
        lines.append(f"### Puerto {port}\n```json")
        lines.append(json.dumps(data, indent=2, default=str))
        lines.append("```\n")

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
