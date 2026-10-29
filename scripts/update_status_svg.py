#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""
Gera e atualiza docs/images/status.svg a partir de docs/status.json.
Usa apenas a biblioteca padrão do Python (sem dependências externas).

Uso:
    python scripts/update_status_svg.py         # atualiza docs/images/status.svg
    python scripts/update_status_svg.py --check # valida se o SVG está sincronizado
"""

import sys
import json
import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATUS_JSON_PATH = ROOT / "docs" / "status.json"
STATUS_SVG_PATH = ROOT / "docs" / "images" / "status.svg"

COLOR_SCHEMES = {
    "completed": {
        "badge_bg": "#064e3b",
        "badge_border": "#059669",
        "badge_text": "#34d399",
        "label": "{pct}% CONCLUÍDO",
        "bar_fill": "url(#barComplete)",
        "circle_bg": "#065f46",
        "circle_border": "#059669",
        "icon_type": "check",
    },
    "completed_firmware": {
        "badge_bg": "#0c4a6e",
        "badge_border": "#0284c7",
        "badge_text": "#38bdf8",
        "label": "{pct}% FW / BANCADA",
        "bar_fill": "url(#barCyan)",
        "circle_bg": "#083344",
        "circle_border": "#0284c7",
        "icon_type": "check",
    },
    "in_progress": {
        "badge_bg": "#78350f",
        "badge_border": "#d97706",
        "badge_text": "#fbbf24",
        "label": "{pct}% EM ANDAMENTO",
        "bar_fill": "url(#barAmber)",
        "circle_bg": "#451a03",
        "circle_border": "#d97706",
        "icon_type": "dot",
    },
    "planned": {
        "badge_bg": "#3b0764",
        "badge_border": "#7c3aed",
        "badge_text": "#c084fc",
        "label": "{pct}% PLANEJADO",
        "bar_fill": "#8b5cf6",
        "circle_bg": "#2e1065",
        "circle_border": "#7c3aed",
        "icon_type": "dot",
    },
    "research": {
        "badge_bg": "#312e81",
        "badge_border": "#4f46e5",
        "badge_text": "#818cf8",
        "label": "{pct}% PESQUISA",
        "bar_fill": "#6366f1",
        "circle_bg": "#1e1b4b",
        "circle_border": "#4f46e5",
        "icon_type": "dot",
    },
    "dormant": {
        "badge_bg": "#1e293b",
        "badge_border": "#475569",
        "badge_text": "#94a3b8",
        "label": "{pct}% LONGO PRAZO",
        "bar_fill": "#64748b",
        "circle_bg": "#1e293b",
        "circle_border": "#475569",
        "icon_type": "dot",
    },
}

def escape_xml(text: str) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )

def render_svg(data: dict) -> str:
    version = escape_xml(data.get("project", {}).get("version", "0.2.1"))
    chip = escape_xml(data.get("project", {}).get("target_platform", {}).get("chip_family", "RP2350"))
    milestones = data.get("milestones", [])

    # Card layout geometry: 2 columns x 3 rows
    col_offsets = [32, 470]
    row_offsets = [98, 244, 390]
    card_width = 418
    card_height = 134

    cards_svg = []
    for idx, m in enumerate(milestones[:6]):
        col = idx % 2
        row = idx // 2
        x = col_offsets[col]
        y = row_offsets[row]
        if row == 2:
            card_h = 126
            bar_y = 108
        else:
            card_h = card_height
            bar_y = 112

        status = m.get("status", "planned")
        pct = m.get("progress_percent", 0)
        if pct == 0 and status == "planned":
            scheme = COLOR_SCHEMES["dormant"]
        else:
            scheme = COLOR_SCHEMES.get(status, COLOR_SCHEMES["planned"])

        badge_text = scheme["label"].format(pct=pct)
        bar_w = int(370 * (max(0, min(100, pct)) / 100.0))

        title = escape_xml(f"{m.get('id', '')} — {m.get('name', '')}")
        caps = m.get("capabilities", [])
        cap_lines = [escape_xml(f"• {c}") for c in caps[:3]]

        # Indicator icon
        if scheme["icon_type"] == "check":
            icon_svg = (
                f'<circle cx="24" cy="28" r="10" fill="{scheme["circle_bg"]}" stroke="{scheme["circle_border"]}" stroke-width="1.5" />\n'
                f'    <path d="M20 28 L23 31 L28 25" stroke="{scheme["badge_text"]}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />'
            )
        else:
            icon_svg = (
                f'<circle cx="24" cy="28" r="10" fill="{scheme["circle_bg"]}" stroke="{scheme["circle_border"]}" stroke-width="1.5" />\n'
                f'    <circle cx="24" cy="28" r="3.5" fill="{scheme["badge_text"]}" />'
            )

        badge_width = max(90, len(badge_text) * 8 + 16)
        badge_x = card_width - badge_width - 16

        lines_svg = "\n".join(
            [f'    <text x="24" y="{56 + i * 18}" font-size="11.5" fill="#94a3b8">{line}</text>' for i, line in enumerate(cap_lines)]
        )

        card = f"""  <!-- CARD {idx + 1}: {m.get('id')} -->
  <g transform="translate({x}, {y})">
    <rect width="{card_width}" height="{card_h}" rx="10" fill="url(#cardGrad)" stroke="#1e293b" stroke-width="1" />
    {icon_svg}
    <text x="44" y="26" font-size="14" font-weight="700" fill="#f8fafc">{title}</text>
    <rect x="{badge_x}" y="18" width="{badge_width}" height="18" rx="9" fill="{scheme['badge_bg']}" stroke="{scheme['badge_border']}" stroke-width="1" />
    <text x="{badge_x + badge_width // 2}" y="31" font-size="9.5" font-weight="700" fill="{scheme['badge_text']}" text-anchor="middle">{badge_text}</text>

{lines_svg}

    <!-- Progress Bar -->
    <rect x="24" y="{bar_y}" width="370" height="6" rx="3" fill="#1e293b" />
    <rect x="24" y="{bar_y}" width="{bar_w}" height="6" rx="3" fill="{scheme['bar_fill']}" />
  </g>"""
        cards_svg.append(card)

    cards_block = "\n\n".join(cards_svg)

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 920 620" width="100%" height="100%" style="background:#090d16; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
  <defs>
    <!-- Gradients -->
    <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#38bdf8" />
      <stop offset="100%" stop-color="#2563eb" />
    </linearGradient>
    <linearGradient id="headerGrad" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#38bdf8" />
      <stop offset="50%" stop-color="#818cf8" />
      <stop offset="100%" stop-color="#c084fc" />
    </linearGradient>
    <linearGradient id="cardGrad" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" stop-color="#161f30" />
      <stop offset="100%" stop-color="#0e1524" />
    </linearGradient>
    <linearGradient id="barComplete" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#10b981" />
      <stop offset="100%" stop-color="#34d399" />
    </linearGradient>
    <linearGradient id="barCyan" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#0284c7" />
      <stop offset="100%" stop-color="#38bdf8" />
    </linearGradient>
    <linearGradient id="barAmber" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#d97706" />
      <stop offset="100%" stop-color="#fbbf24" />
    </linearGradient>
    <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
      <feGaussianBlur stdDeviation="6" result="blur" />
      <feComposite in="SourceGraphic" in2="blur" operator="over" />
    </filter>
  </defs>

  <!-- Outer Canvas Border -->
  <rect x="2" y="2" width="916" height="616" rx="14" fill="#090d16" stroke="#1e293b" stroke-width="1.5" />

  <!-- ==================== HEADER ==================== -->
  <g transform="translate(32, 28)">
    <!-- Aegis Shield Icon -->
    <path d="M22 2 L38 8 C38 22 28 36 22 40 C16 36 6 22 6 8 Z" fill="url(#shieldGrad)" filter="url(#glow)" opacity="0.3" />
    <path d="M22 4 L36 9.5 C36 21 27.5 33 22 37 C16.5 33 8 21 8 9.5 Z" fill="url(#shieldGrad)" stroke="#60a5fa" stroke-width="1.5" />
    <path d="M22 12 L22 30 M15 19 L22 12 L29 19" stroke="#ffffff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />

    <!-- Title & Subtitle -->
    <text x="52" y="22" font-size="20" font-weight="700" fill="url(#headerGrad)" letter-spacing="0.5">AegisToken Security Key</text>
    <text x="52" y="38" font-size="12" font-weight="500" fill="#94a3b8">Universal RP2350 Firmware &amp; Ecosystem • Status &amp; Milestones Dashboard</text>

    <!-- Version & Chip Badges -->
    <g transform="translate(620, 6)">
      <!-- Version Pill -->
      <rect x="0" y="0" width="76" height="24" rx="12" fill="#1e293b" stroke="#334155" stroke-width="1" />
      <circle cx="10" cy="12" r="3.5" fill="#38bdf8" />
      <text x="20" y="16" font-size="11" font-weight="600" fill="#e2e8f0">v{version}</text>

      <!-- Target Chip Pill -->
      <rect x="84" y="0" width="86" height="24" rx="12" fill="#1e293b" stroke="#334155" stroke-width="1" />
      <text x="94" y="16" font-size="11" font-weight="600" fill="#cbd5e1">{chip}</text>

      <!-- License Pill -->
      <rect x="178" y="0" width="62" height="24" rx="12" fill="#064e3b" stroke="#059669" stroke-width="1" />
      <text x="188" y="16" font-size="11" font-weight="700" fill="#34d399">MIT</text>
    </g>
  </g>

  <!-- Divider -->
  <line x1="32" y1="84" x2="888" y2="84" stroke="#1e293b" stroke-width="1" />

  <!-- ==================== MILESTONE CARDS ==================== -->
{cards_block}

  <!-- ==================== FOOTER: INVARIANTS & USB STACK ==================== -->
  <g transform="translate(32, 532)">
    <rect width="856" height="60" rx="8" fill="#0d131f" stroke="#1e293b" stroke-width="1" />
    
    <!-- USB Stack Pills -->
    <text x="20" y="25" font-size="10.5" font-weight="700" fill="#64748b" letter-spacing="0.5">INTERFACES USB COMPOSTAS</text>
    <g transform="translate(20, 32)">
      <text font-size="11" font-weight="600" fill="#38bdf8">HID FIDO <tspan fill="#64748b">(0xF1D0)</tspan></text>
      <text x="135" font-size="11" font-weight="600" fill="#818cf8">HID Management <tspan fill="#64748b">(0xFF00)</tspan></text>
      <text x="300" font-size="11" font-weight="600" fill="#34d399">CCID Smart Card <tspan fill="#64748b">(0x0B)</tspan></text>
    </g>

    <!-- Invariants -->
    <text x="500" y="25" font-size="10.5" font-weight="700" fill="#64748b" letter-spacing="0.5">INVARIANTES DE SEGURANÇA</text>
    <g transform="translate(500, 32)">
      <text font-size="11" font-weight="500" fill="#cbd5e1">&#x2714; Zero Key Export</text>
      <text x="125" font-size="11" font-weight="500" fill="#cbd5e1">&#x2714; Touch Obrigat&#xF3;rio</text>
      <text x="250" font-size="11" font-weight="500" fill="#cbd5e1">&#x2714; no_std / no_alloc</text>
    </g>
  </g>
</svg>
"""
    return svg

def main():
    parser = argparse.ArgumentParser(description="Atualiza status.svg a partir de status.json")
    parser.add_argument("--check", action="store_true", help="Apenas valida se o SVG gerado é idêntico ao existente")
    args = parser.parse_args()

    if not STATUS_JSON_PATH.exists():
        print(f"Erro: {STATUS_JSON_PATH} não encontrado.", file=sys.stderr)
        sys.exit(1)

    with open(STATUS_JSON_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    new_svg = render_svg(data)

    if args.check:
        if not STATUS_SVG_PATH.exists():
            print(f"Erro: {STATUS_SVG_PATH} não existe. Execute sem --check primeiro.", file=sys.stderr)
            sys.exit(1)
        current_svg = STATUS_SVG_PATH.read_text(encoding="utf-8")
        if current_svg.strip() == new_svg.strip():
            print("OK: status.svg está perfeitamente sincronizado com status.json.")
            sys.exit(0)
        else:
            print("AVISO: status.svg está desatualizado em relação a status.json! Execute 'python scripts/update_status_svg.py'.", file=sys.stderr)
            sys.exit(1)

    STATUS_SVG_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATUS_SVG_PATH.write_text(new_svg, encoding="utf-8", newline="\n")
    print(f"Sucesso: {STATUS_SVG_PATH} atualizado a partir de {STATUS_JSON_PATH}.")

if __name__ == "__main__":
    main()
