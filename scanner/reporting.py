

import json, html, os
from datetime import datetime
from typing import Dict, Any


class Reporter:
    @staticmethod
    def to_json(findings, path):
        
        formatted_time = Reporter._format_timestamp()
        data = {"generated_at": formatted_time, "findings": findings}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    @staticmethod
    def to_html(findings, path):
        css_content = Reporter._load_css()
        grouped_findings = Reporter._group_by_severity(findings)
        sections_html = Reporter._generate_sections(grouped_findings)
        formatted_time = Reporter._format_timestamp()

        doc = f"""<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>🛡️ Mini-OWASP Report</title>
        <style>
            {css_content}
        </style>
        <script>
            function toggleAIAnalysis(button) {{
                const row = button.closest('tr');
                const nextRow = row.nextElementSibling;
                if (nextRow && nextRow.classList.contains('ai-analysis-row')) {{
                    if (nextRow.style.display === 'none') {{
                        nextRow.style.display = 'table-row';
                        button.textContent = '📊 Hide';
                    }} else {{
                        nextRow.style.display = 'none';
                        button.textContent = '📊 View';
                    }}
                }}
            }}
        </script>
    </head>
    <body>
        <div class="header-section">
            <h1>🛡️ Mini-OWASP Report</h1>
            <p>🚀 SCAN COMPLETED • {html.escape(formatted_time)} • {len(findings)} THREATS DETECTED</p>
            {Reporter._generate_summary_stats(grouped_findings)}
        </div>

        {sections_html}
    </body>
    </html>"""

        with open(path, "w", encoding="utf-8") as f:
            f.write(doc)

    @staticmethod
    def _group_by_severity(findings):
        """Group findings by severity level"""
        grouped = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
        
        for finding in findings:
            score = finding.get('severity_score', 0)
            if score >= 9:
                grouped['critical'].append(finding)
            elif score >= 7:
                grouped['high'].append(finding)
            elif score >= 4:
                grouped['medium'].append(finding)
            elif score >= 1:
                grouped['low'].append(finding)
            else:
                grouped['info'].append(finding)
        
        return grouped
    
    @staticmethod
    def _generate_summary_stats(grouped_findings):
        """Generate summary statistics cards"""
        total = sum(len(findings) for findings in grouped_findings.values())
        
        if total == 0:
            return '<div class="summary-stats"><div class="stat-card secure">🔒 SYSTEM SECURE - NO THREATS DETECTED 🔒</div></div>'
        
        stats_html = '<div class="summary-stats">'
        
        severity_info = {
            'critical': {'icon': '🚨', 'label': 'CRITICAL'},
            'high': {'icon': '⚠️', 'label': 'HIGH'},
            'medium': {'icon': '🔶', 'label': 'MEDIUM'},
            'low': {'icon': '🔵', 'label': 'LOW'},
            'info': {'icon': 'ℹ️', 'label': 'INFO'}
        }
        
        for severity, info in severity_info.items():
            count = len(grouped_findings[severity])
            stats_html += f'''
            <div class="stat-card {severity}">
                <div class="stat-icon">{info['icon']}</div>
                <div class="stat-number">{count}</div>
                <div class="stat-label">{info['label']}</div>
            </div>
            '''
        
        stats_html += f'''
        <div class="stat-card total">
            <div class="stat-icon">📊</div>
            <div class="stat-number">{total}</div>
            <div class="stat-label">TOTAL</div>
        </div>
        </div>'''
        
        return stats_html

    @staticmethod
    def _generate_sections(grouped_findings):
        """Generate HTML sections for each severity level"""
        sections_html = ""

        severity_config = {
            'critical': {'title': '🚨 CRITICAL THREATS', 'color': '#ff0040'},
            'high': {'title': '⚠️ HIGH PRIORITY THREATS', 'color': '#ff6600'},
            'medium': {'title': '🔶 MEDIUM PRIORITY THREATS', 'color': '#ffcc00'},
            'low': {'title': '🔵 LOW PRIORITY THREATS', 'color': '#00ff88'},
            'info': {'title': 'ℹ️ INFORMATIONAL', 'color': '#00bfff'}
        }

        for severity, config in severity_config.items():
            findings = grouped_findings[severity]
            if not findings:
                continue

            sections_html += f'''
            <div class="severity-section {severity}-section">
                <div class="section-header">
                    <h2 class="section-title">{config['title']}</h2>
                    <div class="section-count">{len(findings)} Issues</div>
                </div>
                <table class="threats-table">
                    <thead>
                        <tr>
                            <th>🔍 Threat Type</th>
                            <th>🌐 Target URL</th>
                            <th>⚠️ Severity</th>
                            <th>📋 Evidence</th>
                            <th>🤖 AI Analysis</th>
                        </tr>
                    </thead>
                    <tbody>
                        {Reporter._generate_table_rows(findings, severity)}
                    </tbody>
                </table>
            </div>
            '''

        if not any(grouped_findings.values()):
            sections_html = '''
            <div class="no-threats-section">
                <div class="secure-icon">🛡️</div>
                <h2>ALL SYSTEMS SECURE</h2>
                <p>No security threats detected during the scan.</p>
            </div>
            '''

        return sections_html

    @staticmethod
    def _generate_table_rows(findings, severity):
        """Generate table rows for findings"""
        rows = []
        for i, finding in enumerate(findings):
            severity_score = finding.get('severity_score', 0)
            ai_analysis = finding.get('ai_analysis', {})
            has_ai = bool(ai_analysis and not finding.get('ai_error'))

            ai_button = f'<button class="ai-toggle" onclick="toggleAIAnalysis(this)">📊 View</button>' if has_ai else '<span class="no-ai">N/A</span>'

            row_html = f'''
            <tr style='--row-index: {i};' class='threat-row {severity}-row'>
                <td class='threat-type'>{html.escape(finding.get('type', ''))}</td>
                <td class='threat-url'>{html.escape(finding.get('url', ''))}</td>
                <td class='threat-severity' data-severity='{severity_score}'>{html.escape(str(severity_score))}</td>
                <td class='threat-evidence'>{html.escape(finding.get('evidence', ''))}</td>
                <td class='threat-ai'>{ai_button}</td>
            </tr>
            '''
            if has_ai:
                row_html += Reporter._generate_ai_analysis_row(finding, i)

            rows.append(row_html)

        return ''.join(rows)

    @staticmethod
    def _generate_ai_analysis_row(finding: Dict[str, Any], row_index: int) -> str:
        """Generate collapsible AI analysis row"""
        ai_analysis = finding.get('ai_analysis', {})

        explanation = html.escape(ai_analysis.get('vulnerability_explanation', 'N/A'))
        attack_scenario = html.escape(ai_analysis.get('attack_scenario', 'N/A'))
        impact = html.escape(ai_analysis.get('impact', 'N/A'))
        code_mitigation = html.escape(ai_analysis.get('code_mitigation', 'N/A'))
        mitigation_steps = ai_analysis.get('mitigation_steps', [])
        tools = ai_analysis.get('tools_to_use', [])
        references = ai_analysis.get('references', [])

        steps_html = ''.join([f'<li>{html.escape(step)}</li>' for step in mitigation_steps])
        tools_html = ''.join([f'<li>{html.escape(tool)}</li>' for tool in tools])
        refs_html = ''.join([f'<li>{html.escape(ref)}</li>' for ref in references])

        return f'''
        <tr class='ai-analysis-row' id='ai-row-{row_index}' style='display: none;'>
            <td colspan='5'>
                <div class='ai-analysis-container'>
                    <div class='ai-section'>
                        <h4>🔍 Vulnerability Explanation</h4>
                        <p>{explanation}</p>
                    </div>
                    <div class='ai-section'>
                        <h4>⚔️ Attack Scenario</h4>
                        <p>{attack_scenario}</p>
                    </div>
                    <div class='ai-section'>
                        <h4>💥 Potential Impact</h4>
                        <p>{impact}</p>
                    </div>
                    <div class='ai-section'>
                        <h4>✅ Mitigation Steps</h4>
                        <ul>{steps_html if steps_html else '<li>No steps provided</li>'}</ul>
                    </div>
                    <div class='ai-section'>
                        <h4>💻 Code Mitigation</h4>
                        <pre><code>{code_mitigation}</code></pre>
                    </div>
                    <div class='ai-section'>
                        <h4>🛠️ Recommended Tools</h4>
                        <ul>{tools_html if tools_html else '<li>No tools provided</li>'}</ul>
                    </div>
                    <div class='ai-section'>
                        <h4>📚 References</h4>
                        <ul>{refs_html if refs_html else '<li>No references provided</li>'}</ul>
                    </div>
                </div>
            </td>
        </tr>
        '''

    @staticmethod
    def _load_css():
        """Load CSS from external file"""
        try:
            current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            css_path = os.path.join(current_dir, 'report-style.css')

            with open(css_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            print(f"[WARN] Gagal memuat CSS: {e}")
            return ""  # Return empty string instead of None

    @staticmethod
    def _format_timestamp():
        """Format timestamp as DD-MM-YYYY HH:MM"""
        now = datetime.now()
        return now.strftime("%d-%m-%Y %H:%M")

    @staticmethod
    def format_finding_with_ai(finding: Dict[str, Any]) -> Dict[str, Any]:
        """Format finding with AI analysis for display."""
        ai_analysis = finding.get("ai_analysis", {})

        if ai_analysis:
            return {
                **finding,
                "explanation": ai_analysis.get("vulnerability_explanation", ""),
                "attack_scenario": ai_analysis.get("attack_scenario", ""),
                "impact": ai_analysis.get("impact", ""),
                "mitigation_steps": ai_analysis.get("mitigation_steps", []),
                "mitigation_code": ai_analysis.get("code_mitigation", ""),
                "recommended_tools": ai_analysis.get("tools_to_use", []),
                "references": ai_analysis.get("references", [])
            }
        return finding
