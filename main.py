import argparse
import os
from scanner.core import Orchestrator
from scanner.reporting import Reporter
from scanner.loading import SimpleLoader
from scanner.reporting_pdf import to_pdf
from scanner.ai_analyzer import GeminiAnalyzer
from datetime import datetime

# Gemini API Key - Add your key here
GEMINI_API_KEY = "AIzaSyBv2hOGGL9EyuQewzq2jWuTlG3epwyPL04"

def parse_args():
    p = argparse.ArgumentParser(description="Mini-OWASP Web Scanner")
    p.add_argument("--target", required=True, help="Base URL target (contoh: https://example.com)")
    p.add_argument("--max-depth", type=int, default=1, help="Kedalaman crawl (default 1)")
    p.add_argument("--rate", type=float, default=2.0, help="Rate limit RPS (default 2)")
    p.add_argument("--out", default="report.json", help="Path file JSON report")
    p.add_argument("--html", default="report.html", help="Path file HTML report")
    p.add_argument("--scope", choices=["same-domain", "same-host"], default="same-domain",
                   help="Batasan scope crawling")
    p.add_argument("--pdf", default=None, help="Path file PDF report (opsional)")
    p.add_argument("--auth-bruteforce", action="store_true", help="Enable authentication bruteforce test")
    p.add_argument("--ai-analysis", action="store_true", help="Enable AI analysis with Gemini")

    return p.parse_args()

def main():
    print(r"""_____ _____ _____  ______ _____ _______ ______  _____ _______    __
 |  __ \_   _|  __ \|  ____|  __ \__   __|  ____|/ ____|__   __|   \ \
 | |  | || | | |  | | |__| |__) | | |  | |__  | (___    | |     (_) |
 | |  | || | | |  | |  __| |  ___/  | |  |  __|  \___ \   | |       | |
 | |__| || |_| |__| | |____| |      | |  | |____ ____) |  | |      _| |
 |_____/_____|_____/|______|_|      |_|  |______|_____/   |_|     (_) |
                                                                   /_/""")

    args = parse_args()

    print(f"🎯 Target: {args.target}")
    print(f"📊 Depth: {args.max_depth} | Rate: {args.rate} RPS")
    if args.ai_analysis:
        print("🤖 AI Analysis: Enabled")
    print()

    loader = SimpleLoader("🔍 Starting security scan")
    loader.start()

    try:
        auth_options = {}
        if args.auth_bruteforce:
            auth_options["allow_bruteforce"] = True

        orch = Orchestrator(base_url=args.target,
                            max_depth=args.max_depth,
                            rate=args.rate,
                            scope=args.scope,
                            auth_options=auth_options)

        loader.stop("Security scan initialized")

        findings = orch.run()
        if findings is None:
            findings = []
            print("⚠️  Warning: Scanner returned no results")

        print(f"🎯 Scan completed - Found {len(findings)} total issues")

    except Exception as e:
        loader.stop(f"Scan failed: {str(e)}")
        return

    # AI Analysis
    if args.ai_analysis:
        ai_loader = SimpleLoader("🤖 Running AI analysis with Gemini")
        ai_loader.start()

        try:
            if not GEMINI_API_KEY or GEMINI_API_KEY == "YOUR_GEMINI_API_KEY_HERE":
                raise ValueError("Gemini API key not configured. Set GEMINI_API_KEY in main.py")

            analyzer = GeminiAnalyzer(api_key=GEMINI_API_KEY)
            findings = analyzer.analyze_findings(findings)
            ai_loader.stop("AI analysis completed")
            print("✅ AI insights added to findings")

        except Exception as e:
            ai_loader.stop(f"AI analysis failed: {str(e)}")
            print(f"⚠️  Continuing without AI analysis: {str(e)}")

    report_loader = SimpleLoader("📝 Generating report")
    report_loader.start()

    try:
        if args.pdf:
            to_pdf(findings, datetime.utcnow().isoformat() + "Z", args.pdf)
            report_loader.stop("PDF report generated successfully")
            print(f"📄 PDF: {args.pdf}")
        else:
            Reporter.to_json(findings, args.out)
            Reporter.to_html(findings, args.html)
            report_loader.stop("Reports generated successfully")
            print(f"📄 JSON: {args.out}")
            print(f"🌐 HTML: {args.html}")

        print("✅ All done!")
    except Exception as e:
        report_loader.stop(f"Report generation failed: {str(e)}")


if __name__ == "__main__":
    main()