from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional
import re


@dataclass(frozen=True)
class ReferenceItem:
    id: str
    title: str
    url: str
    source: str


REFERENCE_CATALOG: Dict[str, List[ReferenceItem]] = {
    "xss": [
        ReferenceItem(
            id="OWASP-A03-2021",
            title="Injection",
            url="https://owasp.org/Top10/A03_2021-Injection/",
            source="OWASP",
        ),
        ReferenceItem(
            id="CWE-79",
            title="Improper Neutralization of Input During Web Page Generation",
            url="https://cwe.mitre.org/data/definitions/79.html",
            source="CWE",
        ),
    ],
    "sqli": [
        ReferenceItem(
            id="OWASP-A03-2021",
            title="Injection",
            url="https://owasp.org/Top10/A03_2021-Injection/",
            source="OWASP",
        ),
        ReferenceItem(
            id="CWE-89",
            title="SQL Injection",
            url="https://cwe.mitre.org/data/definitions/89.html",
            source="CWE",
        ),
    ],
    "csrf": [
        ReferenceItem(
            id="CWE-352",
            title="Cross-Site Request Forgery",
            url="https://cwe.mitre.org/data/definitions/352.html",
            source="CWE",
        ),
        ReferenceItem(
            id="OWASP-A01-2021",
            title="Cross Site Request Forgery Prevention",
            url="https://owasp.org/www-community/attacks/csrf",
            source="OWASP",
        ),
    ],
    "lfi": [
        ReferenceItem(
            id="CWE-98",
            title="Improper Control of Filename for Include/Require Statement",
            url="https://cwe.mitre.org/data/definitions/98.html",
            source="CWE",
        ),
        ReferenceItem(
            id="CWE-22",
            title="Path Traversal",
            url="https://cwe.mitre.org/data/definitions/22.html",
            source="CWE",
        ),
    ],
    "cookie": [
        ReferenceItem(
            id="CWE-614",
            title="Sensitive Cookie in HTTPS Session Without Secure Attribute",
            url="https://cwe.mitre.org/data/definitions/614.html",
            source="CWE",
        ),
        ReferenceItem(
            id="CWE-1004",
            title="Sensitive Cookie without HttpOnly Flag",
            url="https://cwe.mitre.org/data/definitions/1004.html",
            source="CWE",
        ),
    ],
    "cors": [
        ReferenceItem(
            id="CWE-942",
            title="Permissive Cross-domain Policy with Untrusted Domains",
            url="https://cwe.mitre.org/data/definitions/942.html",
            source="CWE",
        ),
    ],
    "ssl": [
        ReferenceItem(
            id="OWASP-A02-2021",
            title="Cryptographic Failures",
            url="https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
            source="OWASP",
        ),
        ReferenceItem(
            id="CWE-326",
            title="Inadequate Encryption Strength",
            url="https://cwe.mitre.org/data/definitions/326.html",
            source="CWE",
        ),
    ],
    "auth": [
        ReferenceItem(
            id="OWASP-A07-2021",
            title="Identification and Authentication Failures",
            url="https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
            source="OWASP",
        ),
        ReferenceItem(
            id="CWE-287",
            title="Improper Authentication",
            url="https://cwe.mitre.org/data/definitions/287.html",
            source="CWE",
        ),
    ],
    "headers": [
        ReferenceItem(
            id="OWASP-ASVS-V14",
            title="Configuring HTTP Security Headers",
            url="https://owasp.org/www-project-application-security-verification-standard/",
            source="OWASP",
        ),
        ReferenceItem(
            id="CWE-693",
            title="Protection Mechanism Failure",
            url="https://cwe.mitre.org/data/definitions/693.html",
            source="CWE",
        ),
    ],
    "misconfig": [
        ReferenceItem(
            id="OWASP-A05-2021",
            title="Security Misconfiguration",
            url="https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
            source="OWASP",
        ),
        ReferenceItem(
            id="CWE-16",
            title="Configuration",
            url="https://cwe.mitre.org/data/definitions/16.html",
            source="CWE",
        ),
    ],
    "business_logic": [
        ReferenceItem(
            id="OWASP-A10-2021",
            title="Server-Side Request Forgery (SSRF)",
            url="https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
            source="OWASP",
        ),
        ReferenceItem(
            id="CWE-863",
            title="Incorrect Authorization",
            url="https://cwe.mitre.org/data/definitions/863.html",
            source="CWE",
        ),
        ReferenceItem(
            id="CWE-943",
            title="Improper Neutralization of Special Elements in Data Query Logic",
            url="https://cwe.mitre.org/data/definitions/943.html",
            source="CWE",
        ),
        ReferenceItem(
            id="CWE-697",
            title="Incorrect Comparison",
            url="https://cwe.mitre.org/data/definitions/697.html",
            source="CWE",
        ),
    ],
}


def _infer_category(finding_type: str) -> str:
    t = (finding_type or "").lower()
    if "xss" in t:
        return "xss"
    if "sqli" in t or "sql" in t:
        return "sqli"
    if "csrf" in t:
        return "csrf"
    if "lfi" in t or "file inclusion" in t or "path traversal" in t:
        return "lfi"
    if "cookie" in t:
        return "cookie"
    if "cors" in t:
        return "cors"
    if "ssl" in t or "tls" in t or "cert" in t or "https" in t:
        return "ssl"
    if "auth" in t or "session" in t or "bruteforce" in t:
        return "auth"
    if "header" in t or "csp" in t or "hsts" in t:
        return "headers"
    if "misconfig" in t or "configuration" in t:
        return "misconfig"
    if "business logic" in t or "price" in t or "quantity" in t or "role" in t or "coupon" in t or "race condition" in t:
        return "business_logic"
    return "unknown"



def _is_trusted_url(url: str) -> bool:
    if not url:
        return False
    return bool(
        re.match(
            r"^https://(owasp\.org|cwe\.mitre\.org|attack\.mitre\.org|capec\.mitre\.org)/",
            url.strip().lower(),
        )
    )


def _extract_ids_by_source(references: List[dict]) -> Dict[str, List[str]]:
    """Extract CWE and OWASP IDs grouped by source."""
    ids_by_source = {"CWE": [], "OWASP": [], "other": []}
    for ref in references:
        source = ref.get("source", "other")
        ref_id = ref.get("id", "")
        if source == "CWE":
            ids_by_source["CWE"].append(ref_id)
        elif source == "OWASP":
            ids_by_source["OWASP"].append(ref_id)
        else:
            ids_by_source["other"].append(f"{ref_id} ({source})")
    return ids_by_source


def attach_references(finding: dict) -> dict:
    finding_type = finding.get("type", "")
    category = _infer_category(finding_type)
    refs = REFERENCE_CATALOG.get(category, [])

    finding["category"] = category
    finding["references"] = [
        {"id": r.id, "title": r.title, "url": r.url, "source": r.source}
        for r in refs
        if _is_trusted_url(r.url)
    ]

    # Extract IDs by source
    ids_by_source = _extract_ids_by_source(finding["references"])
    finding["cwe_ids"] = ids_by_source["CWE"]
    finding["owasp_ids"] = ids_by_source["OWASP"]

    if finding["references"]:
        finding["reference_validated"] = True
        finding["confidence"] = finding.get("confidence", "medium")
    else:
        finding["reference_validated"] = False
        finding["confidence"] = "low"
        finding["false_positive_risk"] = "high"
        if "severity_score" in finding and isinstance(
            finding["severity_score"], (int, float)
        ):
            finding["severity_score"] = max(1, finding["severity_score"] - 2)

    return finding


def validate_findings(findings: List[dict]) -> tuple[List[dict], Dict[str, int]]:
    out: List[dict] = []
    validated = 0
    unvalidated = 0

    for f in findings:
        nf = attach_references(f)
        out.append(nf)
        if nf.get("reference_validated"):
            validated += 1
        else:
            unvalidated += 1

    stats = {
        "total": len(out),
        "validated": validated,
        "needs_manual_review": unvalidated,
    }
    return out, stats