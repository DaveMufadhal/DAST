def _score_header(value, ok_condition):
    if value is None:
        return 0
    return 2 if ok_condition(value) else -1

class HeaderCheck:
    @staticmethod
    def inspect(url, resp):
        h = {k.lower(): v for k, v in resp.headers.items()}
        findings = []

        csp = h.get("content-security-policy")
        csp_ok = lambda v: "default-src" in v and "unsafe-inline" not in v
        findings.append({
            "type": "header:CSP",
            "url": url,
            "present": csp is not None,
            "severity_score": _score_header(csp, csp_ok),
            "evidence": csp or "missing",
            "recommendation": "Add strict CSP; avoid 'unsafe-inline', use nonce/hash instead."
        })

        hsts = h.get("strict-transport-security")
        hsts_ok = lambda v: "max-age" in v
        findings.append({
            "type": "header:HSTS",
            "url": url,
            "present": hsts is not None,
            "severity_score": _score_header(hsts, hsts_ok),
            "evidence": hsts or "missing",
            "recommendation": "Enable HSTS (HTTPS only) with appropriate max-age value."
        })

        xfo = h.get("x-frame-options")
        findings.append({
            "type": "header:XFO",
            "url": url,
            "present": xfo is not None,
            "severity_score": 2 if (xfo and xfo.upper() in ["DENY", "SAMEORIGIN"]) else (0 if xfo is None else -1),
            "evidence": xfo or "missing",
            "recommendation": "Set 'DENY' or 'SAMEORIGIN' or use 'frame-ancestors' in CSP."
        })

        xcto = h.get("x-content-type-options")
        findings.append({
            "type": "header:XCTO",
            "url": url,
            "present": xcto is not None,
            "severity_score": 2 if (xcto and xcto.lower() == "nosniff") else (0 if xcto is None else -1),
            "evidence": xcto or "missing",
            "recommendation": "Set 'X-Content-Type-Options: nosniff'."
        })

        rp = h.get("referrer-policy")
        findings.append({
            "type": "header:Referrer-Policy",
            "url": url,
            "present": rp is not None,
            "severity_score": 2 if (rp and ("no-referrer" in rp.lower() or "strict-origin" in rp.lower())) else (0 if rp is None else -1),
            "evidence": rp or "missing",
            "recommendation": "Use 'no-referrer' or 'strict-origin-when-cross-origin'."
        })

        pp = h.get("permissions-policy")
        findings.append({
            "type": "header:Permissions-Policy",
            "url": url,
            "present": pp is not None,
            "severity_score": 2 if pp else 0,
            "evidence": pp or "missing",
            "recommendation": "Restrict features (camera, geolocation, microphone, etc)."
        })

        return findings
