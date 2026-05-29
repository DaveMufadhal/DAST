import re
import urllib.parse


def xss_payloads(base_payloads=None):
    """
    Generate XSS payloads:
    - classic reflected payloads
    - encoded variants
    - event-handler payloads
    - script-based
    """
    if base_payloads is None:
        base_payloads = [
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
        ]

    out = list(base_payloads)

    encoded = [
        urllib.parse.quote(p) for p in base_payloads
    ]
    out.extend(encoded)

    event_payloads = [
        "<body onload=alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<iframe src=javascript:alert(1)>",
    ]
    out.extend(event_payloads)

    seen = set()
    res = []
    for p in out:
        if p not in seen:
            seen.add(p)
            res.append(p)
    return res


class XSSCheck:
    """Cross-Site Scripting (XSS) vulnerability checker."""

    XSS_PAYLOADS = xss_payloads()

    INDICATORS = [
        "<script>alert",
        "alert(1)",
        "onerror=",
        "onload=",
        "<img",
        "<svg",
    ]

    @classmethod
    def run(cls, http, params_map):
        """Test GET parameters for XSS vulnerabilities."""
        findings = []

        for url, param_names in params_map.items():
            for param in param_names:
                findings.extend(cls._test_parameter(http, url, param))

        return findings

    @classmethod
    def run_forms(cls, http, forms):
        """Test POST forms for XSS vulnerabilities."""
        findings = []

        for form in forms:
            if form["method"].upper() == "POST":
                findings.extend(cls._test_form(http, form))

        return findings

    @classmethod
    def _test_parameter(cls, http, url, param_name):
        """Test a GET parameter for XSS."""
        findings = []

        for payload in cls.XSS_PAYLOADS:
            try:
                parsed = urllib.parse.urlparse(url)
                query_params = urllib.parse.parse_qs(parsed.query)

                query_params[param_name] = [payload]
                new_query = urllib.parse.urlencode(query_params, doseq=True)

                test_url = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))

                response = http.get(test_url)

                if cls._is_vulnerable_reflected(response, payload):
                    findings.append({
                        "type": "XSS (Reflected)",
                        "severity": "HIGH",
                        "severity_score": 8,
                        "url": test_url,
                        "param": param_name,
                        "payload": payload,
                        "evidence": cls._extract_evidence(response.text, payload),
                        "description": f"Reflected XSS vulnerability found in parameter '{param_name}'. "
                                       f"The application reflects user input without proper sanitization.",
                        "recommendation": "Sanitize user input, use proper output encoding (HTML entity encoding), "
                                          "and implement Content Security Policy (CSP)."
                    })
                    break

            except Exception:
                continue

        return findings

    @classmethod
    def _test_form(cls, http, form):
        """Test a POST form for XSS."""
        findings = []

        for input_field in form["inputs"]:
            if input_field["hidden"]:
                continue

            param_name = input_field["name"]

            for payload in cls.XSS_PAYLOADS:
                try:
                    data = {}
                    for inp in form["inputs"]:
                        if inp["name"] == param_name:
                            data[inp["name"]] = payload
                        else:
                            data[inp["name"]] = inp["value"]

                    response = http.post(form["action"], data=data)

                    if cls._is_vulnerable_stored(http, form, payload):
                        findings.append({
                            "type": "XSS (Stored)",
                            "severity": "HIGH",
                            "severity_score": 8,
                            "url": form["action"],
                            "form_page": form["page"],
                            "param": param_name,
                            "payload": payload,
                            "evidence": cls._extract_evidence(response.text, payload),
                            "description": f"Stored XSS vulnerability found in form parameter '{param_name}'. "
                                           f"The application stores and reflects user input without proper sanitization.",
                            "recommendation": "Sanitize user input during storage, use proper output encoding when displaying, "
                                              "and implement Content Security Policy (CSP)."
                        })
                        break

                except Exception:
                    continue

        return findings

    @classmethod
    def _is_vulnerable_reflected(cls, response, payload):
        """Check if response indicates reflected XSS."""
        if not response or not response.text:
            return False

        payload_unquoted = urllib.parse.unquote(payload)

        for indicator in cls.INDICATORS:
            if indicator.lower() in response.text.lower():
                if payload_unquoted.lower() in response.text.lower():
                    return True

        return False

    @classmethod
    def _is_vulnerable_stored(cls, http, form, payload):
        """Check if payload was stored and can be retrieved."""
        try:
            response = http.get(form["page"])
            if payload in response.text or urllib.parse.unquote(payload) in response.text:
                return True
        except Exception:
            pass
        return False

    @classmethod
    def _extract_evidence(cls, response_text, payload):
        """Extract evidence from response."""
        if not response_text:
            return "No response text"

        payload_unquoted = urllib.parse.unquote(payload)

        start = response_text.lower().find(payload_unquoted.lower())
        if start != -1:
            start = max(0, start - 50)
            end = min(len(response_text), start + 200)
            return response_text[start:end].strip()

        for indicator in cls.INDICATORS:
            if indicator.lower() in response_text.lower():
                idx = response_text.lower().find(indicator.lower())
                start = max(0, idx - 50)
                end = min(len(response_text), idx + 150)
                return response_text[start:end].strip()

        lines = response_text.split('\n')
        for line in lines:
            if payload_unquoted.lower() in line.lower():
                return line.strip()[:200]

        return "Payload reflected in response"
"""Check if payload was stored and can be retrieved."""