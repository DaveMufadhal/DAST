import re
from bs4 import BeautifulSoup

class CSRFCheck:
    @staticmethod
    def run(http, crawled_urls):
        findings = []

        for url in crawled_urls:
            try:
                r = http.get(url)
                if r.status_code != 200:
                    continue

                soup = BeautifulSoup(r.text, 'html.parser')

                forms = soup.find_all('form')
                for form in forms:
                    method = form.get('method', 'get').lower()
                    action = form.get('action', '')

                    if method == 'get':
                        continue

                    csrf_found = False
                    csrf_patterns = [
                        'csrf', 'token', '_token', 'authenticity_token',
                        'csrftoken', 'csrf_token', '_csrf'
                    ]

                    hidden_inputs = form.find_all('input', {'type': 'hidden'})
                    for hidden in hidden_inputs:
                        name = hidden.get('name', '').lower()
                        if any(pattern in name for pattern in csrf_patterns):
                            csrf_found = True
                            break

                    if not csrf_found:
                        meta_csrf = soup.find('meta', {'name': re.compile(r'csrf|token', re.I)})
                        if meta_csrf:
                            csrf_found = True

                    if not csrf_found:
                        findings.append({
                            "type": "csrf:missing-token",
                            "url": url,
                            "form_action": action,
                            "form_method": method,
                            "severity_score": 7,
                            "evidence": f"Form with method {method.upper()} does not have CSRF token",
                            "recommendation": "Implement CSRF token on all forms that modify application state"
                        })

            except Exception:
                pass

        return findings
