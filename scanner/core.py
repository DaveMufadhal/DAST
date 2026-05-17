import time
import requests
import re, urllib.parse as up
from bs4 import BeautifulSoup

from .checks.headers import HeaderCheck
from .checks.cookies_cors import CookieCORSCheck
from .checks.xss import XSSCheck
from .checks.sqli import SQLiCheck
from .checks.csrf import CSRFCheck
from .checks.misconfig import MisconfigCheck
from .loading import SimpleLoader
from .checks.auth_session import AuthSessionCheck
from .checks.lfi import LFICheck
from .checks.ssl_tls_certifcate import SSLTLSCheck
from .reference_validator import validate_findings
from .checks.business_logic import BusinessLogicCheck

class Crawler:
    HREF_RE = re.compile(r'href=["\'](.*?)["\']', re.I)

    def __init__(self, base, http, max_depth=1):

        self.base = base.rstrip("/")
        self.http = http
        self.max_depth = max_depth
        self.visited = set()
        self.params = {}
        self.forms = []
        self.base_host = up.urlparse(self.base).hostname

    def in_scope(self, url):

        return up.urlparse(url).hostname == self.base_host

    def _abs(self, url, href):

        if href.startswith("#/"):
            pr = up.urlparse(url)
            return f"{pr.scheme}://{pr.netloc}{pr.path}{href}"
        return up.urljoin(url, href)

    def crawl(self):
        from collections import deque
        from bs4 import XMLParsedAsHTMLWarning
        import warnings

        warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

        common_paths = [
            "/api", "/rest", "/admin", "/api/users", "/api/products",
            "/api/feedback", "/rest/user", "/rest/admin", "/ftp"
        ]

        q = deque([(self.base, 0)])

        for path in common_paths:
            q.append((self.base + path, 0))

        pages = []
        while q:
            url, d = q.popleft()
            if url in self.visited or d > self.max_depth or not self.in_scope(url):
                continue
            self.visited.add(url)
            try:
                r = self.http.get(url)
                pages.append((url, r))

                qs = up.parse_qs(up.urlparse(url).query)
                if qs:
                    self.params[url] = list(qs.keys())

                html = r.text or ""

                content_type = r.headers.get('Content-Type', '').lower()
                if 'xml' in content_type:
                    soup = BeautifulSoup(html, "xml")
                else:
                    soup = BeautifulSoup(html, "html.parser")

                for a in soup.find_all("a", href=True):
                    nxt = self._abs(url, a["href"])
                    q.append((nxt, d + 1))

                for form in soup.find_all("form"):
                    method = (form.get("method") or "GET").upper()
                    action = form.get("action") or url
                    action = self._abs(url, action)

                    inputs = []
                    for inp in form.find_all(["input", "select", "textarea"]):
                        name = inp.get("name")
                        if not name:
                            continue
                        hidden = (inp.get("type") or "").lower() == "hidden"

                        val = inp.get("value") or ""
                        inputs.append({"name": name, "value": val, "hidden": hidden})

                    if inputs:
                        self.forms.append({
                            "page": url,
                            "action": action,
                            "method": method,
                            "inputs": inputs
                        })

                        if method == "GET":
                            self.params.setdefault(action, [])
                            for f in inputs:
                                if f["name"] not in self.params[action]:
                                    self.params[action].append(f["name"])

            except Exception:
                continue
        return pages


class HttpClient:
    """HTTP client sederhana + rate limit & timeout."""

    def __init__(self, rate=2.0, timeout=10):
        self.sess = requests.Session()

        self.sess.headers.update({"User-Agent": "mini-owasp-scanner/1.0"})
        self.rate = rate
        self.timeout = timeout
        self._last = 0

    def _throttle(self):
        now = time.time()
        delay = max(0, (1 / self.rate) - (now - self._last))
        if delay:
            time.sleep(delay)
        self._last = time.time()

    def get(self, url, **kw):
        self._throttle()
        return self.sess.get(url, timeout=self.timeout, allow_redirects=True, **kw)

    def post(self, url, data=None, **kw):
        self._throttle()
        return self.sess.post(url, data=data, timeout=self.timeout, allow_redirects=True, **kw)


class Orchestrator:
    """Orkestrasi: crawl -> passive checks -> active checks."""

    def __init__(self, base_url, max_depth=1, rate=2.0, scope="same-domain", auth_options=None):
        self.base_url = base_url.rstrip("/")
        self.http = HttpClient(rate=rate)

        self.crawler = Crawler(self.base_url, self.http, max_depth)

        self.auth_options = auth_options or {}

    def run(self):
        findings = []

        crawler_loader = SimpleLoader("🕷️  Crawling website")
        crawler_loader.start()

        pages = self.crawler.crawl()

        crawler_loader.stop(f"Found {len(pages)} pages")

        crawled_urls = [url for url, resp in pages]

        header_loader = SimpleLoader("🔒 Checking security headers")
        header_loader.start()

        header_findings = []
        for url, resp in pages:
            header_findings += HeaderCheck.inspect(url, resp)
        findings += header_findings

        header_loader.stop(f"Header check completed - Found {len(header_findings)} issues")

        cookie_loader = SimpleLoader("🍪 Analyzing cookies & CORS")
        cookie_loader.start()

        cookie_findings = []
        for url, resp in pages:
            cookie_findings += CookieCORSCheck.inspect(url, resp)
        findings += cookie_findings

        cookie_loader.stop(f"Cookie & CORS check completed - Found {len(cookie_findings)} issues")

        # Business Logic Testing
        logic_loader = SimpleLoader(
            "🧠 Testing business logic vulnerabilities"
        )
        logic_loader.start()

        logic_findings = BusinessLogicCheck.run(
            self.http,
            self.crawler.forms
        )

        findings += logic_findings

        logic_loader.stop(
            f"Business logic testing completed - "
            f"Found {len(logic_findings)} issues"
        )

        params_map = self.crawler.params
        if params_map:
            # SQL Injection checks
            sqli_loader = SimpleLoader("💉 Testing for SQL injection")
            sqli_loader.start()

            sqli_findings = SQLiCheck.run(self.http, params_map)
            findings += sqli_findings

            sqli_loader.stop(f"SQL injection test completed - Found {len(sqli_findings)} vulnerabilities")

            # XSS checks
            xss_loader = SimpleLoader("🎭 Testing for Cross-Site Scripting")
            xss_loader.start()

            xss_findings = XSSCheck.run(self.http, params_map)
            findings += xss_findings

            xss_loader.stop(f"XSS test completed - Found {len(xss_findings)} vulnerabilities")

            # LFI checks
            lfi_loader = SimpleLoader("📁 Testing for Local File Inclusion")
            lfi_loader.start()

            lfi_findings = LFICheck.run(self.http, params_map)
            findings += lfi_findings

            lfi_loader.stop(f"LFI test completed - Found {len(lfi_findings)} vulnerabilities")
        else:
            print("ℹ️  No parameters found for injection testing")

        misc_loader = SimpleLoader("🔧 Checking CSRF & misconfigurations")
        misc_loader.start()

        csrf_findings = CSRFCheck.run(self.http, crawled_urls)
        misconfig_findings = MisconfigCheck.run(self.http, crawled_urls)
        findings += csrf_findings
        findings += misconfig_findings

        total_misc = len(csrf_findings) + len(misconfig_findings)
        misc_loader.stop(f"CSRF & misconfiguration check completed - Found {total_misc} issues")

        if self.crawler.forms:
            # SQLi via POST forms
            sqli_post_loader = SimpleLoader("💉 Testing SQL injection (POST forms)")
            sqli_post_loader.start()

            sqli_post_findings = SQLiCheck.run_forms(self.http, self.crawler.forms)
            findings += sqli_post_findings

            sqli_post_loader.stop(f"SQL injection (POST) completed - Found {len(sqli_post_findings)} vulnerabilities")

            # XSS via POST forms
            xss_post_loader = SimpleLoader("🎭 Testing Cross-Site Scripting (POST forms)")
            xss_post_loader.start()

            xss_post_findings = XSSCheck.run_forms(self.http, self.crawler.forms)
            findings += xss_post_findings

            xss_post_loader.stop(f"XSS (POST) completed - Found {len(xss_post_findings)} vulnerabilities")

            # LFI via POST forms
            lfi_post_loader = SimpleLoader("📁 Testing Local File Inclusion (POST forms)")
            lfi_post_loader.start()

            lfi_post_findings = LFICheck.run_forms(self.http, self.crawler.forms)
            findings += lfi_post_findings

            lfi_post_loader.stop(f"LFI (POST) completed - Found {len(lfi_post_findings)} vulnerabilities")

            # Authentication and Session Analysis
        auth_loader = SimpleLoader("🔐 Analyzing authentication & sessions")
        auth_loader.start()

        auth_findings = []
        try:

            auth_opts = getattr(self, "auth_options", {}) or {}

            if isinstance(auth_opts, dict) and auth_opts.get("allow_bruteforce") and hasattr(AuthSessionCheck,
                                                                                             "run_enhanced"):
                maybe = AuthSessionCheck.run_enhanced(self.http, pages, auth_opts)
                auth_findings = AuthSessionCheck.run_enhanced(self.http, pages, auth_opts)
            else:
                maybe = AuthSessionCheck.run(self.http, self.base_url, pages, getattr(self.crawler, "forms", []),
                                             auth_opts)
                auth_findings = AuthSessionCheck.run(self.http, self.base_url, pages, self.crawler.forms, auth_opts)
            auth_findings = maybe if isinstance(maybe, list) else (list(maybe) if maybe is not None else [])
        except Exception as e:

            auth_findings = [{
                "type": "auth:check-error",
                "url": self.base_url,
                "evidence": f"Authentication check raised exception: {e}",
                "severity_score": 2
            }]
        finally:
            findings.extend(auth_findings)
            count = len(auth_findings) if isinstance(auth_findings, list) else 0
            auth_loader.stop(f"Authentication analysis completed - Found {count} issues")
            # 7) SSL/TLS certificate checks
        if self.base_url.startswith('https://'):
            ssl_loader = SimpleLoader("🔐 Checking SSL/TLS configuration")
            ssl_loader.start()

            ssl_findings = SSLTLSCheck.run(self.base_url, self.http)
            findings += ssl_findings

            ssl_loader.stop(f"SSL/TLS check completed - Found {len(ssl_findings)} issues")
        else:
            print("ℹ️  Skipping SSL/TLS checks for non-HTTPS URL")
        # At the very end, before return findings
        validated_findings, ref_stats = validate_findings(findings)
        print(
            f"📚 Reference validation: {ref_stats['validated']}/{ref_stats['total']} "
            f"mapped to OWASP/CWE/MITRE, {ref_stats['needs_manual_review']} need manual review"
        )
        return validated_findings
        return findings