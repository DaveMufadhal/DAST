# scanner/authenticated_scanner.py
# Advanced authenticated endpoint scanning with comparison and privilege escalation testing

import logging
import time
from typing import Dict, List, Any, Tuple, Optional
from urllib.parse import urljoin, urlparse
import requests
from .session_manager import SessionManager

logger = logging.getLogger(__name__)


class AuthenticatedScanComparison:
    """Compares vulnerability findings between authenticated and unauthenticated scans."""

    def __init__(self):
        self.unauth_findings = []
        self.auth_findings = []
        self.comparison_results = []

    def set_unauth_findings(self, findings: List[Dict[str, Any]]) -> None:
        """Set findings from unauthenticated scan."""
        self.unauth_findings = findings

    def set_auth_findings(self, findings: List[Dict[str, Any]]) -> None:
        """Set findings from authenticated scan."""
        self.auth_findings = findings

    def compare(self) -> List[Dict[str, Any]]:
        """
        Compare findings between authenticated and unauthenticated scans.

        Returns:
            List of comparison findings
        """
        comparison = []

        # Group findings by type
        unauth_by_type = {}
        auth_by_type = {}

        for finding in self.unauth_findings:
            ftype = finding.get("type", "unknown")
            if ftype not in unauth_by_type:
                unauth_by_type[ftype] = []
            unauth_by_type[ftype].append(finding)

        for finding in self.auth_findings:
            ftype = finding.get("type", "unknown")
            if ftype not in auth_by_type:
                auth_by_type[ftype] = []
            auth_by_type[ftype].append(finding)

        # Compare
        all_types = set(unauth_by_type.keys()) | set(auth_by_type.keys())

        for ftype in all_types:
            unauth_count = len(unauth_by_type.get(ftype, []))
            auth_count = len(auth_by_type.get(ftype, []))

            if unauth_count != auth_count:
                if auth_count > unauth_count:
                    comparison.append({
                        "type": "scan:comparison-more-issues",
                        "issue_type": ftype,
                        "unauthenticated_count": unauth_count,
                        "authenticated_count": auth_count,
                        "difference": auth_count - unauth_count,
                        "evidence": f"Authenticated scan found {auth_count - unauth_count} more {ftype} issues than unauthenticated scan",
                        "recommendation": "Authenticated access may expose additional vulnerabilities",
                        "severity_score": 7
                    })
                else:
                    comparison.append({
                        "type": "scan:comparison-fewer-issues",
                        "issue_type": ftype,
                        "unauthenticated_count": unauth_count,
                        "authenticated_count": auth_count,
                        "difference": unauth_count - auth_count,
                        "evidence": f"Authentication may mitigate {unauth_count - auth_count} {ftype} issues",
                        "recommendation": "Investigate why unauthenticated access has more vulnerabilities",
                        "severity_score": 2
                    })

        self.comparison_results = comparison
        return comparison


class PrivilegeEscalationTester:
    """Tests for privilege escalation vulnerabilities."""

    def __init__(self, http_client, base_url: str):
        """
        Initialize privilege escalation tester.

        Args:
            http_client: HttpClient instance
            base_url: Target base URL
        """
        self.http = http_client
        self.base_url = base_url.rstrip("/")
        self.findings = []

    def test_endpoint_access(self, endpoint: str, username_a: str, username_b: str,
                             session_a: requests.Session, session_b: requests.Session) -> List[Dict[str, Any]]:
        """
        Test if User A can access resources belonging to User B.

        Args:
            endpoint: Endpoint to test (e.g., /api/users/{username})
            username_a: First user
            username_b: Second user
            session_a: Session for User A
            session_b: Session for User B

        Returns:
            List of privilege escalation findings
        """
        findings = []

        try:
            # Replace {username} with actual usernames
            url_a = endpoint.replace("{username}", username_a).replace("{user}", username_a)
            url_b = endpoint.replace("{username}", username_b).replace("{user}", username_b)

            # Make absolute URLs
            url_a = urljoin(self.base_url, url_a)
            url_b = urljoin(self.base_url, url_b)

            logger.info(f"🔐 Testing endpoint access: {endpoint}")
            logger.debug(f"  - User A URL: {url_a}")
            logger.debug(f"  - User B URL: {url_b}")

            # Test User A accessing User B's resource
            try:
                resp_a_to_b = session_a.get(url_b, timeout=10)

                if resp_a_to_b.status_code == 200:
                    findings.append({
                        "type": "priv-esc:horizontal-escalation",
                        "url": url_b,
                        "accessed_by": username_a,
                        "resource_owner": username_b,
                        "evidence": f"User '{username_a}' successfully accessed '{username_b}' resource at {url_b}",
                        "recommendation": "Implement proper authorization checks to prevent horizontal privilege escalation",
                        "severity_score": 9
                    })
                    logger.warning(f"  ✗ IDOR found: {username_a} can access {username_b}'s resources")
                elif resp_a_to_b.status_code in (401, 403):
                    logger.info(f"  ✓ Properly protected: {username_a} cannot access {username_b}'s resources")
            except Exception as e:
                logger.debug(f"Error accessing {url_b}: {e}")

            # Test User A accessing own resource (should succeed)
            try:
                resp_a_to_a = session_a.get(url_a, timeout=10)

                if resp_a_to_a.status_code != 200:
                    logger.warning(f"  ⚠️  User cannot access own resource")
            except Exception as e:
                logger.debug(f"Error accessing {url_a}: {e}")

        except Exception as e:
            logger.error(f"Privilege escalation test error: {e}")

        self.findings.extend(findings)
        return findings

    def test_parameter_tampering(self, base_endpoint: str, param_name: str,
                                 username_a: str, username_b: str,
                                 session_a: requests.Session) -> List[Dict[str, Any]]:
        """
        Test for parameter tampering leading to privilege escalation.

        Args:
            base_endpoint: Base endpoint (e.g., /api/profile)
            param_name: Parameter to tamper with (e.g., 'user_id', 'username')
            username_a: First user
            username_b: Second user
            session_a: Session for User A

        Returns:
            List of findings
        """
        findings = []

        try:
            logger.info(f"🔐 Testing parameter tampering: {param_name}")

            url = urljoin(self.base_url, base_endpoint)

            # Test 1: Direct parameter tampering
            params = {param_name: username_b}
            resp = session_a.get(url, params=params, timeout=10)

            if resp.status_code == 200:
                # Check if response contains information about User B
                if username_b.lower() in resp.text.lower():
                    findings.append({
                        "type": "priv-esc:parameter-tampering",
                        "url": url,
                        "parameter": param_name,
                        "accessed_by": username_a,
                        "resource_owner": username_b,
                        "evidence": f"Parameter '{param_name}' can be tampered to access other user's data",
                        "recommendation": "Validate and verify ownership of resources before returning data",
                        "severity_score": 9
                    })
                    logger.warning(f"  ✗ Parameter tampering found: {param_name}")

            # Test 2: ID-based parameter tampering (numeric IDs)
            logger.debug(f"  Testing numeric ID tampering...")
            for test_id in range(1, 5):
                params_id = {param_name: str(test_id)}
                resp = session_a.get(url, params=params_id, timeout=10)

                if resp.status_code == 200 and len(resp.text) > 100:
                    findings.append({
                        "type": "priv-esc:idor-numeric",
                        "url": url,
                        "parameter": param_name,
                        "test_id": test_id,
                        "accessed_by": username_a,
                        "evidence": f"Numeric ID {test_id} in parameter '{param_name}' returns data",
                        "recommendation": "Implement ID-based access control and verify ownership",
                        "severity_score": 8
                    })
                    break

        except Exception as e:
            logger.error(f"Parameter tampering test error: {e}")

        self.findings.extend(findings)
        return findings

    def test_admin_endpoints(self, admin_endpoints: List[str],
                             user_session: requests.Session,
                             admin_username: str) -> List[Dict[str, Any]]:
        """
        Test if regular user can access admin endpoints.

        Args:
            admin_endpoints: List of suspected admin endpoints
            user_session: Session for non-admin user
            admin_username: Admin username (for comparison)

        Returns:
            List of findings
        """
        findings = []

        try:
            logger.info(f"🔐 Testing admin endpoint access...")

            for endpoint in admin_endpoints:
                url = urljoin(self.base_url, endpoint)

                try:
                    resp = user_session.get(url, timeout=10)

                    if resp.status_code == 200:
                        findings.append({
                            "type": "priv-esc:admin-access",
                            "url": url,
                            "evidence": f"Non-admin user can access admin endpoint: {endpoint}",
                            "recommendation": "Restrict admin endpoints to authorized users only",
                            "severity_score": 10
                        })
                        logger.warning(f"  ✗ Admin endpoint accessible: {endpoint}")
                    elif resp.status_code in (401, 403):
                        logger.info(f"  ✓ Admin endpoint protected: {endpoint}")
                    else:
                        logger.debug(f"  Endpoint {endpoint}: {resp.status_code}")

                except Exception as e:
                    logger.debug(f"Error testing {url}: {e}")

        except Exception as e:
            logger.error(f"Admin endpoint test error: {e}")

        self.findings.extend(findings)
        return findings

    def get_findings(self) -> List[Dict[str, Any]]:
        """Get all privilege escalation findings."""
        return self.findings.copy()


class AuthenticatedPageScanner:
    """Runs all security checks on authenticated pages."""

    def __init__(self, http_client, base_url: str):
        """
        Initialize authenticated page scanner.

        Args:
            http_client: HttpClient instance
            base_url: Target base URL
        """
        self.http = http_client
        self.base_url = base_url.rstrip("/")
        self.authenticated_findings = []

    def scan_authenticated_endpoints(self, pages: List[Tuple[str, Any]],
                                     forms: List[Dict[str, Any]],
                                     params: Dict[str, List[str]],
                                     check_classes: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Run all security checks on authenticated pages.

        Args:
            pages: List of (url, response) tuples
            forms: List of form dictionaries
            params: Dictionary of parameters by URL
            check_classes: Dictionary of check classes (HeaderCheck, XSSCheck, etc.)

        Returns:
            List of findings
        """
        findings = []

        logger.info(f"🔐 Running authenticated endpoint scans...")

        # Run checks on each authenticated page
        from .checks.headers import HeaderCheck
        from .checks.cookies_cors import CookieCORSCheck
        from .checks.xss import XSSCheck
        from .checks.sqli import SQLiCheck
        from .checks.lfi import LFICheck

        for url, resp in pages:
            logger.debug(f"  Scanning authenticated page: {url}")

            # Header checks
            try:
                header_findings = HeaderCheck.inspect(url, resp)
                findings.extend(header_findings)
            except Exception as e:
                logger.debug(f"Header check error: {e}")

            # Cookie/CORS checks
            try:
                cookie_findings = CookieCORSCheck.inspect(url, resp)
                findings.extend(cookie_findings)
            except Exception as e:
                logger.debug(f"Cookie check error: {e}")

        # SQL Injection on authenticated endpoints
        if params:
            try:
                logger.info("  Running SQL injection tests on authenticated endpoints...")
                sqli_findings = SQLiCheck.run(self.http, params)
                findings.extend(sqli_findings)
            except Exception as e:
                logger.debug(f"SQLi check error: {e}")

            # XSS on authenticated endpoints
            try:
                logger.info("  Running XSS tests on authenticated endpoints...")
                xss_findings = XSSCheck.run(self.http, params)
                findings.extend(xss_findings)
            except Exception as e:
                logger.debug(f"XSS check error: {e}")

            # LFI on authenticated endpoints
            try:
                logger.info("  Running LFI tests on authenticated endpoints...")
                lfi_findings = LFICheck.run(self.http, params)
                findings.extend(lfi_findings)
            except Exception as e:
                logger.debug(f"LFI check error: {e}")

        # Form-based injection tests
        if forms:
            try:
                logger.info("  Running injection tests on authenticated forms...")
                sqli_form_findings = SQLiCheck.run_forms(self.http, forms)
                findings.extend(sqli_form_findings)

                xss_form_findings = XSSCheck.run_forms(self.http, forms)
                findings.extend(xss_form_findings)

                lfi_form_findings = LFICheck.run_forms(self.http, forms)
                findings.extend(lfi_form_findings)
            except Exception as e:
                logger.debug(f"Form-based check error: {e}")

        self.authenticated_findings = findings
        logger.info(f"  Authenticated endpoint scan completed - Found {len(findings)} issues")

        return findings

    def get_findings(self) -> List[Dict[str, Any]]:
        """Get all authenticated scanning findings."""
        return self.authenticated_findings.copy()
