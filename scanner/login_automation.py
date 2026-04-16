# scanner/login_automation.py
# Advanced Login Automation with multi-step flows, 2FA, and API support

import json
import re
import time
import requests
import base64
import logging
from typing import Dict, Any, Optional, Tuple, List
from urllib.parse import urljoin
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class LoginFlow:
    """Represents a multi-step login flow."""

    def __init__(self, name: str, steps: List[Dict[str, Any]]):
        """
        Initialize login flow.

        Args:
            name: Flow name (e.g., "form-based", "api-json", "oauth")
            steps: List of step dictionaries with type, url, method, etc.
        """
        self.name = name
        self.steps = steps
        self.current_step = 0
        self.context = {}  # Shared data between steps (tokens, cookies, etc.)

    def reset(self):
        """Reset flow to beginning."""
        self.current_step = 0
        self.context = {}

    def get_current_step(self) -> Optional[Dict[str, Any]]:
        """Get current step configuration."""
        if self.current_step < len(self.steps):
            return self.steps[self.current_step]
        return None

    def advance(self):
        """Move to next step."""
        self.current_step += 1

    def is_complete(self) -> bool:
        """Check if flow is complete."""
        return self.current_step >= len(self.steps)


class LoginAutomation:
    """
    Advanced login automation supporting:
    - HTML form-based login
    - JSON API login
    - Multi-step authentication flows
    - Basic 2FA/TOTP handling
    - Custom header injection
    """

    def __init__(self, session: requests.Session):
        """
        Initialize LoginAutomation.

        Args:
            session: requests.Session to use for login operations
        """
        self.session = session
        self.last_response = None
        self.login_history = []

    # ==================== AUTO-DETECTION ====================

    def detect_login_type(self, login_url: str) -> str:
        """
        Detect login form type by examining the login page.

        Returns: "form", "api", "oauth", or "unknown"
        """
        try:
            resp = self.session.get(login_url, timeout=10)
            content_type = resp.headers.get('Content-Type', '').lower()
            body = resp.text.lower()

            # Check for JSON API
            if 'application/json' in content_type:
                return "api"

            # Check for OAuth indicators
            if 'oauth' in body or 'authorize' in body or 'consent' in body:
                return "oauth"

            # Check for form
            if '<form' in body or '<input' in body:
                return "form"

            return "unknown"
        except Exception as e:
            logger.warning(f"Failed to detect login type: {e}")
            return "unknown"

    # ==================== FORM-BASED LOGIN ====================

    def login_html_form(self, login_url: str, username: str, password: str,
                        username_field: str = "username", password_field: str = "password",
                        extra_fields: Optional[Dict[str, str]] = None,
                        wait_for_element: Optional[str] = None) -> Tuple[bool, str]:
        """
        Login via HTML form submission.

        Args:
            login_url: URL of login page
            username: Username
            password: Password
            username_field: Form field name for username
            password_field: Form field name for password
            extra_fields: Additional form fields
            wait_for_element: Element to wait for post-login (for JS-based sites)

        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            logger.info(f"📝 HTML Form Login: {login_url}")

            # Step 1: GET login page
            resp = self.session.get(login_url, timeout=10)
            self.last_response = resp

            # Step 2: Extract form data
            form_data = self._extract_form_data(resp.text, username_field, password_field)

            # Step 3: Add credentials
            form_data[username_field] = username
            form_data[password_field] = password

            # Step 4: Add extra fields
            if extra_fields:
                form_data.update(extra_fields)

            # Step 5: Extract form action and method
            action_url, method = self._extract_form_action(resp.text, login_url)

            logger.debug(f"  - Form action: {action_url}")
            logger.debug(f"  - Method: {method}")
            logger.debug(f"  - Fields: {list(form_data.keys())}")

            # Step 6: Submit form
            if method.upper() == "POST":
                login_resp = self.session.post(action_url, data=form_data, timeout=10, allow_redirects=True)
            else:
                login_resp = self.session.get(action_url, params=form_data, timeout=10, allow_redirects=True)

            self.last_response = login_resp

            # Step 7: Validate login
            success, message = self._validate_login_success(login_resp, username)

            self.login_history.append({
                "type": "html_form",
                "url": login_url,
                "username": username,
                "success": success,
                "timestamp": time.time()
            })

            if success:
                logger.info(f"✓ HTML Form Login successful: {message}")
            else:
                logger.warning(f"✗ HTML Form Login failed: {message}")

            return success, message

        except Exception as e:
            logger.error(f"HTML form login error: {e}")
            return False, str(e)

    # ==================== JSON API LOGIN ====================

    def login_json_api(self, api_url: str, username: str, password: str,
                       username_key: str = "username", password_key: str = "password",
                       extra_data: Optional[Dict[str, Any]] = None,
                       token_path: str = "token") -> Tuple[bool, str]:
        """
        Login via JSON API endpoint.

        Args:
            api_url: API endpoint URL for login
            username: Username
            password: Password
            username_key: JSON key for username
            password_key: JSON key for password
            extra_data: Additional JSON fields
            token_path: JSON path to extract token (e.g., "access_token" or "data.token")

        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            logger.info(f"🔌 JSON API Login: {api_url}")

            # Build login payload
            payload = {
                username_key: username,
                password_key: password
            }

            if extra_data:
                payload.update(extra_data)

            logger.debug(f"  - Payload keys: {list(payload.keys())}")

            # Send login request
            resp = self.session.post(
                api_url,
                json=payload,
                timeout=10,
                headers={"Content-Type": "application/json"}
            )
            self.last_response = resp

            logger.debug(f"  - Response status: {resp.status_code}")

            # Parse response
            try:
                data = resp.json()
            except:
                return False, f"Invalid JSON response: {resp.text[:100]}"

            # Check for token in response
            token = self._extract_from_json(data, token_path)

            if token:
                # Store token for future requests
                self.session.headers.update({"Authorization": f"Bearer {token}"})
                logger.info(f"✓ JSON API Login successful - Token extracted")

                self.login_history.append({
                    "type": "json_api",
                    "url": api_url,
                    "username": username,
                    "success": True,
                    "token_extracted": True,
                    "timestamp": time.time()
                })

                return True, "Token extracted and set"

            # Check for success indicator
            if isinstance(data, dict):
                if data.get("success") or data.get("authenticated") or data.get("status") == "success":
                    logger.info(f"✓ JSON API Login successful - Success indicator found")

                    self.login_history.append({
                        "type": "json_api",
                        "url": api_url,
                        "username": username,
                        "success": True,
                        "timestamp": time.time()
                    })

                    return True, "Success indicator in response"

            logger.warning(f"✗ JSON API Login failed - No success indicators")

            self.login_history.append({
                "type": "json_api",
                "url": api_url,
                "username": username,
                "success": False,
                "timestamp": time.time()
            })

            return False, f"No success indicators: {str(data)[:100]}"

        except Exception as e:
            logger.error(f"JSON API login error: {e}")
            return False, str(e)

    # ==================== MULTI-STEP LOGIN ====================

    def login_multi_step(self, flow: LoginFlow, credentials: Dict[str, str],
                         validation_url: Optional[str] = None) -> Tuple[bool, str]:
        """
        Execute multi-step login flow.

        Args:
            flow: LoginFlow object with steps
            credentials: Credentials dict
            validation_url: URL to validate after login

        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            logger.info(f"🔐 Multi-step Login Flow: {flow.name}")
            flow.reset()

            while not flow.is_complete():
                step = flow.get_current_step()
                step_num = flow.current_step + 1

                logger.info(f"  Step {step_num}/{len(flow.steps)}: {step.get('name', 'unknown')}")

                step_type = step.get("type", "form")

                if step_type == "form":
                    success, message = self._execute_form_step(step, credentials, flow)
                elif step_type == "api":
                    success, message = self._execute_api_step(step, credentials, flow)
                elif step_type == "2fa":
                    success, message = self._execute_2fa_step(step, credentials, flow)
                else:
                    success, message = False, f"Unknown step type: {step_type}"

                if not success:
                    logger.error(f"  ✗ Step {step_num} failed: {message}")
                    return False, f"Step {step_num} failed: {message}"

                logger.info(f"  ✓ Step {step_num} completed: {message}")
                flow.advance()

            # Validate final state
            if validation_url:
                logger.info(f"  Validating login at: {validation_url}")
                val_resp = self.session.get(validation_url, timeout=10)
                if val_resp.status_code == 200:
                    logger.info(f"✓ Multi-step Login successful - Validation passed")
                    return True, "Multi-step login successful"
                else:
                    logger.warning(f"✗ Validation failed: {val_resp.status_code}")
                    return False, f"Validation failed: {val_resp.status_code}"

            logger.info(f"✓ Multi-step Login successful")
            return True, "Multi-step login completed"

        except Exception as e:
            logger.error(f"Multi-step login error: {e}")
            return False, str(e)

    # ==================== 2FA/TOTP HANDLING ====================

    def login_with_2fa(self, login_url: str, username: str, password: str,
                       totp_secret: Optional[str] = None,
                       username_field: str = "username",
                       password_field: str = "password",
                       totp_field: str = "totp_code") -> Tuple[bool, str]:
        """
        Login with 2FA/TOTP support.

        Args:
            login_url: Login page URL
            username: Username
            password: Password
            totp_secret: Base32-encoded TOTP secret (if available)
            username_field: Username field name
            password_field: Password field name
            totp_field: TOTP code field name

        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            logger.info(f"🔐 2FA Login: {login_url}")

            # Step 1: Initial form submission (username + password)
            resp = self.session.get(login_url, timeout=10)
            form_data = self._extract_form_data(resp.text, username_field, password_field)
            form_data[username_field] = username
            form_data[password_field] = password

            action_url, method = self._extract_form_action(resp.text, login_url)

            # Submit initial login
            if method.upper() == "POST":
                resp = self.session.post(action_url, data=form_data, timeout=10, allow_redirects=True)
            else:
                resp = self.session.get(action_url, params=form_data, timeout=10, allow_redirects=True)

            # Step 2: Check if 2FA is required
            if "2fa" not in resp.text.lower() and "totp" not in resp.text.lower() and "authenticator" not in resp.text.lower():
                # 2FA not required
                logger.info("✓ 2FA Login successful - No 2FA required")
                return True, "No 2FA required"

            logger.info("  2FA required - generating TOTP code")

            # Step 3: Generate TOTP code if secret provided
            if totp_secret:
                totp_code = self._generate_totp(totp_secret)
                logger.debug(f"  - Generated TOTP: {totp_code}")

                # Submit 2FA form
                form_data_2fa = self._extract_form_data(resp.text, totp_field, totp_field)
                form_data_2fa[totp_field] = totp_code

                action_url_2fa, method_2fa = self._extract_form_action(resp.text, login_url)

                if method_2fa.upper() == "POST":
                    resp = self.session.post(action_url_2fa, data=form_data_2fa, timeout=10, allow_redirects=True)
                else:
                    resp = self.session.get(action_url_2fa, params=form_data_2fa, timeout=10, allow_redirects=True)

                success, message = self._validate_login_success(resp, username)

                if success:
                    logger.info(f"✓ 2FA Login successful: {message}")
                else:
                    logger.warning(f"✗ 2FA Login failed: {message}")

                return success, message
            else:
                logger.warning("  TOTP code required but no secret provided")
                return False, "TOTP secret not provided"

        except Exception as e:
            logger.error(f"2FA login error: {e}")
            return False, str(e)

    # ==================== HELPER METHODS ====================

    def _extract_form_data(self, html: str, username_field: str, password_field: str) -> Dict[str, str]:
        """Extract form data from HTML."""
        form_data = {}
        try:
            soup = BeautifulSoup(html, "html.parser")
            form = soup.find("form")

            if form:
                for inp in form.find_all("input"):
                    name = inp.get("name")
                    value = inp.get("value", "")

                    if name:
                        # Skip username and password fields (will be added later)
                        if name.lower() not in [username_field.lower(), password_field.lower()]:
                            form_data[name] = value
        except Exception as e:
            logger.debug(f"Failed to extract form data: {e}")

        return form_data

    def _extract_form_action(self, html: str, base_url: str) -> Tuple[str, str]:
        """Extract form action URL and method."""
        try:
            soup = BeautifulSoup(html, "html.parser")
            form = soup.find("form")

            if form:
                action = form.get("action", "")
                method = form.get("method", "post").upper()

                # Convert relative to absolute URL
                if action:
                    action = urljoin(base_url, action)
                else:
                    action = base_url

                return action, method
        except Exception as e:
            logger.debug(f"Failed to extract form action: {e}")

        return base_url, "POST"

    def _validate_login_success(self, response: requests.Response, username: str) -> Tuple[bool, str]:
        """Validate if login was successful."""
        # Check 1: Status code
        if response.status_code in (301, 302, 303):
            return True, "Redirect detected"

        # Check 2: Session/Auth cookies
        session_indicators = ["session", "sid", "sessionid", "phpsessid", "auth", "token"]
        for cookie in self.session.cookies:
            if any(ind in cookie.name.lower() for ind in session_indicators):
                return True, f"Session cookie '{cookie.name}' found"

        # Check 3: JSON response
        try:
            data = response.json()
            if isinstance(data, dict):
                if data.get("success") or data.get("authenticated") or data.get("token"):
                    return True, "Success indicator in JSON"
        except:
            pass

        # Check 4: Absence of login indicators
        login_indicators = ["login", "sign in", "signin", "enter password", "invalid credentials",
                            "authentication failed"]
        body_lower = response.text.lower()

        if not any(ind in body_lower for ind in login_indicators):
            return True, "Login page indicators absent"

        return False, "No success indicators found"

    def _extract_from_json(self, data: Dict[str, Any], path: str) -> Optional[Any]:
        """Extract value from nested JSON using dot notation."""
        try:
            parts = path.split(".")
            current = data

            for part in parts:
                if isinstance(current, dict):
                    current = current.get(part)
                else:
                    return None

            return current
        except:
            return None

    def _generate_totp(self, secret: str) -> str:
        """Generate TOTP code from secret."""
        try:
            import pyotp
            totp = pyotp.TOTP(secret)
            return totp.now()
        except ImportError:
            logger.warning("pyotp not installed - cannot generate TOTP")
            return ""
        except Exception as e:
            logger.error(f"TOTP generation error: {e}")
            return ""

    def _execute_form_step(self, step: Dict[str, Any], credentials: Dict[str, str],
                           flow: LoginFlow) -> Tuple[bool, str]:
        """Execute a form submission step in multi-step flow."""
        try:
            url = step.get("url")
            username_field = step.get("username_field", "username")
            password_field = step.get("password_field", "password")

            # Build form data
            form_data = self._extract_form_data(self.last_response.text if self.last_response else "",
                                                username_field, password_field)

            # Add credentials if this step requires them
            if step.get("require_credentials", True):
                form_data[username_field] = credentials.get("username", "")
                form_data[password_field] = credentials.get("password", "")

            # Add custom fields
            if "fields" in step:
                for key, value in step["fields"].items():
                    if isinstance(value, str) and value.startswith("{") and value.endswith("}"):
                        # Resolve variable
                        var_name = value[1:-1]
                        form_data[key] = flow.context.get(var_name, value)
                    else:
                        form_data[key] = value

            # Get form action
            action_url, method = self._extract_form_action(
                self.last_response.text if self.last_response else "",
                url
            )

            # Submit
            if method.upper() == "POST":
                resp = self.session.post(action_url, data=form_data, timeout=10)
            else:
                resp = self.session.get(action_url, params=form_data, timeout=10)

            self.last_response = resp

            # Store context
            if "extract" in step:
                for var_name, css_selector in step["extract"].items():
                    # Simple implementation - in production, use more robust extraction
                    soup = BeautifulSoup(resp.text, "html.parser")
                    elem = soup.select_one(css_selector)
                    if elem:
                        flow.context[var_name] = elem.get("value", elem.text)

            return True, "Form submitted"

        except Exception as e:
            return False, str(e)

    def _execute_api_step(self, step: Dict[str, Any], credentials: Dict[str, str],
                          flow: LoginFlow) -> Tuple[bool, str]:
        """Execute an API request step in multi-step flow."""
        try:
            url = step.get("url")
            method = step.get("method", "POST").upper()

            # Build payload
            payload = step.get("data", {}).copy()

            # Add credentials
            if step.get("require_credentials", True):
                payload["username"] = credentials.get("username", "")
                payload["password"] = credentials.get("password", "")

            # Make request
            headers = step.get("headers", {})
            headers["Content-Type"] = "application/json"

            if method == "POST":
                resp = self.session.post(url, json=payload, headers=headers, timeout=10)
            else:
                resp = self.session.get(url, params=payload, headers=headers, timeout=10)

            self.last_response = resp

            # Extract from response
            try:
                data = resp.json()
                if "extract" in step:
                    for var_name, path in step["extract"].items():
                        value = self._extract_from_json(data, path)
                        flow.context[var_name] = value
            except:
                pass

            return True, f"API request completed ({resp.status_code})"

        except Exception as e:
            return False, str(e)

    def _execute_2fa_step(self, step: Dict[str, Any], credentials: Dict[str, str],
                          flow: LoginFlow) -> Tuple[bool, str]:
        """Execute a 2FA/TOTP verification step."""
        try:
            totp_secret = step.get("totp_secret") or credentials.get("totp_secret")

            if totp_secret:
                totp_code = self._generate_totp(totp_secret)

                # Submit TOTP
                url = step.get("url", self.last_response.url)
                method = step.get("method", "POST")

                form_data = {
                    step.get("totp_field", "totp_code"): totp_code
                }

                if method.upper() == "POST":
                    resp = self.session.post(url, data=form_data, timeout=10)
                else:
                    resp = self.session.get(url, params=form_data, timeout=10)

                self.last_response = resp

                return True, "2FA code submitted"
            else:
                return False, "TOTP secret not provided"

        except Exception as e:
            return False, str(e)

    def get_login_history(self) -> List[Dict[str, Any]]:
        """Get history of login attempts."""
        return self.login_history.copy()
