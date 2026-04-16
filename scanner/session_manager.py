# scanner/session_manager.py

import json
import time
import requests
from typing import Dict, Any, Optional, Tuple
from pathlib import Path
import logging
from .login_automation import LoginAutomation, LoginFlow
from .session_maintenance import SessionMaintenance, SessionTimeout, SessionMonitor, SessionRefresh
logger = logging.getLogger(__name__)



class SessionState:
    """Enum-like class for session states."""
    UNAUTHENTICATED = "unauthenticated"
    AUTHENTICATED = "authenticated"
    EXPIRED = "expired"
    INVALID = "invalid"


class SessionManager:
    """
    Manages authenticated session lifecycle:
    - Maintains persistent session across scan
    - Handles cookie jar storage/recovery
    - Tracks session state and metadata
    - Provides session validation
    """

    def __init__(self, session_name: str = "auth_session", storage_dir: str = ".dast_sessions"):
        """
        Initialize SessionManager.

        Args:
            session_name: Identifier for this session (used for storage)
            storage_dir: Directory to store session cookies and metadata
        """
        self.session_name = session_name
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(exist_ok=True)

        # Session state tracking
        self.session = requests.Session()
        self.state = SessionState.UNAUTHENTICATED
        self.created_at: Optional[float] = None
        self.last_activity: Optional[float] = None
        self.metadata: Dict[str, Any] = {}

        # Paths for persistence
        self.cookies_file = self.storage_dir / f"{session_name}_cookies.json"
        self.metadata_file = self.storage_dir / f"{session_name}_metadata.json"

        # Load existing session if available
        self._load_session()

    def _load_session(self) -> bool:
        """
        Load existing session from disk.

        Returns:
            True if session loaded successfully, False otherwise
        """
        try:
            if self.cookies_file.exists() and self.metadata_file.exists():
                # Load metadata
                with open(self.metadata_file, 'r') as f:
                    self.metadata = json.load(f)

                self.state = self.metadata.get("state", SessionState.UNAUTHENTICATED)
                self.created_at = self.metadata.get("created_at")
                self.last_activity = self.metadata.get("last_activity")

                # Load cookies
                with open(self.cookies_file, 'r') as f:
                    cookies_data = json.load(f)

                for cookie_dict in cookies_data:
                    self.session.cookies.set(**cookie_dict)

                logger.info(f"Loaded session '{self.session_name}' from disk")
                return True
        except Exception as e:
            logger.warning(f"Failed to load session from disk: {e}")

        return False

    def save_session(self) -> bool:
        """
        Persist session to disk.

        Returns:
            True if saved successfully, False otherwise
        """
        try:
            # Save cookies
            cookies_list = []
            for cookie in self.session.cookies:
                cookies_list.append({
                    "name": cookie.name,
                    "value": cookie.value,
                    "domain": cookie.domain,
                    "path": cookie.path,
                    "secure": cookie.secure,
                    "expires": cookie.expires
                })

            with open(self.cookies_file, 'w') as f:
                json.dump(cookies_list, f, indent=2)

            # Save metadata
            self.metadata.update({
                "state": self.state,
                "created_at": self.created_at,
                "last_activity": self.last_activity,
                "session_name": self.session_name
            })

            with open(self.metadata_file, 'w') as f:
                json.dump(self.metadata, f, indent=2)

            logger.info(f"Saved session '{self.session_name}' to disk")
            return True
        except Exception as e:
            logger.error(f"Failed to save session: {e}")
            return False

    def authenticate(self, login_url: str, username: str, password: str,
                     username_field: str = "username", password_field: str = "password",
                     extra_params: Optional[Dict[str, str]] = None) -> Tuple[bool, str]:
        """
        Authenticate the session with credentials.

        Args:
            login_url: URL to submit login credentials to
            username: Username/email
            password: Password
            username_field: Name of username input field
            password_field: Name of password input field
            extra_params: Additional form parameters to include

        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            # First, GET the login page to capture any CSRF tokens
            logger.info(f"Fetching login page: {login_url}")
            resp = self.session.get(login_url, timeout=10)

            # Prepare login data
            login_data = {
                username_field: username,
                password_field: password
            }

            if extra_params:
                login_data.update(extra_params)

            # Extract CSRF token if present
            csrf_token = self._extract_csrf_token(resp.text)
            if csrf_token:
                # Try common CSRF field names
                for csrf_name in ["csrf_token", "csrfToken", "_csrf", "_token"]:
                    login_data[csrf_name] = csrf_token

            # Perform login
            logger.info(f"Submitting login credentials to {login_url}")
            login_resp = self.session.post(login_url, data=login_data, timeout=10, allow_redirects=True)

            # Validate login success
            success, message = self._validate_login(login_resp, username)

            if success:
                self.state = SessionState.AUTHENTICATED
                self.created_at = time.time()
                self.last_activity = time.time()
                self.metadata["authenticated_as"] = username
                self.metadata["login_url"] = login_url
                logger.info(f"Authentication successful for user '{username}'")
            else:
                self.state = SessionState.INVALID
                logger.warning(f"Authentication failed: {message}")

            self.save_session()
            return success, message

        except Exception as e:
            logger.error(f"Authentication error: {e}")
            self.state = SessionState.INVALID
            return False, str(e)

    def authenticate_with_automation(self, login_config: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Advanced authentication using LoginAutomation.

        Args:
            login_config: Configuration dict with:
                - type: "form", "api", "2fa", or "multi-step"
                - login_url: URL to login endpoint
                - username: Username
                - password: Password
                - Additional params based on type

        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            login_auto = LoginAutomation(self.session)
            login_type = login_config.get("type", "form")

            if login_type == "form":
                success, message = login_auto.login_html_form(
                    login_url=login_config.get("login_url"),
                    username=login_config.get("username"),
                    password=login_config.get("password"),
                    username_field=login_config.get("username_field", "username"),
                    password_field=login_config.get("password_field", "password"),
                    extra_fields=login_config.get("extra_fields")
                )

            elif login_type == "api":
                success, message = login_auto.login_json_api(
                    api_url=login_config.get("login_url"),
                    username=login_config.get("username"),
                    password=login_config.get("password"),
                    username_key=login_config.get("username_key", "username"),
                    password_key=login_config.get("password_key", "password"),
                    extra_data=login_config.get("extra_data"),
                    token_path=login_config.get("token_path", "token")
                )

            elif login_type == "2fa":
                success, message = login_auto.login_with_2fa(
                    login_url=login_config.get("login_url"),
                    username=login_config.get("username"),
                    password=login_config.get("password"),
                    totp_secret=login_config.get("totp_secret"),
                    username_field=login_config.get("username_field", "username"),
                    password_field=login_config.get("password_field", "password"),
                    totp_field=login_config.get("totp_field", "totp_code")
                )

            elif login_type == "multi-step":
                # Build flow from config
                flow_config = login_config.get("flow", [])
                flow = LoginFlow(
                    name=login_config.get("flow_name", "custom"),
                    steps=flow_config
                )

                success, message = login_auto.login_multi_step(
                    flow=flow,
                    credentials={
                        "username": login_config.get("username"),
                        "password": login_config.get("password"),
                        "totp_secret": login_config.get("totp_secret")
                    },
                    validation_url=login_config.get("validation_url")
                )

            else:
                return False, f"Unknown login type: {login_type}"

            if success:
                self.state = SessionState.AUTHENTICATED
                self.created_at = time.time()
                self.last_activity = time.time()
                self.metadata["authenticated_as"] = login_config.get("username")
                self.metadata["login_type"] = login_type
                self.metadata["login_url"] = login_config.get("login_url")
                logger.info(f"Authentication successful via {login_type}")
            else:
                self.state = SessionState.INVALID
                logger.warning(f"Authentication failed: {message}")

            self.save_session()
            return success, message

        except Exception as e:
            logger.error(f"Authentication automation error: {e}")
            self.state = SessionState.INVALID
            return False, str(e)

    def enable_maintenance(self, timeout_seconds: int = 3600,
                           idle_timeout_seconds: int = 1800,
                           validation_url: Optional[str] = None,
                           refresh_url: Optional[str] = None) -> None:
        """
        Enable session maintenance features.

        Args:
            timeout_seconds: Maximum session lifetime
            idle_timeout_seconds: Idle timeout
            validation_url: URL to validate session
            refresh_url: URL to refresh cookies
        """
        self.maintenance = SessionMaintenance(
            session=self.session,
            timeout_seconds=timeout_seconds,
            idle_timeout_seconds=idle_timeout_seconds,
            validation_url=validation_url,
            refresh_url=refresh_url
        )

        # Register re-authentication callback
        self.maintenance.set_reauth_callback(self._reauth_callback)

        logger.info(f"Session maintenance enabled for '{self.session_name}'")

    def _extract_csrf_token(self, html: str) -> Optional[str]:
        """Extract CSRF token from HTML form."""
        import re
        patterns = [
            r'<input[^>]*name=["\']_csrf["\'][^>]*value=["\']([^"\']+)["\']',
            r'<input[^>]*name=["\']csrf_token["\'][^>]*value=["\']([^"\']+)["\']',
            r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']',
        ]

        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)

        return None

    def _validate_login(self, response: requests.Response, username: str) -> Tuple[bool, str]:
        """
        Validate if login was successful based on response indicators.

        Returns:
            Tuple of (success: bool, message: str)
        """
        # Check 1: Session cookies present
        session_cookie_indicators = ["session", "sid", "sessionid", "phpsessid", "auth", "token"]
        for cookie in self.session.cookies:
            if any(ind in cookie.name.lower() for ind in session_cookie_indicators):
                return True, f"Session cookie '{cookie.name}' detected"

        # Check 2: Redirect after login (common pattern)
        if response.status_code in (301, 302, 303):
            return True, "Redirect after login detected"

        # Check 3: JSON response with success/token
        try:
            data = response.json()
            if isinstance(data, dict):
                if data.get("success") or data.get("authenticated") or data.get("token") or data.get("access_token"):
                    return True, "Authentication token/success in response"
        except:
            pass

        # Check 4: Absence of login indicators in response
        login_indicators = ["login", "sign in", "signin", "enter password", "invalid credentials"]
        body_lower = response.text.lower()

        if not any(ind in body_lower for ind in login_indicators):
            return True, "Login page indicators not found in response"

        return False, "No authentication success indicators found"

    def is_valid(self, validate_url: Optional[str] = None) -> bool:
        """
        Check if current session is still valid.

        Args:
            validate_url: Optional URL to validate against (must return 200 if authenticated)

        Returns:
            True if session is valid, False otherwise
        """
        if self.state == SessionState.UNAUTHENTICATED:
            return False

        if self.state == SessionState.INVALID or self.state == SessionState.EXPIRED:
            return False

        # Optional: validate against URL
        if validate_url:
            try:
                resp = self.session.get(validate_url, timeout=5)
                if resp.status_code == 401 or resp.status_code == 403:
                    self.state = SessionState.EXPIRED
                    logger.warning(f"Session validation failed on {validate_url}: {resp.status_code}")
                    return False
                return resp.status_code == 200
            except Exception as e:
                logger.warning(f"Session validation error: {e}")
                return False

        return True

    def get_session(self) -> requests.Session:
        """Get the underlying requests.Session object."""
        self.last_activity = time.time()
        return self.session

    def get_cookies_dict(self) -> Dict[str, str]:
        """Get cookies as a dictionary."""
        return dict(self.session.cookies)

    def get_state(self) -> str:
        """Get current session state."""
        return self.state

    def get_metadata(self) -> Dict[str, Any]:
        """Get session metadata."""
        return self.metadata.copy()

    def clear_session(self) -> None:
        """Clear session cookies and metadata."""
        self.session.cookies.clear()
        self.state = SessionState.UNAUTHENTICATED
        self.metadata = {}

        # Delete files
        try:
            if self.cookies_file.exists():
                self.cookies_file.unlink()
            if self.metadata_file.exists():
                self.metadata_file.unlink()
            logger.info(f"Cleared session '{self.session_name}'")
        except Exception as e:
            logger.warning(f"Failed to delete session files: {e}")


    def _reauth_callback(self, error_message: str) -> Tuple[bool, str]:
        """
        Callback for automatic re-authentication.

        Args:
            error_message: Message about why re-auth is needed

        Returns:
            Tuple of (success: bool, message: str)
        """
        logger.warning(f"Re-authentication triggered: {error_message}")

        # Re-authenticate using stored credentials
        if "authenticated_as" in self.metadata and "login_url" in self.metadata:
            username = self.metadata.get("authenticated_as", "")
            login_url = self.metadata.get("login_url", "")
            login_type = self.metadata.get("login_type", "form")

            auth_config = {
                "login_url": login_url,
                "username": username,
                "type": login_type
            }

            logger.info(f"Attempting re-authentication for user '{username}'")
            success, message = self.authenticate_with_automation(auth_config)

            return success, message

        return False, "Stored credentials not available for re-authentication"

    def check_session_maintenance(self) -> Tuple[str, Dict[str, Any]]:
        """
        Check and perform session maintenance if enabled.

        Returns:
            Tuple of (status: str, details: dict)
        """
        if not hasattr(self, 'maintenance'):
            return "not_enabled", {}

        # Perform maintenance
        success, message = self.maintenance.maintain_session()

        if success:
            status, details = self.maintenance.check_session_health()
            details["maintenance_message"] = message
            return status, details
        else:
            self.state = SessionState.EXPIRED
            return "maintenance_failed", {"error": message}

    def get_maintenance_report(self) -> Dict[str, Any]:
        """Get session maintenance status report."""
        if not hasattr(self, 'maintenance'):
            return {"status": "maintenance_not_enabled"}

        return self.maintenance.get_status_report()