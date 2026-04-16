# scanner/session_maintenance.py
# Session maintenance: timeout handling, re-authentication, cookie refresh

import time
import logging
from typing import Optional, Callable, Dict, Any, Tuple
from datetime import datetime, timedelta
import requests

logger = logging.getLogger(__name__)


class SessionTimeout:
    """Detects and handles session timeouts."""

    def __init__(self, timeout_seconds: int = 3600, idle_timeout_seconds: int = 1800):
        """
        Initialize session timeout handler.

        Args:
            timeout_seconds: Maximum session lifetime (default 1 hour)
            idle_timeout_seconds: Idle timeout before re-authentication required (default 30 min)
        """
        self.timeout_seconds = timeout_seconds
        self.idle_timeout_seconds = idle_timeout_seconds
        self.created_at = time.time()
        self.last_activity = time.time()
        self.is_expired = False

    def update_activity(self) -> None:
        """Update last activity timestamp."""
        self.last_activity = time.time()

    def check_expired(self) -> bool:
        """
        Check if session has expired (either by age or inactivity).

        Returns:
            True if session is expired
        """
        now = time.time()

        # Check absolute timeout
        if now - self.created_at > self.timeout_seconds:
            logger.warning(f"Session expired: Maximum lifetime exceeded ({self.timeout_seconds}s)")
            self.is_expired = True
            return True

        # Check idle timeout
        if now - self.last_activity > self.idle_timeout_seconds:
            logger.warning(f"Session expired: Idle timeout exceeded ({self.idle_timeout_seconds}s)")
            self.is_expired = True
            return True

        return False

    def get_time_remaining(self) -> int:
        """Get seconds until timeout."""
        now = time.time()
        remaining = self.timeout_seconds - (now - self.created_at)
        return max(0, int(remaining))

    def get_idle_time(self) -> int:
        """Get seconds of idle time."""
        now = time.time()
        idle = now - self.last_activity
        return int(idle)

    def reset(self) -> None:
        """Reset session timeout."""
        self.created_at = time.time()
        self.last_activity = time.time()
        self.is_expired = False
        logger.info("Session timeout reset")


class SessionMonitor:
    """Monitors session health and detects anomalies."""

    def __init__(self, validation_url: Optional[str] = None):
        """
        Initialize session monitor.

        Args:
            validation_url: URL to validate session against
        """
        self.validation_url = validation_url
        self.last_validation = None
        self.validation_history = []
        self.session_health_score = 100

    def validate_session(self, session: requests.Session) -> Tuple[bool, str]:
        """
        Validate session by making a test request.

        Args:
            session: requests.Session to validate

        Returns:
            Tuple of (is_valid: bool, reason: str)
        """
        if not self.validation_url:
            logger.debug("No validation URL provided - skipping session validation")
            return True, "No validation URL"

        try:
            resp = session.get(self.validation_url, timeout=10)
            self.last_validation = time.time()

            # Check status codes indicating valid session
            if resp.status_code == 200:
                self.session_health_score = min(100, self.session_health_score + 5)
                self.validation_history.append({
                    "timestamp": time.time(),
                    "status": "valid",
                    "code": resp.status_code
                })
                logger.debug(f"Session validation passed: {resp.status_code}")
                return True, f"Session valid (HTTP {resp.status_code})"

            # Check for authentication failure indicators
            elif resp.status_code in (401, 403):
                self.session_health_score = 0
                self.validation_history.append({
                    "timestamp": time.time(),
                    "status": "invalid",
                    "code": resp.status_code
                })
                logger.warning(f"Session validation failed: {resp.status_code} - Authentication required")
                return False, f"Session invalid (HTTP {resp.status_code})"

            # Check for redirect to login
            elif resp.status_code in (301, 302):
                if "login" in resp.headers.get("Location", "").lower():
                    self.session_health_score = 0
                    logger.warning(f"Session redirected to login")
                    return False, "Redirected to login page"

            # Unexpected status
            else:
                self.session_health_score = max(0, self.session_health_score - 10)
                logger.info(f"Unexpected validation response: {resp.status_code}")
                return True, f"Unexpected status (HTTP {resp.status_code})"

        except requests.exceptions.RequestException as e:
            self.session_health_score = max(0, self.session_health_score - 20)
            logger.warning(f"Session validation request failed: {e}")
            return False, f"Validation request failed: {e}"

    def detect_session_fixation(self, cookies_before: Dict, cookies_after: Dict) -> bool:
        """
        Detect potential session fixation vulnerability.

        Args:
            cookies_before: Cookies before action
            cookies_after: Cookies after action

        Returns:
            True if session ID remained unchanged (potential fixation)
        """
        session_indicators = ["session", "sid", "sessionid", "phpsessid", "auth", "token"]

        for key in session_indicators:
            # Find matching cookie
            before_val = None
            after_val = None

            for cookie_key, cookie_val in cookies_before.items():
                if key in cookie_key.lower():
                    before_val = cookie_val
                    break

            for cookie_key, cookie_val in cookies_after.items():
                if key in cookie_key.lower():
                    after_val = cookie_val
                    break

            # If session cookie exists and didn't change
            if before_val and after_val and before_val == after_val:
                logger.warning(f"Potential session fixation: {key} unchanged")
                return True

        return False

    def get_health_score(self) -> int:
        """Get session health score (0-100)."""
        return self.session_health_score

    def get_validation_history(self) -> list:
        """Get validation history."""
        return self.validation_history.copy()


class SessionRefresh:
    """Handles session cookie refresh and renewal."""

    def __init__(self, session: requests.Session, refresh_threshold: int = 300):
        """
        Initialize session refresh handler.

        Args:
            session: requests.Session to manage
            refresh_threshold: Seconds before expiry to refresh (default 5 min)
        """
        self.session = session
        self.refresh_threshold = refresh_threshold
        self.last_refresh = time.time()
        self.refresh_count = 0

    def refresh_cookies(self, refresh_url: str) -> Tuple[bool, str]:
        """
        Refresh session cookies by making request to refresh endpoint.

        Args:
            refresh_url: URL to refresh session

        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            logger.info(f"🔄 Refreshing session cookies: {refresh_url}")

            resp = self.session.post(refresh_url, timeout=10)

            if resp.status_code == 200:
                self.last_refresh = time.time()
                self.refresh_count += 1
                logger.info(f"✓ Session cookies refreshed (Count: {self.refresh_count})")
                return True, "Cookies refreshed"
            else:
                logger.warning(f"Cookie refresh failed: HTTP {resp.status_code}")
                return False, f"Refresh failed: HTTP {resp.status_code}"

        except Exception as e:
            logger.error(f"Cookie refresh error: {e}")
            return False, str(e)

    def should_refresh(self, timeout_handler: Optional[SessionTimeout] = None) -> bool:
        """
        Check if cookies should be refreshed.

        Args:
            timeout_handler: Optional SessionTimeout to check

        Returns:
            True if refresh is needed
        """
        # Check time since last refresh
        time_since_refresh = time.time() - self.last_refresh

        if timeout_handler:
            remaining = timeout_handler.get_time_remaining()
            if remaining < self.refresh_threshold:
                logger.debug(f"Refresh needed: {remaining}s remaining before timeout")
                return True

        # Refresh every hour by default
        if time_since_refresh > 3600:
            logger.debug(f"Refresh needed: {time_since_refresh}s since last refresh")
            return True

        return False

    def get_refresh_stats(self) -> Dict[str, Any]:
        """Get refresh statistics."""
        return {
            "refresh_count": self.refresh_count,
            "last_refresh": datetime.fromtimestamp(self.last_refresh).isoformat(),
            "time_since_last_refresh": int(time.time() - self.last_refresh)
        }


class SessionMaintenance:
    """
    Complete session maintenance system.
    Combines timeout handling, monitoring, and refresh mechanisms.
    """

    def __init__(self, session: requests.Session,
                 timeout_seconds: int = 3600,
                 idle_timeout_seconds: int = 1800,
                 validation_url: Optional[str] = None,
                 refresh_url: Optional[str] = None):
        """
        Initialize session maintenance.

        Args:
            session: requests.Session to maintain
            timeout_seconds: Maximum session lifetime
            idle_timeout_seconds: Idle timeout
            validation_url: URL to validate session
            refresh_url: URL to refresh session cookies
        """
        self.session = session
        self.timeout_handler = SessionTimeout(timeout_seconds, idle_timeout_seconds)
        self.monitor = SessionMonitor(validation_url)
        self.refresh = SessionRefresh(session)
        self.validation_url = validation_url
        self.refresh_url = refresh_url
        self.re_auth_callback: Optional[Callable] = None
        self.maintenance_history = []

    def set_reauth_callback(self, callback: Callable[[str], Tuple[bool, str]]) -> None:
        """
        Set callback for re-authentication.

        Args:
            callback: Function that takes error message and returns (success, message)
        """
        self.re_auth_callback = callback
        logger.info("Re-authentication callback registered")

    def check_session_health(self) -> Tuple[str, Dict[str, Any]]:
        """
        Comprehensive session health check.

        Returns:
            Tuple of (status: str, details: dict)
            status: 'healthy', 'warning', 'expired', 'invalid'
        """
        details = {
            "timestamp": datetime.now().isoformat(),
            "timeout_expired": self.timeout_handler.check_expired(),
            "time_remaining": self.timeout_handler.get_time_remaining(),
            "idle_time": self.timeout_handler.get_idle_time(),
            "health_score": self.monitor.get_health_score(),
            "refresh_stats": self.refresh.get_refresh_stats()
        }

        # Determine status
        if self.timeout_handler.is_expired:
            status = "expired"
            logger.warning("⚠️  Session expired")
        elif self.monitor.get_health_score() < 50:
            status = "invalid"
            logger.warning("⚠️  Session health degraded")
        elif details["time_remaining"] < 300:
            status = "warning"
            logger.warning(f"⚠️  Session expiring soon: {details['time_remaining']}s remaining")
        else:
            status = "healthy"
            logger.debug("✓ Session healthy")

        details["status"] = status
        self.maintenance_history.append(details)

        return status, details

    def maintain_session(self) -> Tuple[bool, str]:
        """
        Perform full session maintenance:
        1. Check for timeout
        2. Validate session
        3. Refresh if needed
        4. Re-authenticate if expired

        Returns:
            Tuple of (success: bool, message: str)
        """
        logger.info("🔧 Performing session maintenance...")

        # Update activity
        self.timeout_handler.update_activity()

        # Check health
        status, details = self.check_session_health()

        # Handle based on status
        if status == "expired":
            logger.warning("Session expired - attempting re-authentication")

            if self.re_auth_callback:
                success, message = self.re_auth_callback("Session expired")
                if success:
                    self.timeout_handler.reset()
                    logger.info("✓ Session re-authenticated successfully")
                    return True, "Re-authenticated"
                else:
                    logger.error(f"Re-authentication failed: {message}")
                    return False, f"Re-authentication failed: {message}"
            else:
                return False, "Session expired and no re-authentication callback"

        elif status == "invalid":
            logger.warning("Session marked invalid - validating...")

            is_valid, reason = self.monitor.validate_session(self.session)
            if is_valid:
                logger.info("✓ Session validation passed")
                return True, f"Session validated: {reason}"
            else:
                logger.error(f"Session validation failed: {reason}")

                if self.re_auth_callback:
                    success, message = self.re_auth_callback("Session validation failed")
                    if success:
                        self.timeout_handler.reset()
                        return True, "Re-authenticated"

                return False, f"Session invalid: {reason}"

        elif status == "warning":
            logger.info("Session approaching expiry - refreshing...")

            if self.refresh_url and self.refresh.should_refresh(self.timeout_handler):
                success, message = self.refresh.refresh_cookies(self.refresh_url)
                if success:
                    self.timeout_handler.reset()
                    return True, message

            return True, "Session warning but still valid"

        else:  # healthy
            # Optional periodic validation
            if details["idle_time"] > 600:  # Every 10 minutes if idle
                is_valid, reason = self.monitor.validate_session(self.session)
                if is_valid:
                    logger.debug(f"✓ Periodic validation passed: {reason}")
                    return True, reason
                else:
                    logger.warning(f"Periodic validation failed: {reason}")

                    if self.re_auth_callback:
                        success, message = self.re_auth_callback("Periodic validation failed")
                        if success:
                            self.timeout_handler.reset()
                            return True, "Re-authenticated"

                    return False, reason

            return True, "Session healthy"

    def get_status_report(self) -> Dict[str, Any]:
        """Get comprehensive session status report."""
        status, details = self.check_session_health()

        return {
            "current_status": status,
            "details": details,
            "timeout_handler": {
                "created_at": datetime.fromtimestamp(self.timeout_handler.created_at).isoformat(),
                "last_activity": datetime.fromtimestamp(self.timeout_handler.last_activity).isoformat(),
                "time_remaining": self.timeout_handler.get_time_remaining(),
                "idle_time": self.timeout_handler.get_idle_time()
            },
            "monitor": {
                "health_score": self.monitor.get_health_score(),
                "last_validation": datetime.fromtimestamp(
                    self.monitor.last_validation).isoformat() if self.monitor.last_validation else None,
                "validation_history_count": len(self.monitor.validation_history)
            },
            "refresh": self.refresh.get_refresh_stats(),
            "maintenance_history_count": len(self.maintenance_history)
        }
