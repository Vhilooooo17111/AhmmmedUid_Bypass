import requests
from datetime import datetime

# API Configuration
API_URL = "https://bypass.hottrends.site/api.php"

class APIClient:
    def __init__(self):
        """Initialize API Client"""
        self.url = API_URL
        self._whitelist_cache = None
        self._cache_timestamp = 0
        self.CACHE_TIMEOUT = 30  # seconds

    def _load_whitelist(self):
        """Load full whitelist with caching"""
        current_time = datetime.now().timestamp()
        if self._whitelist_cache is not None and (current_time - self._cache_timestamp) < self.CACHE_TIMEOUT:
            return self._whitelist_cache

        try:
            api_url = f"{self.url}?action=get"
            response = requests.get(api_url, timeout=10, headers={"Accept": "application/json"})
            if response.status_code == 200:
                whitelist = response.json()
                if isinstance(whitelist, list):
                    self._whitelist_cache = whitelist
                    self._cache_timestamp = current_time
                    print(f"[API] Loaded {len(whitelist)} UIDs from remote API")
                    return whitelist
            return self._whitelist_cache or []
        except Exception as e:
            print(f"[API] Error loading whitelist: {e}")
            return self._whitelist_cache or []

    def check_maintenance_mode(self):
        """Check if server is in maintenance mode"""
        try:
            api_url = f"{self.url}?action=check_maintenance"
            response = requests.get(api_url, timeout=5, headers={"Accept": "application/json"})
            if response.status_code == 200:
                data = response.json()
                # {"enabled": true, "reason": "..."}
                return data.get("enabled", False), data.get("reason", "Server under maintenance")
            return False, ""
        except Exception:
            return False, ""

    def check_subscription(self, uid: str) -> dict:
        """Check subscription validity using the cached whitelist"""
        uid = str(uid).strip()
        if not uid or uid.lower() == "unknown":
            return {"valid": False, "reason": "invalid_uid", "expiry_date": "N/A"}

        # 1. Check Maintenance first
        is_maint, maint_reason = self.check_maintenance_mode()
        if is_maint:
            return {"valid": False, "reason": "maintenance", "expiry_date": "N/A", "message": maint_reason}

        # 2. Check Whitelist
        whitelist = self._load_whitelist()
        current_date = datetime.now().strftime("%Y-%m-%d")

        for entry in whitelist:
            if str(entry.get("uid")) == uid:
                expire_date = entry.get("expire_date", "") or entry.get("expiry", "")
                
                if expire_date and expire_date < current_date:
                    return {"valid": False, "reason": "expired", "expiry_date": expire_date}
                else:
                    return {"valid": True, "reason": "active", "expiry_date": expire_date or "Infinite"}

        return {"valid": False, "reason": "not_authorized", "expiry_date": "N/A"}
