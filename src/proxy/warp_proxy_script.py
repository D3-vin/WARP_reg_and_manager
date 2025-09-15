#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mitmproxy script for intercepting and modifying Warp API requests
"""

import json
import sqlite3
import time
import urllib3
import re
import random
import string
from mitmproxy import http
from mitmproxy.script import concurrent

# Try to import languages module - use fallback if not available
try:
    from src.config.languages import get_language_manager, _
except ImportError:
    try:
        # Fallback for when running from project root
        import sys
        import os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
        from src.config.languages import get_language_manager, _
    except ImportError:
        # Final fallback if languages module is not available
        def get_language_manager():
            return None
        def _(key):
            return key

# Hide SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# SSL verification bypass - complete SSL verification disable
import ssl
try:
    ssl._create_default_https_context = ssl._create_unverified_context
except AttributeError:
    # Older Python versions
    pass


def randomize_uuid_string(uuid_str):
    """
    Randomly modify UUID string - letters replaced with hex symbols, digits with random numbers
    Hyphen (-) characters are preserved, upper/lower case format is preserved

    Args:
        uuid_str (str): UUID format string (e.g.: 4d22323e-1ce9-44c1-a922-112a718ea3fc)

    Returns:
        str: Randomly modified UUID string
    """
    if not uuid_str or len(uuid_str) == 0:
        # If empty, generate new UUID
        return generate_experiment_id()
        
    hex_digits_lower = '0123456789abcdef'
    hex_digits_upper = '0123456789ABCDEF'

    result = []
    for char in uuid_str:
        if char == '-':
            # Preserve hyphen character
            result.append(char)
        elif char.isdigit():
            # Replace digit with random hex character (digit or a-f)
            result.append(random.choice(hex_digits_lower))
        elif char in 'abcdef':
            # Replace lowercase hex letter with random lowercase hex letter
            result.append(random.choice(hex_digits_lower))
        elif char in 'ABCDEF':
            # Replace uppercase hex letter with random uppercase hex letter
            result.append(random.choice(hex_digits_upper))
        else:
            # Leave other characters as is (for safety)
            result.append(char)

    return ''.join(result)


def generate_experiment_id():
    """Generate UUID in Warp Experiment ID format - different each time"""
    # In format 931df166-756c-4d4c-b486-4231224bc531
    # Structure 8-4-4-4-12 hex characters
    def hex_chunk(length):
        return ''.join(random.choice('0123456789abcdef') for _ in range(length))

    return f"{hex_chunk(8)}-{hex_chunk(4)}-{hex_chunk(4)}-{hex_chunk(4)}-{hex_chunk(12)}"

class WarpProxyHandler:
    def __init__(self):
        self.db_path = "accounts.db"
        self.active_token = None
        self.active_email = None
        self.token_expiry = None
        self.last_trigger_check = 0
        self.last_token_check = 0
        self.user_settings_cache = None

    def get_active_account(self):
        """Get active account from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # First get active account
            cursor.execute('SELECT value FROM proxy_settings WHERE key = ?', ('active_account',))
            active_result = cursor.fetchone()

            if active_result:
                active_email = active_result[0]
                # Then get account data
                cursor.execute('SELECT account_data FROM accounts WHERE email = ?', (active_email,))
                account_result = cursor.fetchone()

                if account_result:
                    account_data = json.loads(account_result[0])
                    conn.close()
                    return active_email, account_data

            conn.close()
            return None, None
        except Exception as e:
            print(f"Error getting active account: {e}")
            return None, None

    def update_active_token(self):
        """Update active account token information"""
        try:
            print("🔍 Checking active account...")
            email, account_data = self.get_active_account()
            if not account_data:
                print("❌ No active account found")
                self.active_token = None
                self.active_email = None
                return False

            old_email = self.active_email
            print(f"📧 Found active account: {email}")

            current_time = int(time.time() * 1000)
            token_expiry = account_data['stsTokenManager']['expirationTime']
            # Convert to int if it's a string
            if isinstance(token_expiry, str):
                token_expiry = int(token_expiry)

            print(f"🕑 Token expiry: {token_expiry}, Current: {current_time}")
            print(f"🕑 Time until expiry: {(token_expiry - current_time) // 1000} seconds")

            # If less than 1 minute left until token expires, refresh
            if current_time >= (token_expiry - 60000):  # 1 minute = 60000ms
                print(f"🔄 Token expiring soon, refreshing: {email}")
                if self.refresh_token(email, account_data):
                    # Get updated data
                    email, account_data = self.get_active_account()
                    if account_data:
                        self.active_token = account_data['stsTokenManager']['accessToken']
                        self.token_expiry = account_data['stsTokenManager']['expirationTime']
                        self.active_email = email
                        print(f"✅ Token refreshed: {email}")
                        return True
                else:
                    print(f"❌ Failed to refresh token for: {email}")
                return False
            else:
                self.active_token = account_data['stsTokenManager']['accessToken']
                self.token_expiry = token_expiry
                self.active_email = email

                if old_email != email:
                    print(f"🔄 Active account changed: {old_email} → {email}")
                else:
                    print(f"✅ Token active: {email}")
                    
                print(f"🔑 Token loaded: {self.active_token[:30] if self.active_token else 'None'}...")
                return True
        except Exception as e:
            print(f"❌ Token update error: {e}")
            import traceback
            traceback.print_exc()
            return False

    def check_account_change_trigger(self):
        """Check account change trigger file"""
        try:
            trigger_file = "account_change_trigger.tmp"
            import os

            if os.path.exists(trigger_file):
                # Check file modification time
                mtime = os.path.getmtime(trigger_file)
                if mtime > self.last_trigger_check:
                    print("🔄 Account change trigger detected!")
                    self.last_trigger_check = mtime

                    # Delete trigger file
                    try:
                        os.remove(trigger_file)
                        print("🗑️  Trigger file deleted")
                    except Exception as e:
                        print(f"Error deleting trigger file: {e}")

                    # Update token
                    print("🔄 Updating token...")
                    self.update_active_token()
                    return True
            return False
        except Exception as e:
            print(f"Trigger check error: {e}")
            return False

    def refresh_token(self, email, account_data):
        """Refresh Firebase token"""
        try:
            import requests

            refresh_token = account_data['stsTokenManager']['refreshToken']
            api_key = account_data['apiKey']

            url = f"https://securetoken.googleapis.com/v1/token?key={api_key}"
            data = {
                'grant_type': 'refresh_token',
                'refresh_token': refresh_token
            }

            # Direct connection - completely bypass proxy and SSL verification
            response = requests.post(url, json=data, timeout=30, verify=False)

            if response.status_code == 200:
                token_data = response.json()
                new_token_data = {
                    'accessToken': token_data['access_token'],
                    'refreshToken': token_data['refresh_token'],
                    'expirationTime': int(time.time() * 1000) + (int(token_data['expires_in']) * 1000)
                }

                # Update database
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute('SELECT account_data FROM accounts WHERE email = ?', (email,))
                result = cursor.fetchone()

                if result:
                    account_data = json.loads(result[0])
                    account_data['stsTokenManager'].update(new_token_data)

                    cursor.execute('''
                        UPDATE accounts SET account_data = ?, last_updated = CURRENT_TIMESTAMP
                        WHERE email = ?
                    ''', (json.dumps(account_data), email))
                    conn.commit()

                conn.close()
                return True
            return False
        except Exception as e:
            print(f"Token refresh error: {e}")
            return False

    def mark_account_as_banned(self, email):
        """Mark account as banned"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Update account health_status as 'banned'
            cursor.execute('''
                UPDATE accounts SET health_status = 'banned', last_updated = CURRENT_TIMESTAMP
                WHERE email = ?
            ''', (email,))
            conn.commit()
            conn.close()

            print(f"Account marked as banned: {email}")

            # Clear active account (banned account cannot be active)
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM proxy_settings WHERE key = ?', ('active_account',))
            conn.commit()
            conn.close()

            # Clear active account information in Handler
            self.active_token = None
            self.active_email = None
            self.token_expiry = None

            print("Banned account removed from active accounts list")

            # Send ban notification to GUI
            self.notify_gui_about_ban(email)
            return True

        except Exception as e:
            print(f"Error marking account as banned: {e}")
            return False

    def notify_gui_about_ban(self, email):
        """Send ban notification to GUI via file"""
        try:
            import os
            import time

            # Create ban notification file
            ban_notification_file = "ban_notification.tmp"
            with open(ban_notification_file, 'w', encoding='utf-8') as f:
                f.write(f"{email}|{int(time.time())}")

            print(f"Ban notification file created: {ban_notification_file}")
        except Exception as e:
            print(f"Error sending ban notification: {e}")

    def load_user_settings(self):
        """Load user_settings.json file"""
        try:
            import os
            if os.path.exists("user_settings.json"):
                with open("user_settings.json", 'r', encoding='utf-8') as f:
                    self.user_settings_cache = json.load(f)
                print("✅ user_settings.json file loaded successfully")
                return True
            else:
                print("⚠️ user_settings.json file not found")
                self.user_settings_cache = None
                return False
        except Exception as e:
            print(f"Error loading user_settings.json: {e}")
            self.user_settings_cache = None
            return False

    def refresh_user_settings(self):
        """Reload user_settings.json file"""
        print("🔄 Reloading user_settings.json...")
        return self.load_user_settings()

# Глобальные переменные для отладки
DEBUG_LOG_FILE = "proxy_debug.log"
DEBUG_ALL_REQUESTS = True  # Включить логирование всех запросов
REQUEST_COUNTER = 0
LAST_WARP_REQUEST_TIME = 0

# Global handler instance
handler = WarpProxyHandler()

def debug_log_all_requests(flow: http.HTTPFlow):
    """Логирование всех запросов для отладки"""
    global REQUEST_COUNTER, LAST_WARP_REQUEST_TIME
    
    if not DEBUG_ALL_REQUESTS:
        return
        
    REQUEST_COUNTER += 1
    current_time = time.time()
    
    # Определяем тип запроса
    is_warp_related = any(domain in flow.request.pretty_host for domain in [
        "app.warp.dev", "warp.dev", "dataplane.rudderstack.com", 
        "identitytoolkit.googleapis.com", "securetoken.googleapis.com"
    ])
    
    if is_warp_related:
        LAST_WARP_REQUEST_TIME = current_time
    
    # Форматируем отладочную информацию
    debug_info = {
        "counter": REQUEST_COUNTER,
        "timestamp": time.strftime("%H:%M:%S", time.localtime(current_time)),
        "method": flow.request.method,
        "host": flow.request.pretty_host,
        "path": flow.request.path,
        "url": flow.request.pretty_url,
        "is_warp_related": is_warp_related,
        "headers": dict(flow.request.headers),
        "user_agent": flow.request.headers.get("User-Agent", "None"),
        "authorization": flow.request.headers.get("Authorization", "None")[:50] + "..." if flow.request.headers.get("Authorization") else "None"
    }
    
    # Выводим краткую информацию в консоль
    if is_warp_related:
        print(f"\n🔍 DEBUG #{REQUEST_COUNTER} - WARP REQUEST DETECTED!")
        print(f"   🕐 Time: {debug_info['timestamp']}")
        print(f"   🌐 {debug_info['method']} {debug_info['host']}{debug_info['path']}")
        print(f"   🔑 Auth: {debug_info['authorization']}")
        print(f"   🤖 UA: {debug_info['user_agent'][:100]}")
    else:
        # Логируем только счетчик для обычных запросов
        if REQUEST_COUNTER % 10 == 0:  # Каждый 10-й запрос
            print(f"📊 DEBUG: Processed {REQUEST_COUNTER} requests, last Warp request: {int(current_time - LAST_WARP_REQUEST_TIME)}s ago")
    
    # Записываем полную информацию в файл
    try:
        with open(DEBUG_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"{json.dumps(debug_info, ensure_ascii=False)}\n")
    except Exception as e:
        print(f"⚠️ Debug log write error: {e}")

def debug_get_statistics():
    """Получить статистику отладки"""
    global REQUEST_COUNTER, LAST_WARP_REQUEST_TIME
    current_time = time.time()
    
    stats = {
        "total_requests": REQUEST_COUNTER,
        "last_warp_request_ago": int(current_time - LAST_WARP_REQUEST_TIME) if LAST_WARP_REQUEST_TIME > 0 else "Never",
        "proxy_running_since": time.strftime("%H:%M:%S", time.localtime(current_time - (current_time % 3600))),
        "debug_log_file": DEBUG_LOG_FILE
    }
    
    return stats

def is_relevant_request(flow: http.HTTPFlow) -> bool:
    """Check if this request is relevant to us"""

    # Check Firebase token refresh requests by User-Agent and exclude them
    if ("securetoken.googleapis.com" in flow.request.pretty_host and
        flow.request.headers.get("User-Agent") == "WarpAccountManager/1.0"):
        return False

    # Check and exclude requests from WarpAccountManager
    if flow.request.headers.get("x-warp-manager-request") == "true":
        return False

    # Process only specific domains
    relevant_domains = [
        "app.warp.dev",
        "dataplane.rudderstack.com"  # For blocking
    ]

    # Silently pass requests not related to Warp (don't block internet access)
    if not any(domain in flow.request.pretty_host for domain in relevant_domains):
        return False

    return True

def request(flow: http.HTTPFlow) -> None:
    """Executed when request is intercepted"""
    
    # РАСШИРЕННАЯ ОТЛАДКА - логируем ВСЕ запросы для диагностики
    debug_log_all_requests(flow)
    
    # КРИТИЧЕСКИ ВАЖНО: Проверяем ВСЕ запросы к Warp доменам
    is_warp_request = any(domain in flow.request.pretty_host for domain in [
        "app.warp.dev", "warp.dev", "securetoken.googleapis.com", "identitytoolkit.googleapis.com"
    ])
    
    if is_warp_request:
        print(f"\n🎯 WARP REQUEST INTERCEPTED: {flow.request.method} {flow.request.pretty_url}")
        print(f"   🌐 Host: {flow.request.pretty_host}")
        print(f"   📍 Path: {flow.request.path}")
        print(f"   🔑 Current Auth: {flow.request.headers.get('Authorization', 'None')[:50]}...")
    
    # Immediately filter unimportant requests - pass silently (don't interfere with internet access)
    if not is_relevant_request(flow):
        # Directly pass all traffic not related to Warp
        return

    request_url = flow.request.pretty_url

    # Block requests to *.dataplane.rudderstack.com
    if "dataplane.rudderstack.com" in flow.request.pretty_host:
        print(f"🚫 Blocked Rudderstack request: {request_url}")
        flow.response = http.Response.make(
            204,  # No Content
            b"",
            {"Content-Type": "text/plain"}
        )
        return

    print(f"🌐 Processing Warp Request: {flow.request.method} {flow.request.pretty_url}")

    # Detect CreateGenericStringObject request - trigger user_settings.json update
    if ("/graphql/v2?op=CreateGenericStringObject" in request_url and
        flow.request.method == "POST"):
        print("🔄 CreateGenericStringObject request detected - updating user_settings.json...")
        handler.refresh_user_settings()

    # Check account change trigger (on every request)
    if handler.check_account_change_trigger():
        print("🔄 Trigger detected and token updated!")

    # ОБЯЗАТЕЛЬНО проверяем активный аккаунт при каждом запросе
    current_time = time.time()
    if current_time - handler.last_token_check > 30:  # Проверяем каждые 30 секунд (было 60)
        print("⏰ Regular token check...")
        handler.update_active_token()
        handler.last_token_check = current_time

    # Check active account
    if not handler.active_email:
        print("❌ No active account found, updating...")
        handler.update_active_token()

    # Show active account information
    print(f"📧 Current active account: {handler.active_email}")
    print(f"🔑 Token available: {handler.active_token is not None}")

    # Modify Authorization header - КРИТИЧЕСКИ ВАЖНО!
    if handler.active_token:
        old_auth = flow.request.headers.get("Authorization", "None")
        new_auth = f"Bearer {handler.active_token}"
        
        # ВСЕГДА заменяем заголовок авторизации
        flow.request.headers["Authorization"] = new_auth

        print(f"🔑 Authorization header MODIFIED for: {handler.active_email}")
        print(f"   📝 Old: {old_auth[:50]}...")
        print(f"   📝 New: {new_auth[:50]}...")

        # Check if tokens are actually different
        if old_auth == new_auth:
            print("   ⚠️  WARNING: Old and new tokens are IDENTICAL!")
        else:
            print("   ✅ Token successfully REPLACED")

        # Also show token ending
        if len(handler.active_token) > 100:
            print(f"   🎯 Token ending: ...{handler.active_token[-20:]}")

    else:
        print("❌ CRITICAL: ACTIVE TOKEN NOT FOUND - HEADER NOT MODIFIED!")
        print(f"   📧 Active email: {handler.active_email}")
        print(f"   🔑 Token status: {handler.active_token is not None}")
        print("   💡 Make sure to activate an account in the UI!")

    # For all app.warp.dev requests check and randomize x-warp-experiment-id header
    if "app.warp.dev" in flow.request.pretty_host:
        # Always generate new experiment ID and add/modify header
        new_experiment_id = generate_experiment_id()
        old_experiment_id = flow.request.headers.get("x-warp-experiment-id", "None")
        flow.request.headers["x-warp-experiment-id"] = new_experiment_id
        
        print(f"🧪 Experiment ID changed ({flow.request.path}):")
        print(f"   📝 Old: {old_experiment_id}")
        print(f"   📝 New: {new_experiment_id}")
        
    print(f"✅ Request processing completed for: {flow.request.pretty_url}")

def responseheaders(flow: http.HTTPFlow) -> None:
    """Executed when response headers are received - controls streaming"""
    # Immediately filter unimportant requests - pass silently
    if not is_relevant_request(flow):
        return

    # Enable streaming for /ai/multi-agent endpoint
    if "/ai/multi-agent" in flow.request.path:
        flow.response.stream = True
        print(f"[{time.strftime('%H:%M:%S')}] Streaming enabled: {flow.request.pretty_url}")
    else:
        flow.response.stream = False

def response(flow: http.HTTPFlow) -> None:
    """Executed when response is received"""

    # Check Firebase token refresh requests by User-Agent and exclude them
    if ("securetoken.googleapis.com" in flow.request.pretty_host and
        flow.request.headers.get("User-Agent") == "WarpAccountManager/1.0"):
        return

    # Process only specific domains
    if "app.warp.dev" not in flow.request.pretty_host:
        return

    # Immediately filter unimportant requests - pass silently (don't interfere with internet access)
    if not is_relevant_request(flow):
        return

    # Exclude requests from WarpAccountManager
    if flow.request.headers.get("x-warp-manager-request") == "true":
        return

    print(f"📡 Warp Response: {flow.response.status_code} - {flow.request.pretty_url}")

    # Use cached response for GetUpdatedCloudObjects request
    if ("/graphql/v2?op=GetUpdatedCloudObjects" in flow.request.pretty_url and
        flow.request.method == "POST" and
        flow.response.status_code == 200 and
        handler.user_settings_cache is not None):
        print("🔄 GetUpdatedCloudObjects response being replaced with cached data...")
        try:
            # Convert cached data to JSON string
            cached_response = json.dumps(handler.user_settings_cache, ensure_ascii=False)

            # Modify Response
            flow.response.content = cached_response.encode('utf-8')
            flow.response.headers["Content-Length"] = str(len(flow.response.content))
            flow.response.headers["Content-Type"] = "application/json"

            print("✅ GetUpdatedCloudObjects response successfully modified")
        except Exception as e:
            print(f"❌ Error modifying response: {e}")

    # 403 error in /ai/multi-agent endpoint - immediate account ban
    if "/ai/multi-agent" in flow.request.path and flow.response.status_code == 403:
        print("⛔ 403 FORBIDDEN - Account ban detected!")
        if handler.active_email:
            print(f"Banned account: {handler.active_email}")
            handler.mark_account_as_banned(handler.active_email)
        else:
            print("Active account not found, ban not marked")

    # If 401 error received, try to refresh token
    if flow.response.status_code == 401:
        print("401 error received, refreshing token...")
        if handler.update_active_token():
            print("Token refreshed, retry request")

# Load active account on startup
def load(loader):
    """Executed when script starts"""
    print("\n" + "="*60)
    print("🚀 WARP PROXY SCRIPT STARTED - ENHANCED DEBUG MODE")
    print("="*60)
    
    # Инициализация отладочного файла
    try:
        with open(DEBUG_LOG_FILE, "w", encoding="utf-8") as f:
            f.write(f"# Proxy Debug Log Started at {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        print(f"📝 Debug log initialized: {DEBUG_LOG_FILE}")
    except Exception as e:
        print(f"⚠️ Failed to initialize debug log: {e}")
    
    print("\n🔍 DIAGNOSTIC INFORMATION:")
    print("-" * 40)
    
    # Проверка системы
    import sys
    import os
    print(f"🐍 Python: {sys.version[:20]}...")
    print(f"💻 Platform: {sys.platform}")
    print(f"📂 Working directory: {os.getcwd()}")
    print(f"🌐 Debug mode: {DEBUG_ALL_REQUESTS}")
    
    print("\n📧 ACCOUNT STATUS:")
    print("-" * 20)
    print("Checking database connection...")
    handler.update_active_token()
    if handler.active_email:
        print(f"✅ Active account loaded: {handler.active_email}")
        print(f"🔑 Token exists: {handler.active_token is not None}")
        if handler.active_token:
            print(f"🎯 Token preview: {handler.active_token[:30]}...")
    else:
        print("❌ No active account found - Don't forget to activate an account!")

    # Load user_settings.json file
    print("\n⚙️ USER SETTINGS:")
    print("-" * 17)
    print("Loading user_settings.json file...")
    handler.load_user_settings()
    
    print("\n🎯 PROXY INTERCEPTION TARGETS:")
    print("-" * 32)
    print("✅ app.warp.dev (main target)")
    print("🚫 dataplane.rudderstack.com (blocked)")
    print("🔧 identitytoolkit.googleapis.com (auth)")
    print("🔄 securetoken.googleapis.com (token refresh)")
    
    print("\n⚡ READY FOR INTERCEPTION!")
    print("="*60)
    print("Waiting for requests... (use Ctrl+C to stop)\n")

def done():
    """Executed when script stops"""
    print("\n" + "="*60)
    print("🛑 WARP PROXY SCRIPT STOPPING")
    print("="*60)
    
    # Показываем финальную статистику
    stats = debug_get_statistics()
    print(f"📊 FINAL STATISTICS:")
    print(f"   Total requests processed: {stats['total_requests']}")
    print(f"   Last Warp request: {stats['last_warp_request_ago']} seconds ago")
    print(f"   Debug log saved to: {stats['debug_log_file']}")
    
    # Записываем финальную статистику в лог
    try:
        with open(DEBUG_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"\n# Script stopped at {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Final statistics: {json.dumps(stats, ensure_ascii=False)}\n")
    except Exception as e:
        print(f"⚠️ Failed to write final stats: {e}")
    
    print("\n👋 Proxy script stopped successfully")
    print("="*60)
