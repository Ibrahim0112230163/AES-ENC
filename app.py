import hashlib
import hmac
import base64
import time
from flask import Flask, render_template_string, request
from Crypto.Cipher import AES

app = Flask(__name__)

# Simulation "Secret Keys"
AES_KEY = b'this_is_16_bytes'     # Used for Encryption
HMAC_KEY = b'bank_private_key'    # Used for Digital Signature
DEFAULT_PASS = "123456"

def build_secure_packet(amount, password):
    # 1. Password Verification
    if password != DEFAULT_PASS:
        return {"error": "Invalid Password!"}

    # 2. Generate Timestamp
    current_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())

    # 3. Create HMAC (Private Key Signature of the amount)
    # This ensures the 'amount' cannot be changed by a hacker.
    hmac_obj = hmac.new(HMAC_KEY, amount.encode(), hashlib.sha256)
    signature = hmac_obj.hexdigest()

    # 4. Construct the Payload (Amount | Timestamp | Signature)
    # We use '|' as a delimiter so we can split it easily later
    full_payload = f"{amount}|{current_time}|{signature}"

    # 5. AES Encryption (Final Layer)
    cipher = AES.new(AES_KEY, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(full_payload.encode())

    # This represents the "Encrypted Packet" sent to the bank server
    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(tag).decode(),
        "packet_preview": base64.b64encode(ciphertext[:16]).decode() + "...", # Preview
        "timestamp": current_time
    }

def decrypt_and_verify(nonce_b64, ciphertext_b64, tag_b64):
    try:
        # 1. AES Decrypt
        cipher = AES.new(AES_KEY, AES.MODE_EAX, nonce=base64.b64decode(nonce_b64))
        raw_data = cipher.decrypt_and_verify(
            base64.b64decode(ciphertext_b64), 
            base64.b64decode(tag_b64)
        ).decode()

        # 2. Parse the Packet
        amount, timestamp, received_hmac = raw_data.split('|')

        # 3. Verify HMAC (Check if amount was tampered)
        expected_hmac = hmac.new(HMAC_KEY, amount.encode(), hashlib.sha256).hexdigest()
        
        # Return both hashes for comparison
        is_valid = hmac.compare_digest(expected_hmac, received_hmac)
        
        return {
            "status": "SUCCESS" if is_valid else "TAMPERED",
            "amount": amount,
            "time": timestamp,
            "received_hash": received_hmac,
            "computed_hash": expected_hmac,
            "hash_match": is_valid
        }

    except Exception as e:
        return {"status": "ERROR", "msg": str(e)}

# --- UI Template ---
HTML_UI = """
<!DOCTYPE html>
<html>
<head>
    <title>ToCashless - Transaction Portal</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
        body { font-family: 'Inter', sans-serif; }
        .bank-gradient { background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%); }
        .hash-box { font-family: 'Courier New', monospace; word-break: break-all; }
    </style>
</head>
<body class="bg-gray-50">
    <!-- Bank Header -->
    <div class="bank-gradient text-white py-4 shadow-lg">
        <div class="max-w-4xl mx-auto px-6 flex items-center justify-between">
            <div class="flex items-center space-x-3">
                <i class="fas fa-shield-alt text-3xl"></i>
                <div>
                    <h1 class="text-2xl font-bold">ToCashless</h1>
                    <p class="text-xs text-blue-100">Encrypted Transaction System</p>
                </div>
            </div>
            <div class="text-right text-sm">
                <p class="font-semibold">Group A4</p>
                <p class="text-blue-100">AES-256 Encrypted</p>
            </div>
        </div>
    </div>

    <div class="max-w-4xl mx-auto px-6 py-8">
        <!-- AES Encryption/Decryption Process Diagram -->
        <div class="bg-white rounded-xl shadow-lg overflow-hidden mb-6">
            <div class="bg-gradient-to-r from-indigo-600 to-indigo-700 px-6 py-4">
                <h2 class="text-xl font-bold text-white flex items-center">
                    <i class="fas fa-project-diagram mr-3"></i>AES Encryption & Decryption Flow
                </h2>
            </div>
            <div class="p-6">
                <!-- Encryption Process -->
                <div class="mb-8">
                    <h3 class="text-lg font-bold text-gray-800 mb-4 flex items-center">
                        <i class="fas fa-lock text-green-600 mr-2"></i>Encryption Process (Client Side)
                    </h3>
                    <div class="flex items-center justify-between space-x-2">
                        <!-- Step 1 -->
                        <div class="flex-1 bg-blue-50 border-2 border-blue-300 rounded-lg p-4 text-center">
                            <div class="text-3xl mb-2">🔐</div>
                            <div class="font-bold text-sm text-blue-900">Password Check</div>
                            <div class="text-xs text-gray-600 mt-1">Verify: 123456</div>
                        </div>
                        <div class="text-2xl text-gray-400">→</div>
                        
                        <!-- Step 2 -->
                        <div class="flex-1 bg-purple-50 border-2 border-purple-300 rounded-lg p-4 text-center">
                            <div class="text-3xl mb-2">🔏</div>
                            <div class="font-bold text-sm text-purple-900">HMAC Sign</div>
                            <div class="text-xs text-gray-600 mt-1">SHA-256 Hash</div>
                        </div>
                        <div class="text-2xl text-gray-400">→</div>
                        
                        <!-- Step 3 -->
                        <div class="flex-1 bg-yellow-50 border-2 border-yellow-300 rounded-lg p-4 text-center">
                            <div class="text-3xl mb-2">📦</div>
                            <div class="font-bold text-sm text-yellow-900">Build Packet</div>
                            <div class="text-xs text-gray-600 mt-1">Amount|Time|Hash</div>
                        </div>
                        <div class="text-2xl text-gray-400">→</div>
                        
                        <!-- Step 4 -->
                        <div class="flex-1 bg-green-50 border-2 border-green-300 rounded-lg p-4 text-center">
                            <div class="text-3xl mb-2">🔒</div>
                            <div class="font-bold text-sm text-green-900">AES Encrypt</div>
                            <div class="text-xs text-gray-600 mt-1">EAX Mode</div>
                        </div>
                        <div class="text-2xl text-gray-400">→</div>
                        
                        <!-- Step 5 -->
                        <div class="flex-1 bg-gray-800 border-2 border-gray-700 rounded-lg p-4 text-center">
                            <div class="text-3xl mb-2">📡</div>
                            <div class="font-bold text-sm text-white">Send</div>
                            <div class="text-xs text-gray-300 mt-1">Ciphertext</div>
                        </div>
                    </div>
                </div>

                <!-- Decryption Process -->
                <div>
                    <h3 class="text-lg font-bold text-gray-800 mb-4 flex items-center">
                        <i class="fas fa-unlock text-red-600 mr-2"></i>Decryption Process (Bank Server)
                    </h3>
                    <div class="flex items-center justify-between space-x-2">
                        <!-- Step 1 -->
                        <div class="flex-1 bg-gray-800 border-2 border-gray-700 rounded-lg p-4 text-center">
                            <div class="text-3xl mb-2">📥</div>
                            <div class="font-bold text-sm text-white">Receive</div>
                            <div class="text-xs text-gray-300 mt-1">Ciphertext</div>
                        </div>
                        <div class="text-2xl text-gray-400">→</div>
                        
                        <!-- Step 2 -->
                        <div class="flex-1 bg-red-50 border-2 border-red-300 rounded-lg p-4 text-center">
                            <div class="text-3xl mb-2">🔓</div>
                            <div class="font-bold text-sm text-red-900">AES Decrypt</div>
                            <div class="text-xs text-gray-600 mt-1">Extract Payload</div>
                        </div>
                        <div class="text-2xl text-gray-400">→</div>
                        
                        <!-- Step 3 -->
                        <div class="flex-1 bg-orange-50 border-2 border-orange-300 rounded-lg p-4 text-center">
                            <div class="text-3xl mb-2">📋</div>
                            <div class="font-bold text-sm text-orange-900">Parse Data</div>
                            <div class="text-xs text-gray-600 mt-1">Split Packet</div>
                        </div>
                        <div class="text-2xl text-gray-400">→</div>
                        
                        <!-- Step 4 -->
                        <div class="flex-1 bg-indigo-50 border-2 border-indigo-300 rounded-lg p-4 text-center">
                            <div class="text-3xl mb-2">🔍</div>
                            <div class="font-bold text-sm text-indigo-900">Compute Hash</div>
                            <div class="text-xs text-gray-600 mt-1">SHA-256</div>
                        </div>
                        <div class="text-2xl text-gray-400">→</div>
                        
                        <!-- Step 5 -->
                        <div class="flex-1 bg-teal-50 border-2 border-teal-300 rounded-lg p-4 text-center">
                            <div class="text-3xl mb-2">✅</div>
                            <div class="font-bold text-sm text-teal-900">Verify</div>
                            <div class="text-xs text-gray-600 mt-1">Compare Hash</div>
                        </div>
                    </div>
                </div>

                <!-- Security Layers Info -->
                <div class="mt-6 bg-gradient-to-r from-blue-50 to-purple-50 rounded-lg p-4 border-2 border-blue-200">
                    <h4 class="font-bold text-gray-800 mb-3 flex items-center">
                        <i class="fas fa-layer-group text-blue-600 mr-2"></i>
                        Security Layers Applied
                    </h4>
                    <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
                        <div class="flex items-center text-sm">
                            <i class="fas fa-check-circle text-green-600 mr-2"></i>
                            <span class="text-gray-700">Password Auth</span>
                        </div>
                        <div class="flex items-center text-sm">
                            <i class="fas fa-check-circle text-green-600 mr-2"></i>
                            <span class="text-gray-700">HMAC-SHA256</span>
                        </div>
                        <div class="flex items-center text-sm">
                            <i class="fas fa-check-circle text-green-600 mr-2"></i>
                            <span class="text-gray-700">Timestamp</span>
                        </div>
                        <div class="flex items-center text-sm">
                            <i class="fas fa-check-circle text-green-600 mr-2"></i>
                            <span class="text-gray-700">AES-256 EAX</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Client Transaction Form -->
        <div class="bg-white rounded-xl shadow-lg overflow-hidden mb-6">
            <div class="bg-gradient-to-r from-blue-600 to-blue-700 px-6 py-4">
                <h2 class="text-xl font-bold text-white flex items-center">
                    <i class="fas fa-user-circle mr-3"></i>Client Portal - Initiate Transfer
                </h2>
            </div>
            <div class="p-6">
                <form method="POST" class="space-y-5">
                    <div>
                        <label class="block text-sm font-semibold text-gray-700 mb-2">
                            <i class="fas fa-dollar-sign text-green-600 mr-2"></i>Transfer Amount (USD)
                        </label>
                        <input type="number" name="amount" required 
                               class="w-full p-3 border-2 border-gray-300 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 outline-none transition text-lg"
                               placeholder="Enter amount">
                    </div>
                    <div>
                        <label class="block text-sm font-semibold text-gray-700 mb-2">
                            <i class="fas fa-lock text-red-600 mr-2"></i>Account Password
                        </label>
                        <input type="password" name="password" required 
                               class="w-full p-3 border-2 border-gray-300 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 outline-none transition"
                               placeholder="Enter your password">
                        <p class="text-xs text-gray-500 mt-1">
                            <i class="fas fa-info-circle"></i> Default: 123456
                        </p>
                    </div>
                    <button type="submit" name="action" value="encrypt" 
                            class="w-full bg-gradient-to-r from-blue-600 to-blue-700 text-white py-3 px-6 rounded-lg font-bold text-lg hover:from-blue-700 hover:to-blue-800 transition shadow-md flex items-center justify-center">
                        <i class="fas fa-paper-plane mr-2"></i>Authorize & Encrypt Transaction
                    </button>
                </form>

                {% if result %}
                    {% if result.error %}
                        <div class="mt-6 p-4 bg-red-50 border-l-4 border-red-500 rounded-r-lg">
                            <div class="flex items-center">
                                <i class="fas fa-exclamation-triangle text-red-500 text-xl mr-3"></i>
                                <div>
                                    <p class="font-bold text-red-800">Authentication Failed</p>
                                    <p class="text-red-700 text-sm">{{ result.error }}</p>
                                </div>
                            </div>
                        </div>
                    {% else %}
                        <div class="mt-6 border-t-2 border-gray-200 pt-6">
                            <div class="bg-green-50 border-l-4 border-green-500 p-4 rounded-r-lg mb-4">
                                <div class="flex items-center">
                                    <i class="fas fa-check-circle text-green-600 text-xl mr-3"></i>
                                    <div>
                                        <p class="font-bold text-green-800">Transaction Encrypted Successfully</p>
                                        <p class="text-green-700 text-sm">Secure packet ready for transmission</p>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="bg-gray-900 rounded-lg p-5 text-green-400">
                                <p class="text-xs font-bold text-gray-400 uppercase mb-3 flex items-center">
                                    <i class="fas fa-cube mr-2"></i>Encrypted Data Packet
                                </p>
                                <p class="hash-box text-xs leading-relaxed">{{ result.ciphertext }}</p>
                                <div class="mt-4 pt-4 border-t border-gray-700">
                                    <div class="grid grid-cols-2 gap-3 text-xs">
                                        <div class="flex items-center text-gray-400">
                                            <i class="fas fa-check-circle text-green-500 mr-2"></i>HMAC Signature
                                        </div>
                                        <div class="flex items-center text-gray-400">
                                            <i class="fas fa-check-circle text-green-500 mr-2"></i>Timestamp Embedded
                                        </div>
                                        <div class="flex items-center text-gray-400">
                                            <i class="fas fa-check-circle text-green-500 mr-2"></i>Password Verified
                                        </div>
                                        <div class="flex items-center text-gray-400">
                                            <i class="fas fa-check-circle text-green-500 mr-2"></i>AES-256 Encrypted
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <form method="POST" class="mt-4">
                                <input type="hidden" name="nonce" value="{{ result.nonce }}">
                                <input type="hidden" name="ciphertext" value="{{ result.ciphertext }}">
                                <input type="hidden" name="tag" value="{{ result.tag }}">
                                <button type="submit" name="action" value="decrypt" 
                                        class="w-full border-2 border-blue-600 text-blue-600 py-3 px-6 rounded-lg font-semibold hover:bg-blue-50 transition flex items-center justify-center">
                                    <i class="fas fa-server mr-2"></i>Process at Bank Server (Decrypt & Verify)
                                </button>
                            </form>
                        </div>
                    {% endif %}
                {% endif %}
            </div>
        </div>

        <!-- Bank Server Response -->
        {% if final %}
        <div class="bg-white rounded-xl shadow-lg overflow-hidden">
            <div class="bg-gradient-to-r from-purple-600 to-purple-700 px-6 py-4">
                <h2 class="text-xl font-bold text-white flex items-center">
                    <i class="fas fa-server mr-3"></i>Bank Server - Decryption & Verification
                </h2>
            </div>
            <div class="p-6">
                {% if final.status == 'SUCCESS' %}
                    <div class="bg-green-50 border-2 border-green-500 rounded-lg p-5 mb-5">
                        <div class="flex items-center mb-4">
                            <i class="fas fa-check-circle text-green-600 text-3xl mr-4"></i>
                            <div>
                                <h3 class="font-bold text-xl text-green-800">Transaction Verified ✓</h3>
                                <p class="text-green-700">Data integrity confirmed - No tampering detected</p>
                            </div>
                        </div>
                        <div class="grid grid-cols-2 gap-4 text-sm">
                            <div class="bg-white p-3 rounded border border-green-200">
                                <p class="text-gray-600 font-semibold">Amount</p>
                                <p class="text-2xl font-bold text-green-700">${{ final.amount }}</p>
                            </div>
                            <div class="bg-white p-3 rounded border border-green-200">
                                <p class="text-gray-600 font-semibold">Timestamp</p>
                                <p class="text-sm font-mono text-gray-800">{{ final.time }}</p>
                            </div>
                        </div>
                    </div>
                {% elif final.status == 'TAMPERED' %}
                    <div class="bg-red-50 border-2 border-red-500 rounded-lg p-5 mb-5">
                        <div class="flex items-center mb-4">
                            <i class="fas fa-exclamation-triangle text-red-600 text-3xl mr-4"></i>
                            <div>
                                <h3 class="font-bold text-xl text-red-800">Security Alert: Data Tampered!</h3>
                                <p class="text-red-700">Hash verification failed - Transaction rejected</p>
                            </div>
                        </div>
                        <div class="grid grid-cols-2 gap-4 text-sm">
                            <div class="bg-white p-3 rounded border border-red-200">
                                <p class="text-gray-600 font-semibold">Received Amount</p>
                                <p class="text-2xl font-bold text-red-700">${{ final.amount }}</p>
                            </div>
                            <div class="bg-white p-3 rounded border border-red-200">
                                <p class="text-gray-600 font-semibold">Timestamp</p>
                                <p class="text-sm font-mono text-gray-800">{{ final.time }}</p>
                            </div>
                        </div>
                    </div>
                {% else %}
                    <div class="bg-yellow-50 border-2 border-yellow-500 rounded-lg p-5 mb-5">
                        <div class="flex items-center">
                            <i class="fas fa-exclamation-circle text-yellow-600 text-3xl mr-4"></i>
                            <div>
                                <h3 class="font-bold text-xl text-yellow-800">Decryption Error</h3>
                                <p class="text-yellow-700">{{ final.msg }}</p>
                            </div>
                        </div>
                    </div>
                {% endif %}

                {% if final.received_hash %}
                <!-- Hash Comparison Section -->
                <div class="border-t-2 border-gray-200 pt-5 mt-5">
                    <h3 class="font-bold text-lg mb-4 flex items-center text-gray-800">
                        <i class="fas fa-fingerprint text-purple-600 mr-2"></i>
                        HMAC Hash Comparison (SHA-256)
                    </h3>
                    
                    <div class="space-y-4">
                        <!-- Received Hash -->
                        <div class="bg-blue-50 border-l-4 border-blue-500 rounded-r-lg p-4">
                            <p class="text-sm font-bold text-blue-900 mb-2 flex items-center">
                                <i class="fas fa-download mr-2"></i>Hash Received from Client
                            </p>
                            <p class="hash-box text-xs text-blue-800 bg-white p-3 rounded border border-blue-200">
                                {{ final.received_hash }}
                            </p>
                        </div>

                        <!-- Computed Hash -->
                        <div class="bg-purple-50 border-l-4 border-purple-500 rounded-r-lg p-4">
                            <p class="text-sm font-bold text-purple-900 mb-2 flex items-center">
                                <i class="fas fa-calculator mr-2"></i>Hash Computed by Bank Server
                            </p>
                            <p class="hash-box text-xs text-purple-800 bg-white p-3 rounded border border-purple-200">
                                {{ final.computed_hash }}
                            </p>
                        </div>

                        <!-- Comparison Result -->
                        <div class="bg-gray-100 rounded-lg p-5 text-center">
                            {% if final.hash_match %}
                                <div class="flex items-center justify-center text-green-700 mb-2">
                                    <i class="fas fa-equals text-3xl mr-3"></i>
                                    <span class="text-2xl font-bold">Hashes Match</span>
                                    <i class="fas fa-check-circle text-3xl ml-3"></i>
                                </div>
                                <p class="text-green-800 font-semibold">✓ Data integrity verified - No tampering detected</p>
                                <p class="text-sm text-gray-600 mt-2">The transaction data has not been modified during transmission</p>
                            {% else %}
                                <div class="flex items-center justify-center text-red-700 mb-2">
                                    <i class="fas fa-not-equal text-3xl mr-3"></i>
                                    <span class="text-2xl font-bold">Hashes Don't Match</span>
                                    <i class="fas fa-times-circle text-3xl ml-3"></i>
                                </div>
                                <p class="text-red-800 font-semibold">✗ Data integrity compromised - Tampering detected!</p>
                                <p class="text-sm text-gray-600 mt-2">The transaction data was modified after encryption</p>
                            {% endif %}
                        </div>
                    </div>
                </div>
                {% endif %}
            </div>
        </div>
        {% endif %}
    </div>

    <!-- Footer -->
    <div class="text-center py-6 text-gray-600 text-sm">
        <p><i class="fas fa-shield-alt text-blue-600"></i> Tocashless - AES-256 Encrypted Transaction System | Group A4</p>
        <p class="text-xs mt-1">Protected by multi-layer encryption: Password Authentication • HMAC Signature • Timestamp • AES Encryption</p>
    </div>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def index():
    result, final = None, None
    if request.method == "POST":
        action = request.form.get("action")
        if action == "encrypt":
            result = build_secure_packet(request.form.get("amount"), request.form.get("password"))
        elif action == "decrypt":
            final = decrypt_and_verify(request.form.get("nonce"), request.form.get("ciphertext"), request.form.get("tag"))
    return render_template_string(HTML_UI, result=result, final=final)

if __name__ == "__main__":
    app.run(debug=True)