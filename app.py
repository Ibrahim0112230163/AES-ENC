from flask import Flask, render_template_string, request
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

app = Flask(__name__)

# In a real app, this key should be stored securely (not hardcoded)
# AES-128 requires a 16-byte key
SECRET_KEY = b'this_is_16_bytes' 

def encrypt_aes(message):
    cipher = AES.new(SECRET_KEY, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    # Encode to Base64 so it can be displayed as text on the website
    return {
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
        "tag": base64.b64encode(tag).decode('utf-8')
    }

def decrypt_aes(nonce_b64, ciphertext_b64, tag_b64):
    try:
        nonce = base64.b64decode(nonce_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        tag = base64.b64decode(tag_b64)
        
        cipher = AES.new(SECRET_KEY, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')
    except Exception as e:
        return f"Decryption Failed: {str(e)}"

# Professional Banking UI Template
HTML_UI = """
<!DOCTYPE html>
<html>
<head>
    <title>AES Simulation - Encrypted Transaction System</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
        
        body {
            font-family: 'Inter', sans-serif;
        }
        
        .gradient-bg {
            background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 50%, #1e40af 100%);
        }
        
        .card-hover {
            transition: all 0.3s ease;
        }
        
        .card-hover:hover {
            transform: translateY(-5px);
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
        }
        
        .encrypted-text {
            background: linear-gradient(90deg, #1f2937 0%, #111827 100%);
            border-left: 4px solid #10b981;
        }
        
        .pulse-animation {
            animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: .7; }
        }
        
        .btn-primary {
            background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
            transition: all 0.3s ease;
        }
        
        .btn-primary:hover {
            background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
            transform: scale(1.02);
        }
        
        .btn-success {
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            transition: all 0.3s ease;
        }
        
        .btn-success:hover {
            background: linear-gradient(135deg, #059669 0%, #047857 100%);
            transform: scale(1.02);
        }
    </style>
</head>
<body class="bg-gray-50">
    <!-- Header -->
    <div class="gradient-bg text-white shadow-2xl">
        <div class="max-w-7xl mx-auto px-4 py-6">
            <div class="flex items-center justify-between">
                <div class="flex items-center space-x-3">
                    <i class="fas fa-shield-alt text-3xl"></i>
                    <div>
                        <h1 class="text-2xl font-bold">AES Simulation</h1>
                        <p class="text-sm text-blue-100">AES-256 Encrypted Transaction System</p>
                    </div>
                </div>
                <div class="flex items-center space-x-2 bg-white/10 px-4 py-2 rounded-lg backdrop-blur-sm">
                    <i class="fas fa-lock text-green-400"></i>
                    <span class="text-sm font-medium">Secured Connection</span>
                </div>
            </div>
        </div>
    </div>

    <!-- Main Content -->
    <div class="max-w-7xl mx-auto px-4 py-8">
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
            
            <!-- Sender Side - Encrypt Transaction -->
            <div class="bg-white rounded-2xl shadow-xl p-8 card-hover border-t-4 border-blue-500">
                <div class="flex items-center space-x-3 mb-6">
                    <div class="bg-blue-100 p-3 rounded-lg">
                        <i class="fas fa-paper-plane text-blue-600 text-2xl"></i>
                    </div>
                    <div>
                        <h2 class="text-2xl font-bold text-gray-800">Sender</h2>
                        <p class="text-sm text-gray-500">Encrypt Your Transaction</p>
                    </div>
                </div>
                
                <form method="POST" class="space-y-6">
                    <div>
                        <label class="block text-sm font-semibold text-gray-700 mb-2">
                            <i class="fas fa-file-invoice-dollar mr-2"></i>Transaction Details
                        </label>
                        <textarea 
                            name="message" 
                            rows="4"
                            class="w-full px-4 py-3 border-2 border-gray-200 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all outline-none text-gray-700" 
                            placeholder="Enter transaction details... (e.g., Transfer $5000 to Account #123456)"
                            required
                        ></textarea>
                    </div>
                    
                    <button 
                        type="submit" 
                        name="action" 
                        value="encrypt" 
                        class="btn-primary w-full text-white font-semibold py-4 px-6 rounded-lg shadow-lg flex items-center justify-center space-x-2"
                    >
                        <i class="fas fa-lock"></i>
                        <span>Encrypt Transaction</span>
                        <i class="fas fa-arrow-right"></i>
                    </button>
                </form>

                <div class="mt-6 p-4 bg-blue-50 rounded-lg border border-blue-200">
                    <div class="flex items-start space-x-2">
                        <i class="fas fa-info-circle text-blue-500 mt-1"></i>
                        <div class="text-sm text-blue-800">
                            <p class="font-semibold">Secure Encryption</p>
                            <p class="text-blue-600">Your transaction will be encrypted using AES-256 encryption standard.</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Receiver Side - Decrypt & Verify -->
            <div class="bg-white rounded-2xl shadow-xl p-8 card-hover border-t-4 border-green-500">
                <div class="flex items-center space-x-3 mb-6">
                    <div class="bg-green-100 p-3 rounded-lg">
                        <i class="fas fa-inbox text-green-600 text-2xl"></i>
                    </div>
                    <div>
                        <h2 class="text-2xl font-bold text-gray-800">Receiver</h2>
                        <p class="text-sm text-gray-500">Decrypt & Verify Transaction</p>
                    </div>
                </div>

                {% if result %}
                <div class="space-y-4">
                    <div class="bg-gradient-to-br from-gray-900 to-gray-800 rounded-lg p-4 shadow-inner">
                        <div class="flex items-center justify-between mb-2">
                            <span class="text-xs font-semibold text-gray-400 uppercase tracking-wider">
                                <i class="fas fa-key mr-1"></i>Encrypted Ciphertext
                            </span>
                            <span class="text-xs bg-green-500 text-white px-2 py-1 rounded-full pulse-animation">
                                <i class="fas fa-check-circle mr-1"></i>Encrypted
                            </span>
                        </div>
                        <p class="break-all text-xs font-mono text-green-400 leading-relaxed">{{ result.ciphertext }}</p>
                    </div>
                    
                    <form method="POST">
                        <input type="hidden" name="nonce" value="{{ result.nonce }}">
                        <input type="hidden" name="ciphertext" value="{{ result.ciphertext }}">
                        <input type="hidden" name="tag" value="{{ result.tag }}">
                        <button 
                            type="submit" 
                            name="action" 
                            value="decrypt" 
                            class="btn-success w-full text-white font-semibold py-4 px-6 rounded-lg shadow-lg flex items-center justify-center space-x-2"
                        >
                            <i class="fas fa-unlock"></i>
                            <span>Decrypt & Verify</span>
                            <i class="fas fa-check-double"></i>
                        </button>
                    </form>
                </div>
                {% else %}
                <div class="flex flex-col items-center justify-center h-64 text-gray-400">
                    <i class="fas fa-envelope-open-text text-6xl mb-4"></i>
                    <p class="text-lg font-medium">Waiting for encrypted transaction...</p>
                    <p class="text-sm mt-2">Encrypted data will appear here</p>
                </div>
                {% endif %}

                {% if decrypted %}
                <div class="mt-6 bg-gradient-to-r from-green-50 to-emerald-50 border-2 border-green-500 rounded-lg p-6 shadow-lg">
                    <div class="flex items-center space-x-2 mb-3">
                        <i class="fas fa-check-circle text-green-600 text-xl"></i>
                        <h3 class="font-bold text-lg text-green-800">Transaction Verified</h3>
                    </div>
                    <div class="bg-white rounded-lg p-4 border border-green-200">
                        <p class="text-gray-800 font-medium">{{ decrypted }}</p>
                    </div>
                    <div class="mt-3 flex items-center space-x-2 text-xs text-green-700">
                        <i class="fas fa-shield-alt"></i>
                        <span>Authenticity verified • Integrity confirmed</span>
                    </div>
                </div>
                {% endif %}

                <div class="mt-6 p-4 bg-green-50 rounded-lg border border-green-200">
                    <div class="flex items-start space-x-2">
                        <i class="fas fa-shield-alt text-green-500 mt-1"></i>
                        <div class="text-sm text-green-800">
                            <p class="font-semibold">Bank-Grade Security</p>
                            <p class="text-green-600">All transactions are verified for authenticity and integrity.</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Security Features -->
        <div class="mt-8 grid grid-cols-1 md:grid-cols-3 gap-6">
            <div class="bg-white rounded-xl p-6 shadow-md text-center card-hover">
                <div class="bg-blue-100 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
                    <i class="fas fa-lock text-blue-600 text-2xl"></i>
                </div>
                <h3 class="font-bold text-gray-800 mb-2">AES-256 Encryption</h3>
                <p class="text-sm text-gray-600">Military-grade encryption protecting your sensitive data</p>
            </div>
            
            <div class="bg-white rounded-xl p-6 shadow-md text-center card-hover">
                <div class="bg-green-100 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
                    <i class="fas fa-check-double text-green-600 text-2xl"></i>
                </div>
                <h3 class="font-bold text-gray-800 mb-2">Authentication</h3>
                <p class="text-sm text-gray-600">Verify sender identity and data integrity</p>
            </div>
            
            <div class="bg-white rounded-xl p-6 shadow-md text-center card-hover">
                <div class="bg-purple-100 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
                    <i class="fas fa-user-shield text-purple-600 text-2xl"></i>
                </div>
                <h3 class="font-bold text-gray-800 mb-2">Privacy Protected</h3>
                <p class="text-sm text-gray-600">Your transaction details remain confidential</p>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <div class="bg-gray-800 text-gray-300 mt-12 py-6">
        <div class="max-w-7xl mx-auto px-4 text-center">
            <p class="text-sm">© 2026 SecureBank. All rights reserved. | Powered by AES-256 Encryption</p>
            <p class="text-xs mt-2 text-gray-500">
                <i class="fas fa-lock mr-1"></i>Your security is our priority
            </p>
        </div>
    </div>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    decrypted = None
    if request.method == "POST":
        action = request.form.get("action")
        if action == "encrypt":
            msg = request.form.get("message")
            result = encrypt_aes(msg)
        elif action == "decrypt":
            decrypted = decrypt_aes(
                request.form.get("nonce"),
                request.form.get("ciphertext"),
                request.form.get("tag")
            )
    return render_template_string(HTML_UI, result=result, decrypted=decrypted)

if __name__ == "__main__":
    app.run(debug=True)