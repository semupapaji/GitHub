from flask import Flask, request, jsonify
import requests
import json
import base64
from google.protobuf.json_format import MessageToJson
import AccountPersonalShow_pb2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii
from google.protobuf.message import DecodeError

app = Flask(__name__)

# =============================================================================
#  CONSTANTS
# =============================================================================

# Keys from payload
G = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
F = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

# OB54 Release Version
RELEASE_VERSION = "OB54"
APP_VERSION = "1.126.1"

# Region mapping
REGIONS = {
    "IND": "https://client.ind.freefiremobile.com",
    "BR": "https://client.us.freefiremobile.com",
    "US": "https://client.us.freefiremobile.com",
    "SAC": "https://client.us.freefiremobile.com",
    "NA": "https://client.us.freefiremobile.com",
    "BD": "https://clientbp.ggblueshark.com",
    "DEFAULT": "https://clientbp.ggblueshark.com"
}

# =============================================================================
#  TOKEN MANAGEMENT
# =============================================================================

def load_tokens(server_name):
    try:
        if server_name == "IND":
            with open("token_ind.json", "r") as f:
                tokens = json.load(f)
        elif server_name in {"BR", "US", "SAC", "NA"}:
            with open("token_br.json", "r") as f:
                tokens = json.load(f)
        else:
            with open("token_bd.json", "r") as f:
                tokens = json.load(f)
        return tokens
    except Exception as e:
        app.logger.error(f"Error loading tokens for server {server_name}: {e}")
        return None

def save_tokens(server_name, token_data):
    try:
        if server_name == "IND":
            filename = "token_ind.json"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            filename = "token_br.json"
        else:
            filename = "token_bd.json"
        
        with open(filename, "w") as f:
            json.dump([{"token": token_data}], f, indent=2)
        return True
    except Exception as e:
        app.logger.error(f"Error saving tokens: {e}")
        return False

# =============================================================================
#  ENCRYPTION FUNCTIONS
# =============================================================================

def encrypt_message(plaintext):
    try:
        cipher = AES.new(G, AES.MODE_CBC, F)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Error encrypting message: {e}")
        return None

def decrypt_message(encrypted_hex):
    try:
        encrypted_bytes = bytes.fromhex(encrypted_hex)
        cipher = AES.new(G, AES.MODE_CBC, F)
        decrypted = cipher.decrypt(encrypted_bytes)
        unpadded = unpad(decrypted, AES.block_size)
        return unpadded
    except Exception as e:
        app.logger.error(f"Error decrypting message: {e}")
        return None

# =============================================================================
#  UID PROTOBUF CREATION (Updated for OB54)
# =============================================================================

def create_uid_protobuf(uid):
    """
    Create protobuf for UID request based on new payload structure
    """
    try:
        # New structure from OB54 payload
        message = {
            'a': int(uid),  # UID
            'b': 7,         # Unknown constant (from original code)
            'c': 1,         # Platform type
            'd': RELEASE_VERSION,  # OB54
            'e': APP_VERSION       # 1.126.1
        }
        return json.dumps(message).encode('utf-8')
    except Exception as e:
        app.logger.error(f"Error creating uid protobuf: {e}")
        return None

def create_login_protobuf(open_id, login_token):
    """
    Create login protobuf for OB54
    """
    try:
        message = {
            'open_id': open_id,
            'open_id_type': 4,
            'login_token': login_token,
            'orign_platform_type': 4,
            'version': APP_VERSION,
            'release': RELEASE_VERSION
        }
        return json.dumps(message).encode('utf-8')
    except Exception as e:
        app.logger.error(f"Error creating login protobuf: {e}")
        return None

def enc(uid):
    protobuf_data = create_uid_protobuf(uid)
    if protobuf_data is None:
        return None
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid

# =============================================================================
#  DECODING FUNCTIONS
# =============================================================================

def decode_protobuf(binary):
    try:
        items = AccountPersonalShow_pb2.AccountPersonalShowInfo()
        items.ParseFromString(binary)
        return items
    except DecodeError as e:
        app.logger.error(f"Error decoding Protobuf data: {e}")
        return None
    except Exception as e:
        app.logger.error(f"Unexpected error during protobuf decoding: {e}")
        return None

# =============================================================================
#  REQUEST FUNCTIONS
# =============================================================================

def make_request(encrypt, server_name, token):
    try:
        # Get base URL
        base_url = REGIONS.get(server_name, REGIONS["DEFAULT"])
        url = f"{base_url}/GetPlayerPersonalShow"
        
        edata = bytes.fromhex(encrypt)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': RELEASE_VERSION  # OB54
        }
        
        app.logger.info(f"Making request to: {url}")
        app.logger.info(f"Release Version: {RELEASE_VERSION}")
        
        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=30)
        
        if response.status_code != 200:
            app.logger.error(f"HTTP Error: {response.status_code}")
            return None
            
        hex_data = response.content.hex()
        binary = bytes.fromhex(hex_data)
        decode = decode_protobuf(binary)
        return decode
        
    except requests.exceptions.Timeout:
        app.logger.error("Request timeout")
        return None
    except Exception as e:
        app.logger.error(f"Error in make_request: {e}")
        return None

# =============================================================================
#  LOGIN FUNCTION (To Generate Tokens)
# =============================================================================

def generate_token(server_name, open_id, access_token):
    """
    Generate new token using OB54 login endpoint
    """
    try:
        # Create login request
        login_data = create_login_protobuf(open_id, access_token)
        if login_data is None:
            return None
            
        encrypted = encrypt_message(login_data)
        if encrypted is None:
            return None
            
        edata = bytes.fromhex(encrypted)
        url = "https://loginbp.ggpolarbear.com/MajorLogin"
        
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': RELEASE_VERSION
        }
        
        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=30)
        
        if response.status_code != 200:
            app.logger.error(f"Login HTTP Error: {response.status_code}")
            return None
            
        # Parse response
        decrypted = decrypt_message(response.content.hex())
        if decrypted is None:
            return None
            
        try:
            data = json.loads(decrypted.decode('utf-8'))
            token = data.get('token')
            if token:
                # Save token
                save_tokens(server_name, token)
                return token
        except:
            # Try protobuf parsing
            try:
                from FreeFire_pb2 import LoginRes
                login_res = LoginRes()
                login_res.ParseFromString(response.content)
                token = login_res.token
                if token:
                    save_tokens(server_name, token)
                    return token
            except:
                pass
                
        return None
        
    except Exception as e:
        app.logger.error(f"Error generating token: {e}")
        return None

# =============================================================================
#  PLAYER INFO FUNCTION
# =============================================================================

def get_player_info(uid, server_name):
    """
    Get complete player info
    Returns: (nickname, level, likes, region, rank, clan_name, account_id)
    """
    try:
        # Load tokens
        tokens = load_tokens(server_name)
        if tokens is None:
            app.logger.error("Failed to load tokens.")
            return None, None, None, None, None, None, None
            
        token = tokens[0]['token']
        
        # Encrypt UID
        encrypted_uid = enc(uid)
        if encrypted_uid is None:
            app.logger.error("Encryption of UID failed.")
            return None, None, None, None, None, None, None
            
        # Make request
        result = make_request(encrypted_uid, server_name, token)
        if result is None:
            app.logger.error("Failed to retrieve player info.")
            return None, None, None, None, None, None, None
            
        # Parse response
        try:
            jsone = MessageToJson(result)
            data = json.loads(jsone)
            
            # Extract from correct structure
            if 'basicInfo' in data:
                basic = data['basicInfo']
                account_id = basic.get('accountId', uid)
                nickname = basic.get('nickname', 'Unknown')
                level = basic.get('level', 0)
                region = basic.get('region', server_name)
                rank = basic.get('rank', 0)
                clan_name = basic.get('clanName', 'No Clan')
                likes = basic.get('liked', 0)
            else:
                # Fallback
                account_id = data.get('accountId', uid)
                nickname = data.get('nickname', 'Unknown')
                level = data.get('level', 0)
                region = data.get('region', server_name)
                rank = data.get('rank', 0)
                clan_name = data.get('clanName', 'No Clan')
                likes = data.get('liked', 0)
            
            # Convert types
            try:
                level = int(level)
            except:
                level = 0
                
            try:
                likes = int(likes)
            except:
                likes = 0
                
            try:
                rank = int(rank)
            except:
                rank = 0
            
            app.logger.info(f"✅ Player found: {nickname} (Level {level}) [Region: {region}]")
            return nickname, level, likes, region, rank, clan_name, account_id
            
        except Exception as e:
            app.logger.error(f"Error parsing player info: {e}")
            return None, None, None, None, None, None, None
            
    except Exception as e:
        app.logger.error(f"Error in get_player_info: {e}")
        return None, None, None, None, None, None, None

# =============================================================================
#  ROUTES
# =============================================================================

@app.route('/')
def home():
    return jsonify({
        "status": "Active",
        "message": f"Free Fire Player Info API ({RELEASE_VERSION} - {APP_VERSION})",
        "endpoints": {
            "/player": "Get player info (requires UID and server_name)",
            "/debug": "Get player info with full response (for debugging)",
            "/generate_token": "Generate new token (requires open_id and access_token)"
        },
        "example": "/player?uid=4620004854&server_name=IND"
    })

@app.route('/player', methods=['GET'])
def get_player():
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    
    if not uid:
        return jsonify({"error": "UID is required"}), 400
    
    if not server_name:
        return jsonify({"error": "server_name is required (IND, US, BR, BD, etc.)"}), 400
    
    try:
        nickname, level, likes, region, rank, clan_name, account_id = get_player_info(uid, server_name)
        
        if nickname is None or nickname == 'Unknown':
            return jsonify({"error": "Failed to fetch player info. Please check UID and server_name."}), 404
        
        return jsonify({
            "status": "success",
            "player": {
                "account_id": account_id,
                "nickname": nickname,
                "level": level,
                "likes": likes,
                "region": region,
                "rank": rank,
                "clan_name": clan_name,
                "uid": uid
            }
        })
        
    except Exception as e:
        app.logger.error(f"Error in get_player endpoint: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/debug', methods=['GET'])
def debug_player():
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    
    if not uid or not server_name:
        return jsonify({"error": "UID and server_name required"}), 400
    
    try:
        tokens = load_tokens(server_name)
        if tokens is None:
            return jsonify({"error": "Failed to load tokens"}), 500
            
        token = tokens[0]['token']
        encrypted_uid = enc(uid)
        if encrypted_uid is None:
            return jsonify({"error": "Encryption failed"}), 500
            
        result = make_request(encrypted_uid, server_name, token)
        if result is None:
            return jsonify({"error": "Request failed"}), 500
            
        jsone = MessageToJson(result)
        data = json.loads(jsone)
        
        return jsonify({
            "version": {
                "release": RELEASE_VERSION,
                "app": APP_VERSION
            },
            "full_response": data,
            "available_keys": list(data.keys()),
            "message": "Check 'basicInfo' field for account details"
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/generate_token', methods=['POST', 'GET'])
def generate_token_route():
    if request.method == 'GET':
        open_id = request.args.get("open_id")
        access_token = request.args.get("access_token")
        server_name = request.args.get("server_name", "IND").upper()
    else:
        data = request.get_json()
        open_id = data.get("open_id")
        access_token = data.get("access_token")
        server_name = data.get("server_name", "IND").upper()
    
    if not open_id or not access_token:
        return jsonify({"error": "open_id and access_token required"}), 400
    
    try:
        token = generate_token(server_name, open_id, access_token)
        if token:
            return jsonify({
                "status": "success",
                "message": f"Token generated for {server_name}",
                "token": token,
                "server": server_name,
                "version": RELEASE_VERSION
            })
        else:
            return jsonify({"error": "Failed to generate token"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =============================================================================
#  MAIN
# =============================================================================

if __name__ == '__main__':
    print("\n" + "="*60)
    print(f"🚀 FREE FIRE PLAYER INFO API STARTED")
    print(f"📌 Version: {RELEASE_VERSION} - {APP_VERSION}")
    print("="*60)
    print("📍 Endpoints:")
    print("   GET /player?uid=UID&server_name=REGION")
    print("   GET /debug?uid=UID&server_name=REGION")
    print("   POST/GET /generate_token?open_id=ID&access_token=TOKEN&server_name=REGION")
    print("\n📝 Examples:")
    print("   http://localhost:5000/player?uid=4620004854&server_name=IND")
    print("   http://localhost:5000/generate_token?open_id=4306245793de86da425a52caadf21eed&access_token=c69ae208fad72738b674b2847b50a3a1dfa25d1a19fae745fc76ac4a0e414c94&server_name=IND")
    print("="*60 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)