# app.py - Full working version for Vercel

from flask import Flask, request, jsonify
import requests
import json
import os
import sys
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

G = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
F = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
RELEASE_VERSION = "OB54"
APP_VERSION = "1.126.1"

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
#  TOKEN MANAGEMENT (WITH ENV VAR SUPPORT)
# =============================================================================

def load_tokens(server_name):
    try:
        # 🔑 Check environment variables first (for Vercel)
        if server_name == "IND":
            env_token = os.getenv("IND_TOKEN")
        elif server_name in {"BR", "US", "SAC", "NA"}:
            env_token = os.getenv("BR_TOKEN")
        else:
            env_token = os.getenv("BD_TOKEN")
        
        if env_token:
            app.logger.info(f"✅ Using token from environment for {server_name}")
            return [{"token": env_token}]
        
        # 📁 Fallback to file (local development)
        if server_name == "IND":
            filename = "token_ind.json"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            filename = "token_br.json"
        else:
            filename = "token_bd.json"
        
        # Check if file exists
        if not os.path.exists(filename):
            app.logger.error(f"❌ File not found: {filename}")
            return None
            
        with open(filename, "r") as f:
            tokens = json.load(f)
            return tokens
            
    except Exception as e:
        app.logger.error(f"Error loading tokens for {server_name}: {e}")
        return None

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
        app.logger.error(f"Error encrypting: {e}")
        return None

def create_uid_protobuf(uid):
    try:
        message = {
            'a': int(uid),
            'b': 7,
            'c': 1,
            'd': RELEASE_VERSION,
            'e': APP_VERSION
        }
        return json.dumps(message).encode('utf-8')
    except Exception as e:
        app.logger.error(f"Error creating protobuf: {e}")
        return None

def enc(uid):
    protobuf_data = create_uid_protobuf(uid)
    if protobuf_data is None:
        return None
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid

def decode_protobuf(binary):
    try:
        items = AccountPersonalShow_pb2.AccountPersonalShowInfo()
        items.ParseFromString(binary)
        return items
    except Exception as e:
        app.logger.error(f"Error decoding: {e}")
        return None

def make_request(encrypt, server_name, token):
    try:
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
            'ReleaseVersion': RELEASE_VERSION
        }
        
        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=30)
        
        if response.status_code != 200:
            app.logger.error(f"HTTP Error: {response.status_code}")
            return None
            
        binary = bytes.fromhex(response.content.hex())
        decode = decode_protobuf(binary)
        return decode
        
    except Exception as e:
        app.logger.error(f"Error in make_request: {e}")
        return None

def get_player_info(uid, server_name):
    try:
        tokens = load_tokens(server_name)
        if tokens is None:
            app.logger.error("Failed to load tokens.")
            return None, None, None, None, None, None, None
            
        token = tokens[0]['token']
        
        encrypted_uid = enc(uid)
        if encrypted_uid is None:
            app.logger.error("Encryption failed.")
            return None, None, None, None, None, None, None
            
        result = make_request(encrypted_uid, server_name, token)
        if result is None:
            app.logger.error("Request failed.")
            return None, None, None, None, None, None, None
            
        try:
            jsone = MessageToJson(result)
            data = json.loads(jsone)
            
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
                account_id = data.get('accountId', uid)
                nickname = data.get('nickname', 'Unknown')
                level = data.get('level', 0)
                region = data.get('region', server_name)
                rank = data.get('rank', 0)
                clan_name = data.get('clanName', 'No Clan')
                likes = data.get('liked', 0)
            
            return nickname, int(level), int(likes), region, int(rank), clan_name, account_id
            
        except Exception as e:
            app.logger.error(f"Error parsing: {e}")
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
        "message": f"Free Fire Player Info API ({RELEASE_VERSION})",
        "endpoints": {
            "/player": "Get player info",
            "/health": "Health check"
        },
        "example": "/player?uid=4620004854&server_name=IND"
    })

@app.route('/health')
def health():
    return jsonify({"status": "ok", "version": RELEASE_VERSION})

@app.route('/player', methods=['GET'])
def get_player():
    try:
        uid = request.args.get("uid")
        server_name = request.args.get("server_name", "").upper()
        
        if not uid:
            return jsonify({"error": "UID is required"}), 400
        
        if not server_name:
            return jsonify({"error": "server_name is required"}), 400
        
        nickname, level, likes, region, rank, clan_name, account_id = get_player_info(uid, server_name)
        
        if nickname is None:
            return jsonify({"error": "Player not found"}), 404
        
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
        app.logger.error(f"Error: {e}")
        return jsonify({"error": str(e)}), 500

# =============================================================================
#  FOR VERCEL
# =============================================================================

# This is required for Vercel
app = app

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
