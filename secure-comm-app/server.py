from flask import Flask, request, jsonify, redirect, url_for
from flask_jwt_extended import (
    JWTManager, 
    create_access_token,
    get_jwt_identity,
    jwt_required,
    verify_jwt_in_request
)
from flask_dance.contrib.google import make_google_blueprint, google
from security import (
    generate_key_pair, 
    encrypt_message, 
    decrypt_message, 
    sign_message, 
    verify_signature,
    hybrid_encrypt,
    hybrid_decrypt,
    encrypt_file,
    decrypt_file,
    generate_secure_token
)

import asyncio
import websockets
import json
import os
import ssl
import logging
from datetime import datetime, timedelta
from models.user import User
from models.room import Room, Message
from database import get_db, Base, engine
import re
import bcrypt
import uuid
from functools import wraps

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("server.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("secure-comm-server")

# Initialize Flask app
app = Flask(__name__)

# Generate a secure random key for JWT
if not os.path.exists('.env'):
    with open('.env', 'w') as f:
        jwt_secret = os.urandom(32).hex()
        f.write(f"JWT_SECRET_KEY={jwt_secret}\n")
        f.write(f"GOOGLE_OAUTH_CLIENT_ID=your-google-client-id\n")
        f.write(f"GOOGLE_OAUTH_CLIENT_SECRET=your-google-client-secret\n")
        f.write(f"RECAPTCHA_SECRET_KEY=your-recaptcha-secret-key\n")
        logger.info("Created .env file with secure JWT secret")

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# Configure JWT
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY", os.urandom(32).hex())
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
jwt = JWTManager(app)

# Rate limiting setup
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Google OAuth setup
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_OAUTH_CLIENT_ID", "your-google-client-id")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_OAUTH_CLIENT_SECRET", "your-google-client-secret")
google_bp = make_google_blueprint(
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    redirect_to="google_authorized",
    scope=["profile", "email"]
)
app.register_blueprint(google_bp, url_prefix="/login")

# Initialize database
Base.metadata.create_all(bind=engine)

# WebSocket clients dictionary
clients = {}
rooms = {}

# Input validation functions
def is_valid_username(username: str) -> bool:
    """Validate username: 3-20 chars, alphanumeric and underscores only"""
    return bool(re.match(r'^[a-zA-Z0-9_]{3,20}$', username))

def is_valid_email(email: str) -> bool:
    """Validate email format"""
    return bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email))

def is_valid_password(password: str) -> bool:
    """
    Validate password strength:
    - At least 8 characters
    - Contains at least one uppercase letter
    - Contains at least one lowercase letter
    - Contains at least one digit
    - Contains at least one special character
    """
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True

def sanitize_input(text: str) -> str:
    """Basic input sanitization to prevent injection attacks"""
    if not text:
        return ""
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[<>\'";]', '', text)
    return sanitized

# Security middleware
def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key or api_key != os.getenv('API_KEY'):
            return jsonify({"message": "Invalid or missing API key"}), 401
        return f(*args, **kwargs)
    return decorated

# Routes
@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    try:
        data = request.get_json()
        
        # Validate and sanitize inputs
        email = sanitize_input(data.get('email', ''))
        username = sanitize_input(data.get('username', ''))
        password = data.get('password', '')
        
        # Validate captcha if enabled
        captcha_response = data.get('captcha_response')
        if os.getenv('RECAPTCHA_ENABLED', 'false').lower() == 'true':
            if not captcha_response:
                return jsonify({"message": "CAPTCHA verification required"}), 400
            
            # Verify CAPTCHA
            if not verify_captcha(captcha_response):
                return jsonify({"message": "CAPTCHA verification failed"}), 400
        
        # Validate inputs
        if not is_valid_email(email):
            return jsonify({"message": "Invalid email format"}), 400
        
        if not is_valid_username(username):
            return jsonify({"message": "Invalid username. Must be 3-20 characters, alphanumeric or underscores only."}), 400
        
        if not is_valid_password(password):
            return jsonify({"message": "Password must be at least 8 characters and include uppercase, lowercase, number, and special character."}), 400
        
        # Check if user exists
        db = next(get_db())
        if not User.is_email_username_unique(db, email, username):
            return jsonify({"message": "Email or Username already exists"}), 400
        
        # Create user
        user = User.create_user(db, email, username, password)
        if not user:
            return jsonify({"message": "Registration failed"}), 500
        
        # Generate a verification token and send email (simplified)
        verification_token = generate_secure_token()
        # In a real app, store this token and send an email with a verification link
        
        logger.info(f"User registered: {username}")
        return jsonify({
            "message": "User registered successfully. Please check your email to verify your account.",
            "user_id": user.id
        }), 201
    
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        return jsonify({"message": "An error occurred during registration"}), 500

@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    try:
        data = request.get_json()
        username = sanitize_input(data.get('username', ''))
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({"message": "Username and password are required"}), 400
        
        db = next(get_db())
        user = User.authenticate(db, username, password)
        
        if not user:
            # Use a generic error message to prevent username enumeration
            return jsonify({"message": "Invalid credentials"}), 401
        
        # Generate tokens
        access_token = create_access_token(identity=username)
        
        # In a real app, you would also generate a refresh token
        # refresh_token = create_refresh_token(identity=username)
        
        logger.info(f"User logged in: {username}")
        return jsonify({
            "access_token": access_token,
            # "refresh_token": refresh_token,
            "username": username
        }), 200
    
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({"message": "An error occurred during login"}), 500

@app.route('/login/google')
def login_google():
    # This route just triggers the OAuth redirect
    return redirect(url_for("google.login"))

@app.route('/login/google/authorized')
def google_authorized():
    if not google.authorized:
        return redirect(url_for("google.login"))
    
    try:
        resp = google.get("/oauth2/v2/userinfo")
        if not resp.ok:
            logger.error(f"Failed to fetch user info from Google: {resp.text}")
            return "Failed to fetch user info from Google.", 400
        
        info = resp.json()
        email = info.get("email")
        if not email:
            return "Email not provided by Google.", 400
        
        username = info.get("name") or email.split("@")[0]
        
        # Sanitize username
        username = sanitize_input(username)
        if not is_valid_username(username):
            # Generate a valid username if the Google-provided one is invalid
            username = f"user_{uuid.uuid4().hex[:10]}"
        
        db = next(get_db())
        user = db.query(User).filter_by(email=email).first()
        
        if not user:
            # Create user if doesn't exist
            # Generate a secure random password for OAuth users
            random_password = generate_secure_token(16)
            password_hash = bcrypt.hashpw(random_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            user = User(email=email, username=username, password_hash=password_hash)
            db.add(user)
            db.commit()
            db.refresh(user)
        
        # Issue JWT token
        access_token = create_access_token(identity=user.username)
        
        logger.info(f"User logged in via Google: {username}")
        # You might want to redirect to a frontend page or show a success message
        return jsonify({
            "access_token": access_token, 
            "username": user.username, 
            "email": user.email
        })
    
    except Exception as e:
        logger.error(f"Google OAuth error: {str(e)}")
        return jsonify({"message": "An error occurred during Google authentication"}), 500

@app.route('/verify_captcha', methods=['POST'])
def verify_captcha():
    try:
        data = request.get_json()
        captcha_response = data.get('captcha_response')
        
        if not captcha_response:
            return jsonify({"status": "failed", "error": "CAPTCHA response is required"}), 400
        
        import requests
        verification_url = 'https://www.google.com/recaptcha/api/siteverify'
        payload = {
            'secret': os.getenv('RECAPTCHA_SECRET_KEY'),
            'response': captcha_response
        }
        response = requests.post(verification_url, data=payload)
        result = response.json()
        
        if result.get('success'):
            return jsonify({'status': 'success'}), 200
        
        return jsonify({
            'status': 'failed', 
            'error': result.get('error-codes', 'Invalid CAPTCHA')
        }), 400
    
    except Exception as e:
        logger.error(f"CAPTCHA verification error: {str(e)}")
        return jsonify({"status": "failed", "error": "CAPTCHA verification failed"}), 500

@app.route('/rooms', methods=['GET'])
@jwt_required()
def list_rooms():
    try:
        username = get_jwt_identity()
        db = next(get_db())
        user = db.query(User).filter_by(username=username).first()
        
        if not user:
            return jsonify({"message": "User not found"}), 404
        
        rooms = Message.get_user_rooms(db, user.id)
        return jsonify(rooms), 200
    
    except Exception as e:
        logger.error(f"Error listing rooms: {str(e)}")
        return jsonify({"message": "An error occurred while retrieving rooms"}), 500

@app.route('/rooms', methods=['POST'])
@jwt_required()
def create_room():
    try:
        data = request.get_json()
        room_name = sanitize_input(data.get('name', ''))
        
        if not room_name:
            return jsonify({"message": "Room name required"}), 400
        
        db = next(get_db())
        username = get_jwt_identity()
        user = db.query(User).filter_by(username=username).first()
        
        if not user:
            return jsonify({"message": "User not found"}), 404
        
        room = Room.create_room(db, room_name)
        Room.add_user_to_room(db, room.id, user.id)
        
        logger.info(f"Room created: {room_name} by {username}")
        return jsonify({
            "message": "Room created",
            "room_id": room.id,
            "room_name": room.name
        }), 201
    
    except Exception as e:
        logger.error(f"Error creating room: {str(e)}")
        return jsonify({"message": "An error occurred while creating the room"}), 500

@app.route('/rooms/<int:room_id>/users', methods=['POST'])
@jwt_required()
def add_user_to_room(room_id):
    try:
        data = request.get_json()
        username_to_add = sanitize_input(data.get('username', ''))
        
        if not username_to_add:
            return jsonify({"message": "Username required"}), 400
        
        db = next(get_db())
        current_username = get_jwt_identity()
        current_user = db.query(User).filter_by(username=current_username).first()
        
        if not current_user:
            return jsonify({"message": "User not found"}), 404
        
        # Check if the current user is in the room
        if not Room.is_user_in_room(db, room_id, current_user.id):
            return jsonify({"message": "You are not a member of this room"}), 403
        
        # Find the user to add
        user_to_add = db.query(User).filter_by(username=username_to_add).first()
        if not user_to_add:
            return jsonify({"message": "User to add not found"}), 404
        
        # Add the user to the room
        if Room.add_user_to_room(db, room_id, user_to_add.id):
            logger.info(f"User {username_to_add} added to room {room_id} by {current_username}")
            return jsonify({"message": f"User {username_to_add} added to the room"}), 200
        else:
            return jsonify({"message": "Failed to add user to room"}), 500
    
    except Exception as e:
        logger.error(f"Error adding user to room: {str(e)}")
        return jsonify({"message": "An error occurred while adding user to room"}), 500

# --- WebSocket Room-based Messaging ---
async def handle_client(websocket, path):
    client_id = str(uuid.uuid4())
    try:
        # Authenticate the client
        token = await websocket.recv()
        try:
            # Verify JWT token
            from flask_jwt_extended.utils import decode_token
            decoded_token = decode_token(token)
            username = decoded_token['sub']  # 'sub' contains the identity (username)
            
            db = next(get_db())
            user_obj = db.query(User).filter(User.username == username).first()
            if not user_obj:
                logger.warning(f"WebSocket authentication failed: User {username} not found")
                await websocket.close(1008, "User not found")
                return
            
            user_id = user_obj.id
            logger.info(f"WebSocket client authenticated: {username}")
        except Exception as e:
            logger.error(f"WebSocket JWT verification failed: {e}")
            await websocket.close(1008, "Authentication failed")
            return

        # Generate key pair for this session
        key_pair = generate_key_pair()
        clients[client_id] = {
            "websocket": websocket,
            "username": username,
            "user_id": user_id,
            "room_id": None,
            "public_key": key_pair['public_key'],
            "private_key": key_pair['private_key'],
            "client_public_key": None  # Will be set when client sends their public key
        }

        # Wait for client's public key
        try:
            message = await websocket.recv()
            data = json.loads(message)
            if data['type'] == 'public_key':
                clients[client_id]['client_public_key'] = data['key']
                logger.info(f"Received public key from {username}")
            else:
                logger.warning(f"Expected public key but received {data['type']} from {username}")
        except Exception as e:
            logger.error(f"Error receiving public key: {e}")
            await websocket.close(1008, "Failed to exchange keys")
            return

        # Send server's public key to client
        await websocket.send(json.dumps({
            'type': 'key_exchange',
            'public_key': key_pair['public_key']
        }))

        # Main message handling loop
        async for message in websocket:
            try:
                data = json.loads(message)
                db = next(get_db())
                
                if data['type'] == 'join_room':
                    room_id = data['room_id']
                    if Room.is_user_in_room(db, room_id, user_id):
                        clients[client_id]['room_id'] = room_id
                        
                        # Add client to room tracking
                        if room_id not in rooms:
                            rooms[room_id] = set()
                        rooms[room_id].add(client_id)
                        
                        # Get room history
                        history = Message.get_room_messages(db, room_id)
                        
                        # Send room history to client
                        for msg in history:
                            # Encrypt the message content with client's public key
                            encrypted_data = hybrid_encrypt(
                                msg['content'],
                                clients[client_id]['client_public_key']
                            )
                            
                            # Create signed message
                            signed_data = json.dumps({
                                'id': msg['id'],
                                'sender': msg['username'],
                                'timestamp': msg['timestamp'].isoformat()
                            })
                            
                            signature = sign_message(
                                clients[client_id]['private_key'],
                                signed_data
                            )
                            
                            # Send encrypted message
                            await websocket.send(json.dumps({
                                'type': 'encrypted_message',
                                'id': msg['id'],
                                'user_id': msg['user_id'],
                                'username': msg['username'],
                                'encrypted_key': encrypted_data['encrypted_key'],
                                'content': encrypted_data['encrypted_message'],
                                'signature': signature,
                                'signed_data': signed_data,
                                'sender_public_key': clients[client_id]['public_key'],
                                'timestamp': msg['timestamp'].isoformat(),
                                'room_id': room_id
                            }))
                        
                        logger.info(f"User {username} joined room {room_id}")
                    else:
                        await websocket.send(json.dumps({
                            'type': 'error',
                            'message': 'You are not a member of this room'
                        }))
                
                elif data['type'] == 'encrypted_message':
                    room_id = clients[client_id]['room_id']
                    if not room_id:
                        await websocket.send(json.dumps({
                            'type': 'error',
                            'message': 'You must join a room first'
                        }))
                        continue
                    
                    # Decrypt the message with server's private key
                    try:
                        encrypted_content = {
                            'encrypted_key': data['encrypted_key'],
                            'encrypted_message': data['content']
                        }
                        
                        decrypted_content = hybrid_decrypt(
                            encrypted_content,
                            clients[client_id]['private_key']
                        )
                        
                        # Save message to database
                        msg_obj = Message.save_message(
                            db,
                            room_id,
                            user_id,
                            decrypted_content
                        )
                        
                        # Set message expiration (5 minutes from now)
                        expiration = (datetime.now() + timedelta(minutes=5)).isoformat()
                        
                        # Broadcast to all clients in the same room
                        if room_id in rooms:
                            for recipient_id in rooms[room_id]:
                                if recipient_id != client_id:  # Don't send back to sender
                                    recipient = clients.get(recipient_id)
                                    if recipient and recipient['websocket'].open:
                                        try:
                                            # Re-encrypt with recipient's public key
                                            recipient_encrypted = hybrid_encrypt(
                                                decrypted_content,
                                                recipient['client_public_key']
                                            )
                                            
                                            # Create signed message data
                                            signed_data = json.dumps({
                                                'id': msg_obj.id,
                                                'content': decrypted_content,
                                                'username': username,
                                                'timestamp': msg_obj.timestamp.isoformat(),
                                                'expiration': expiration
                                            })
                                            
                                            signature = sign_message(
                                                clients[client_id]['private_key'],
                                                signed_data
                                            )
                                            
                                            # Send to recipient
                                            await recipient['websocket'].send(json.dumps({
                                                'type': 'encrypted_message',
                                                'id': msg_obj.id,
                                                'user_id': user_id,
                                                'username': username,
                                                'encrypted_key': recipient_encrypted['encrypted_key'],
                                                'content': recipient_encrypted['encrypted_message'],
                                                'signature': signature,
                                                'signed_data': signed_data,
                                                'sender_public_key': clients[client_id]['public_key'],
                                                'timestamp': msg_obj.timestamp.isoformat(),
                                                'expiration': expiration,
                                                'room_id': room_id
                                            }))
                                        except Exception as e:
                                            logger.error(f"Error sending message to recipient {recipient['username']}: {e}")
                        
                        logger.info(f"Message from {username} in room {room_id} processed")
                    except Exception as e:
                        logger.error(f"Error processing encrypted message: {e}")
                        await websocket.send(json.dumps({
                            'type': 'error',
                            'message': 'Failed to process encrypted message'
                        }))
                
                elif data['type'] == 'encrypted_file':
                    room_id = clients[client_id]['room_id']
                    if not room_id:
                        await websocket.send(json.dumps({
                            'type': 'error',
                            'message': 'You must join a room first'
                        }))
                        continue
                    
                    # Process file transfer (similar to message but with file metadata)
                    filename = data.get('filename', 'unknown_file')
                    filesize = data.get('filesize', 0)
                    
                    # Save file metadata to database
                    file_msg = Message.save_message(
                        db,
                        room_id,
                        user_id,
                        f"[FILE] {filename} ({filesize} bytes)"
                    )
                    
                    # Set file expiration (30 minutes from now)
                    expiration = (datetime.now() + timedelta(minutes=30)).isoformat()
                    
                    # Broadcast to all clients in the same room
                    if room_id in rooms:
                        for recipient_id in rooms[room_id]:
                            if recipient_id != client_id:  # Don't send back to sender
                                recipient = clients.get(recipient_id)
                                if recipient and recipient['websocket'].open:
                                    try:
                                        # Forward the encrypted file data
                                        # Note: We don't decrypt/re-encrypt the file on the server
                                        # to avoid memory issues with large files
                                        
                                        # Create signed file metadata
                                        signed_data = json.dumps({
                                            'id': file_msg.id,
                                            'filename': filename,
                                            'filesize': filesize,
                                            'username': username,
                                            'timestamp': file_msg.timestamp.isoformat(),
                                            'expiration': expiration
                                        })
                                        
                                        signature = sign_message(
                                            clients[client_id]['private_key'],
                                            signed_data
                                        )
                                        
                                        # Send to recipient
                                        await recipient['websocket'].send(json.dumps({
                                            'type': 'encrypted_file',
                                            'id': file_msg.id,
                                            'user_id': user_id,
                                            'username': username,
                                            'encrypted_key': data['encrypted_key'],
                                            'iv': data['iv'],
                                            'tag': data['tag'],
                                            'ciphertext': data['ciphertext'],
                                            'filename': filename,
                                            'filesize': filesize,
                                            'signature': signature,
                                            'signed_data': signed_data,
                                            'sender_public_key': clients[client_id]['public_key'],
                                            'timestamp': file_msg.timestamp.isoformat(),
                                            'expiration': expiration,
                                            'room_id': room_id
                                        }))
                                    except Exception as e:
                                        logger.error(f"Error sending file to recipient {recipient['username']}: {e}")
                    
                    logger.info(f"File {filename} from {username} in room {room_id} processed")
            
            except json.JSONDecodeError:
                logger.error(f"Invalid JSON received from {username}")
                await websocket.send(json.dumps({
                    'type': 'error',
                    'message': 'Invalid message format'
                }))
            except Exception as e:
                logger.error(f"Error processing message from {username}: {e}")
                await websocket.send(json.dumps({
                    'type': 'error',
                    'message': 'Server error processing message'
                }))
    
    except websockets.exceptions.ConnectionClosed:
        logger.info(f"WebSocket connection closed for {clients.get(client_id, {}).get('username', 'unknown')}")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        # Clean up client resources
        client_info = clients.pop(client_id, None)
        if client_info and client_info.get('room_id'):
            room_id = client_info['room_id']
            if room_id in rooms:
                rooms[room_id].discard(client_id)
                # Remove room if empty
                if not rooms[room_id]:
                    rooms.pop(room_id, None)

async def main():
    # Create SSL context for secure WebSocket (wss://)
    ssl_context = None
    cert_file = os.getenv('SSL_CERT_FILE')
    key_file = os.getenv('SSL_KEY_FILE')
    
    if cert_file and key_file and os.path.exists(cert_file) and os.path.exists(key_file):
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(cert_file, key_file)
        logger.info("SSL/TLS enabled for WebSocket server")
    else:
        logger.warning("SSL/TLS not configured. WebSocket server running in insecure mode.")
    
    # Start WebSocket server
    start_server = await websockets.serve(
        handle_client, 
        "0.0.0.0",  # Listen on all interfaces
        8765,
        ssl=ssl_context
    )
    
    logger.info("WebSocket server started on port 8765")
    await start_server.wait_closed()

if __name__ == '__main__':
    # Run Flask app in a separate thread
    import threading
    
    def run_flask():
        app.run(host="0.0.0.0", port=5000, debug=False)
    
    flask_thread = threading.Thread(target=run_flask)
    flask_thread.daemon = True
    flask_thread.start()
    
    # Run WebSocket server in the main thread
    logger.info("Starting secure communication server")
    asyncio.run(main())
