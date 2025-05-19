# chat_service.py
import asyncio
import websockets
import json
import requests
from datetime import datetime
import os
from security import hybrid_encrypt, hybrid_decrypt, encrypt_file, decrypt_file


class ChatService:
    def __init__(self, server_url="ws://localhost:8765"):
        self.server_url = server_url
        self.messages = []
        self.websocket = None
        self.group_chats = {}  # Dictionary to hold group chat information
        self.security_context = None  # Will hold security keys and context

    async def connect(self, token, security):
        """Connect to the WebSocket server and send the JWT token."""
        try:
            # Store security context for later use
            self.security_context = security
            
            # Connect to WebSocket server with TLS if using wss://
            if self.server_url.startswith("wss://"):
                self.websocket = await websockets.connect(
                    self.server_url,
                    ssl=True  # Enable SSL/TLS
                )
            else:
                self.websocket = await websockets.connect(self.server_url)
            
            # Send authentication token
            await self.websocket.send(token)
            
            # Send public key to server for secure key exchange
            # Check if security is a dict or an object with get_public_key method
            if isinstance(security, dict) and 'public_key' in security:
                public_key = security['public_key']
            elif hasattr(security, 'get_public_key'):
                public_key = security.get_public_key()
            else:
                # Fallback if security object doesn't have the expected structure
                raise ValueError("Security object doesn't have a valid public key")
                
            await self.websocket.send(json.dumps({
                "type": "public_key", 
                "key": public_key
            }))
            
            # Start listening for messages
            asyncio.create_task(self.listen())
            return True
        except Exception as e:
            print(f"Connection error: {e}")
            return False

    async def listen(self):
        """Listen for incoming messages/files."""
        while True:
            try:
                if not self.websocket:
                    print("WebSocket connection lost. Attempting to reconnect...")
                    # Implement reconnection logic here
                    break
                
                message = await self.websocket.recv()
                data = json.loads(message)

                # Check if the message has expired
                if 'expiration' in data:
                    expiration_time = datetime.fromisoformat(data['expiration'])
                    if datetime.now() > expiration_time:
                        print("Message has expired and will not be processed.")
                        continue  # Skip processing the expired message

                # Verify message signature if present
                if 'signature' in data and 'signed_data' in data and 'sender_public_key' in data:
                    from security import verify_signature
                    is_valid = verify_signature(
                        data['sender_public_key'],
                        data['signed_data'],
                        data['signature']
                    )
                    if not is_valid:
                        print("Message signature verification failed. Possible tampering detected.")
                        continue  # Skip this message as it failed verification

                # Process different message types
                if data['type'] == 'encrypted_message':
                    # Decrypt the message content
                    try:
                        encrypted_content = {
                            'encrypted_key': data['encrypted_key'],
                            'encrypted_message': data['content']
                        }
                        data['decrypted_content'] = hybrid_decrypt(
                            encrypted_content,
                            self.security_context['private_key']
                        )
                    except Exception as e:
                        print(f"Failed to decrypt message: {e}")
                        data['decrypted_content'] = "[Encrypted message - decryption failed]"
                
                elif data['type'] == 'encrypted_file':
                    # Store encrypted file data for later decryption when accessed
                    data['file_data'] = {
                        'encrypted_key': data['encrypted_key'],
                        'iv': data['iv'],
                        'tag': data['tag'],
                        'ciphertext': data['ciphertext']
                    }
                
                # Add the processed message to our message list
                self.messages.append(data)
                
                # If this is a group message, also add to the appropriate group chat
                if 'group_id' in data and data['group_id']:
                    group_id = data['group_id']
                    if group_id not in self.group_chats:
                        self.group_chats[group_id] = []
                    self.group_chats[group_id].append(data)

            except websockets.exceptions.ConnectionClosed:
                print("WebSocket connection closed")
                break
            except Exception as e:
                print(f"WebSocket error: {e}")
                continue

    async def send_message(self, user, message, security, recipient_public_key, group_id=None):
        """Send an encrypted message using hybrid encryption."""
        try:
            # Use hybrid encryption (RSA + AES) for better performance with larger messages
            encrypted_data = hybrid_encrypt(message, recipient_public_key)
            
            # Prepare message payload
            payload = {
                "type": "encrypted_message",
                "encrypted_key": encrypted_data['encrypted_key'],
                "content": encrypted_data['encrypted_message'],
                "sender": user.username,
                "timestamp": datetime.now().isoformat(),
                "group_id": group_id
            }
            
            # Sign the message for integrity verification
            from security import sign_message
            signed_data = json.dumps({
                "content": message,
                "sender": user.username,
                "timestamp": payload["timestamp"]
            })
            signature = sign_message(security['private_key'], signed_data)
            
            # Add signature and signed data to payload
            payload["signature"] = signature
            payload["signed_data"] = signed_data
            payload["sender_public_key"] = security['public_key']
            
            # Send the encrypted message
            await self.websocket.send(json.dumps(payload))
            
            # Add to local message store for UI display
            self.messages.append({
                "type": "message",
                "sender": user.username,
                "content": message,  # Store unencrypted for local display
                "timestamp": payload["timestamp"],
                "group_id": group_id
            })
            
            # Update group chat if applicable
            if group_id:
                if group_id in self.group_chats:
                    self.group_chats[group_id].append({
                        'sender': user.username, 
                        'content': message,
                        'timestamp': payload["timestamp"]
                    })
                else:
                    self.group_chats[group_id] = [{
                        'sender': user.username, 
                        'content': message,
                        'timestamp': payload["timestamp"]
                    }]
            
            return True
        except Exception as e:
            print(f"Error sending message: {e}")
            return False

    async def send_file(self, user, file_path, security, recipient_public_key, group_id=None):
        """Send an encrypted file."""
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")
            
            # Get file name and size
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            
            # Check if file is too large (e.g., > 50MB)
            max_size = 50 * 1024 * 1024  # 50MB
            if file_size > max_size:
                raise ValueError(f"File too large: {file_size} bytes. Maximum allowed: {max_size} bytes")
            
            # Encrypt the file using hybrid encryption
            encrypted_data = encrypt_file(file_path, recipient_public_key)
            
            # Prepare file transfer payload
            payload = {
                "type": "encrypted_file",
                "encrypted_key": encrypted_data['encrypted_key'],
                "iv": encrypted_data['iv'],
                "tag": encrypted_data['tag'],
                "ciphertext": encrypted_data['ciphertext'],
                "sender": user.username,
                "filename": file_name,
                "filesize": file_size,
                "timestamp": datetime.now().isoformat(),
                "group_id": group_id
            }
            
            # Sign the file metadata for integrity verification
            from security import sign_message
            signed_data = json.dumps({
                "filename": file_name,
                "filesize": file_size,
                "sender": user.username,
                "timestamp": payload["timestamp"]
            })
            signature = sign_message(security['private_key'], signed_data)
            
            # Add signature and signed data to payload
            payload["signature"] = signature
            payload["signed_data"] = signed_data
            payload["sender_public_key"] = security['public_key']
            
            # Send the encrypted file
            await self.websocket.send(json.dumps(payload))
            
            # Add to local message store for UI display
            self.messages.append({
                "type": "file",
                "sender": user.username,
                "filename": file_name,
                "filesize": file_size,
                "timestamp": payload["timestamp"],
                "group_id": group_id
            })
            
            # Update group chat if applicable
            if group_id and group_id in self.group_chats:
                self.group_chats[group_id].append({
                    'sender': user.username, 
                    'type': 'file',
                    'filename': file_name,
                    'timestamp': payload["timestamp"]
                })
            
            return True
        except Exception as e:
            print(f"Error sending file: {e}")
            return False

    def save_received_file(self, message_id, save_path):
        """Save a received encrypted file to disk after decryption."""
        try:
            # Find the file message by ID
            file_message = None
            for msg in self.messages:
                if msg.get('id') == message_id and msg.get('type') == 'encrypted_file':
                    file_message = msg
                    break
            
            if not file_message:
                raise ValueError(f"File message with ID {message_id} not found")
            
            # Decrypt the file
            file_data = decrypt_file(
                file_message['file_data'],
                self.security_context['private_key']
            )
            
            # Ensure the directory exists
            os.makedirs(os.path.dirname(os.path.abspath(save_path)), exist_ok=True)
            
            # Save the decrypted file
            with open(save_path, 'wb') as f:
                f.write(file_data)
            
            return True
        except Exception as e:
            print(f"Error saving file: {e}")
            return False

    def get_messages(self, group_id=None, limit=50):
        """Get messages, optionally filtered by group ID."""
        if group_id:
            return self.group_chats.get(group_id, [])[:limit]
        return self.messages[-limit:] if len(self.messages) > limit else self.messages

    def login(self, username, password):
        """Authenticate with the Flask server and get a JWT token."""
        try:
            response = requests.post(
                f"{self.server_url.replace('ws://', 'http://').replace('wss://', 'https://')}/login", 
                json={"username": username, "password": password},
                timeout=10  # Set a timeout for the request
            )
            
            if response.status_code == 200:
                return response.json()["access_token"]
            else:
                error_msg = response.json().get("message", "Unknown error")
                raise Exception(f"Login failed: {error_msg}")
        except requests.exceptions.RequestException as e:
            raise Exception(f"Connection error: {e}")
        except Exception as e:
            raise Exception(f"Login failed: {e}")

    def create_group(self, user, group_name):
        """Create a new chat group."""
        try:
            response = requests.post(
                f"{self.server_url.replace('ws://', 'http://').replace('wss://', 'https://')}/rooms",
                json={"name": group_name},
                headers={"Authorization": f"Bearer {user.token}"},
                timeout=10
            )
            
            if response.status_code == 201:
                return response.json()["room_id"]
            else:
                error_msg = response.json().get("message", "Unknown error")
                raise Exception(f"Failed to create group: {error_msg}")
        except Exception as e:
            print(f"Error creating group: {e}")
            return None

    def get_groups(self, user):
        """Get all groups the user is a member of."""
        try:
            response = requests.get(
                f"{self.server_url.replace('ws://', 'http://').replace('wss://', 'https://')}/rooms",
                headers={"Authorization": f"Bearer {user.token}"},
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                error_msg = response.json().get("message", "Unknown error")
                raise Exception(f"Failed to get groups: {error_msg}")
        except Exception as e:
            print(f"Error getting groups: {e}")
            return []

    async def join_group(self, user, group_id):
        """Join a chat group."""
        try:
            payload = {
                "type": "join_room",
                "room_id": group_id
            }
            
            await self.websocket.send(json.dumps(payload))
            return True
        except Exception as e:
            print(f"Error joining group: {e}")
            return False
