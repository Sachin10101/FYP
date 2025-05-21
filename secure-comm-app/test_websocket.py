#!/usr/bin/env python3
import asyncio
import websockets
import json
import requests
import base64
from security import generate_key_pair, hybrid_encrypt, sign_message

async def test_websocket():
    # Login to get JWT token
    login_url = "http://localhost:12000/login"
    login_data = {"username": "testuser5", "password": "TestPassword123!"}
    
    print("Logging in...")
    response = requests.post(login_url, json=login_data)
    if response.status_code != 200:
        print(f"Login failed: {response.text}")
        return
    
    token = response.json()["access_token"]
    print(f"Login successful, token: {token[:20]}...")
    
    # Generate key pair for encryption
    print("Generating key pair...")
    security = generate_key_pair()
    
    # Connect to WebSocket server
    print("Connecting to WebSocket server...")
    async with websockets.connect("ws://localhost:12001") as websocket:
        # Send authentication token
        await websocket.send(token)
        
        # Send public key to server
        await websocket.send(json.dumps({
            "type": "public_key", 
            "key": security["public_key"]
        }))
        
        # Wait for server response
        response = await websocket.recv()
        print(f"Server response: {response}")
        
        # Join a room (Test Room 3, id=3)
        room_id = 3
        await websocket.send(json.dumps({
            "type": "join_room",
            "room_id": room_id
        }))
        
        # Wait for join confirmation
        response = await websocket.recv()
        print(f"Join room response: {response}")
        
        # Send a test message
        message = "Hello, this is a test message from testuser!"
        
        # Get server's public key from the join response
        join_response = json.loads(response)
        server_public_key = join_response.get("server_public_key")
        
        if not server_public_key:
            print("Error: Server public key not received")
            return
        
        # Encrypt the message with server's public key
        encrypted_data = hybrid_encrypt(message, server_public_key)
        
        # Sign the message
        signed_data = json.dumps({
            "content": message,
            "sender": "testuser4",
            "timestamp": "2025-05-21T11:45:00"
        })
        signature = sign_message(security["private_key"], signed_data)
        
        # Send encrypted message
        await websocket.send(json.dumps({
            "type": "encrypted_message",
            "encrypted_key": encrypted_data["encrypted_key"],
            "content": encrypted_data["encrypted_message"],
            "sender": "testuser4",
            "timestamp": "2025-05-21T11:45:00",
            "signature": signature,
            "signed_data": signed_data,
            "sender_public_key": security["public_key"]
        }))
        
        # Wait for message confirmation
        try:
            response = await asyncio.wait_for(websocket.recv(), timeout=5)
            print(f"Message response: {response}")
        except asyncio.TimeoutError:
            print("Timeout waiting for message response")
        
        print("Test completed")

if __name__ == "__main__":
    asyncio.run(test_websocket())