#!/usr/bin/env python3
import requests

def register_user():
    register_url = "http://localhost:12000/register"
    register_data = {
        "email": "testuser5@example.com",
        "username": "testuser5",
        "password": "TestPassword123!"
    }
    
    print("Registering user...")
    response = requests.post(register_url, json=register_data)
    print(f"Status code: {response.status_code}")
    print(f"Response: {response.text}")
    
    if response.status_code == 201:
        print("User registered successfully!")
        
        # Try to login
        login_url = "http://localhost:12000/login"
        login_data = {
            "username": "testuser5",
            "password": "TestPassword123!"
        }
        
        print("\nLogging in...")
        response = requests.post(login_url, json=login_data)
        print(f"Status code: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 200:
            print("Login successful!")
            token = response.json()["access_token"]
            print(f"Token: {token[:20]}...")
            
            # Create a room
            create_room_url = "http://localhost:12000/rooms"
            room_data = {"name": "Test Room 4"}
            headers = {"Authorization": f"Bearer {token}"}
            
            print("\nCreating room...")
            response = requests.post(create_room_url, json=room_data, headers=headers)
            print(f"Status code: {response.status_code}")
            print(f"Response: {response.text}")
            
            if response.status_code == 201:
                print("Room created successfully!")
                room_id = response.json()["room_id"]
                
                # Get rooms
                get_rooms_url = "http://localhost:12000/rooms"
                
                print("\nGetting rooms...")
                response = requests.get(get_rooms_url, headers=headers)
                print(f"Status code: {response.status_code}")
                print(f"Response: {response.text}")
                
                # Add testuser to the room
                add_user_url = f"http://localhost:12000/rooms/{room_id}/users"
                add_user_data = {"username": "testuser"}
                
                print("\nAdding testuser to room...")
                response = requests.post(add_user_url, json=add_user_data, headers=headers)
                print(f"Status code: {response.status_code}")
                print(f"Response: {response.text}")
                
                if response.status_code == 200:
                    print("User added to room successfully!")
                else:
                    print("Failed to add user to room")
            else:
                print("Failed to create room")
        else:
            print("Login failed")
    else:
        print("Registration failed")

if __name__ == "__main__":
    register_user()