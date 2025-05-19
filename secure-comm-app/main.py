# main.py
from kivymd.app import MDApp
from kivy.uix.screenmanager import ScreenManager, Screen
from kivymd.uix.dialog import MDDialog
from kivy.lang import Builder
from kivy.core.window import Window
from security import generate_key_pair, encrypt_message, decrypt_message, sign_message, verify_signature
from chat_service import ChatService
import asyncio
import threading
import jwt
from models.user import User
from models.room import Room
from database import Base, engine, get_db
from sqlalchemy.orm import Session

from sqlalchemy.orm import Session
from database import Base, engine

class LoginScreen(Screen):
    def login(self):
        # Retrieve input values
        username = self.ids.login_username.text.strip()
        password = self.ids.login_password.text.strip()

        # Validate credentials
        if not username or not password:
            MDDialog(
                title="Login Failed",
                text="Username and password cannot be empty."
            ).open()
            return

        # Check if user exists in the database
        db: Session = next(get_db())
        user = User.authenticate(db, username, password)
        if user:
            # Generate JWT token
            # Use user's secret key or a default if not set
            secret_key = user.secret_key if user.secret_key else 'your_secret_key'
            token = self.generate_jwt_token(username, secret_key)
            
            # Pass token and username to chat screen
            chat_screen = self.manager.get_screen('chat')
            if hasattr(chat_screen, 'set_token_and_user'):
                chat_screen.set_token_and_user(token, username)
            else:
                # If method doesn't exist, store directly in app
                app = MDApp.get_running_app()
                app.token = token
                app.username = username
            
            # Navigate to chat screen
            self.manager.current = 'chat'
        else:
            # Show error dialog for invalid credentials
            MDDialog(
                title="Login Failed",
                text="Invalid username or password. Please try again."
            ).open()
            
    def generate_jwt_token(self, username, secret_key):
        """Generate a JWT token for the user"""
        payload = {'user': username}
        return jwt.encode(payload, secret_key, algorithm='HS256')

class RegisterScreen(Screen):
    dialog = None
    def register(self):
        # Validate registration fields
        email = self.ids.register_email.text.strip()
        username = self.ids.register_username.text.strip()
        password = self.ids.register_password.text.strip()
        confirm_password = self.ids.register_confirm_password.text.strip() if 'register_confirm_password' in self.ids else password

        def show_dialog(title, text):
            if self.dialog:
                self.dialog.dismiss()
            self.dialog = MDDialog(title=title, text=text)
            self.dialog.open()

        if not email or not username or not password:
            show_dialog("Registration Failed", "All fields are required.")
            return
        if password != confirm_password:
            show_dialog("Registration Failed", "Passwords do not match.")
            return
        # Send registration data to backend
        try:
            import requests
            response = requests.post(
                "http://localhost:8765/register",
                json={"email": email, "username": username, "password": password}
            )
            if response.status_code == 201:
                show_dialog("Registration Successful", "You can now log in!")
                self.manager.current = 'login'
            else:
                msg = response.json().get("message", "Registration failed.")
                show_dialog("Registration Failed", msg)
        except Exception as e:
            show_dialog("Error", f"Could not connect to server: {e}")

class ForgotPasswordScreen(Screen):
    def reset_password(self): 
        username = self.ids.username_field.text.strip()
        if not username:
            MDDialog(
                title="Reset Password Failed",
                text="Username is required."
            ).open()
            return
        
        # Logic to handle password reset (e.g., send email)
        print(f"Password reset requested for {username}. Instructions sent to email.")
        self.manager.current = 'login'

class ChatScreen(Screen):
    def __init__(self, **kwargs):
        super(ChatScreen, self).__init__(**kwargs)
        self.token = None
        self.username = None
        
    def set_token_and_user(self, token, username):
        """Set the JWT token and username for this screen"""
        self.token = token
        self.username = username
        
    def update_chat_history(self, messages, security):
        """Update the chat display with decrypted messages."""
        chat_text = ""
        for msg in messages:
            if msg['type'] == 'message':
                # Check if content is directly available or needs decryption
                if 'content' in msg:
                    content = msg['content']
                elif 'data' in msg and hasattr(security, 'decrypt_message'):
                    content = security.decrypt_message(msg['data'])
                else:
                    content = "[Encrypted message]"
                chat_text += f"{msg['sender']}: {content}\n"
            elif msg['type'] == 'file':
                chat_text += f"{msg['sender']} sent file: {msg.get('filename', 'unknown')}\n"
        
        # Check if chat_label exists in the ids
        if hasattr(self.ids, 'chat_label'):
            self.ids.chat_label.text = chat_text
        elif hasattr(self.ids, 'chat_bubbles'):
            # If using chat bubbles instead of a label
            self.ids.chat_bubbles.clear_widgets()
            for msg in messages:
                # Add chat bubbles for each message
                pass

class SecureCommApp(MDApp):
    def build(self):
        Window.size = (800, 600)
        self.theme_cls.theme_style = "Dark"  # Optional: Dark theme
        
        # Generate key pair for encryption and store it in a way that's accessible
        self.security = generate_key_pair()  # This returns a dictionary with 'private_key' and 'public_key'
        
        # Add get_public_key method to the security object for compatibility
        self.security.get_public_key = lambda: self.security['public_key']
        
        # Initialize database tables
        Base.metadata.create_all(bind=engine)
        
        # Initialize models (no longer need separate instances)
        self.chat_service = ChatService("ws://localhost:8765")  # Replace with wss:// for TLS
        self.file_picker = None  # Placeholder for file picker
        self.user = None
        self.token = None
        self.username = None
        
        Builder.load_file('gui.kv')
        self.root = ScreenManager()
        self.root.add_widget(LoginScreen(name='login'))
        self.root.add_widget(RegisterScreen(name='register'))
        self.root.add_widget(ForgotPasswordScreen(name='forgot_password'))
        self.root.add_widget(ChatScreen(name='chat'))
        return self.root
    def on_start(self):
        # Load user data if needed
        pass
    def on_stop(self):
        # Cleanup resources
        if self.chat_service.websocket:
            asyncio.run(self.chat_service.websocket.close())
        pass
    def on_file_picker(self, file_path):
        """Handle file selection from file picker."""
        self.file_picker = file_path
        print(f"File selected: {file_path}")
    def on_file_dismiss(self, *args):
        """Handle file picker dismissal."""
        self.file_picker = None
        print("File picker dismissed.")
    def on_file_select(self, *args):
        """Handle file selection."""
        if self.file_picker:
            self.send_file()
        else:
            print("No file selected.")
    def on_file_cancel(self, *args):
        """Handle file selection cancellation."""
        self.file_picker = None
        print("File selection cancelled.")
        

    def login(self):
        username = self.root.get_screen('login').ids.login_username.text
        password = self.root.get_screen('login').ids.login_password.text
        try:
            token = self.chat_service.login(username, password)
            # Get user from database
            db: Session = next(get_db())
            user = User.get_by_username(db, username)
            self.user = user
            asyncio.run(self.chat_service.connect(token, self.security))
            self.root.current = 'chat'
            threading.Thread(target=self.run_async_loop, daemon=True).start()
        except Exception as e:
            print(f"Login error: {e}")

    def register(self):
        # Simplified registration (add server call in production)
        self.root.current = 'login'

    def generate_jwt_token(self, username, secret_key):
        payload = {'user': username}
        return jwt.encode(payload, secret_key, algorithm='HS256')
    
    def send_message(self):
        message = self.root.get_screen('chat').ids.message_input.text.strip()
        if message:
            # Make sure we have a user object
            if not self.user:
                # Try to get the user from the database
                username = self.username or self.root.get_screen('chat').username
                if username:
                    db = next(get_db())
                    self.user = User.get_by_username(db, username)
                else:
                    MDDialog(
                        title="Error",
                        text="You need to log in first."
                    ).open()
                    return
            
            # Simulated recipient public key (replace with actual key exchange)
            recipient_public_key = self.security.get_public_key()
            asyncio.run(self.chat_service.send_message(self.user, message, self.security, recipient_public_key))
            self.root.get_screen('chat').ids.message_input.text = ''
            self.update_chat()

    def send_file(self):
        file_path = self.file_picker  # Use the file picker to select a file
        if not file_path:
            print("No file selected.")
            MDDialog(
                title="Error",
                text="No file selected. Please select a file first."
            ).open()
            return
            
        # Make sure we have a user object
        if not self.user:
            # Try to get the user from the database
            username = self.username or self.root.get_screen('chat').username
            if username:
                db = next(get_db())
                self.user = User.get_by_username(db, username)
            else:
                MDDialog(
                    title="Error",
                    text="You need to log in first."
                ).open()
                return
                
        recipient_public_key = self.security.get_public_key()
        try:
            asyncio.run(self.chat_service.send_file(self.user, file_path, self.security, recipient_public_key))
            self.update_chat()
        except Exception as e:
            print(f"Error sending file: {e}")
            MDDialog(
                title="Error",
                text=f"Error sending file: {e}"
            ).open()

    def update_chat(self):
        self.root.get_screen('chat').update_chat_history(self.chat_service.get_messages(), self.security)

    def run_async_loop(self):
        asyncio.run(self.async_update())

    async def async_update(self):
        while True:
            await asyncio.sleep(1)
            self.update_chat()

if __name__ == "__main__":
    SecureCommApp().run()
