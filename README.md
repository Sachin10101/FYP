# Secure Communication Application

This is a secure communication application that allows users to send encrypted messages and files to each other.

## Prerequisites

- Python 3.8 or higher
- Required system libraries for SDL2 (for GUI)
- Required Python packages (see requirements.txt)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Sachin10101/FYP.git
cd FYP
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install the required packages:
```bash
pip install -r requirements.txt
```

4. Install system dependencies (on Ubuntu/Debian):
```bash
sudo apt-get update
sudo apt-get install -y \
    libsdl2-dev \
    libsdl2-image-dev \
    libsdl2-mixer-dev \
    libsdl2-ttf-dev \
    libgl1-mesa-dev \
    libgles2-mesa-dev
```

## Configuration

The application uses environment variables for configuration. You can set these in a `.env` file in the root directory of the project. The following variables are supported:

- `SECRET_KEY`: Secret key for Flask application
- `JWT_SECRET_KEY`: Secret key for JWT tokens
- `DATABASE_URL`: URL for the user database
- `CHAT_DATABASE_URL`: URL for the chat database
- `SERVER_PORT`: Port for the Flask server (default: 12000)
- `WEBSOCKET_PORT`: Port for the WebSocket server (default: 8765)
- `SSL_CERT_FILE`: Path to SSL certificate file (optional)
- `SSL_KEY_FILE`: Path to SSL key file (optional)
- `DEBUG`: Set to 'True' to enable debug mode (default: 'False')
- `GOOGLE_OAUTH_CLIENT_ID`: Google OAuth client ID (optional)
- `GOOGLE_OAUTH_CLIENT_SECRET`: Google OAuth client secret (optional)
- `RECAPTCHA_SECRET_KEY`: reCAPTCHA secret key (optional)
- `API_KEY`: API key for protected endpoints (optional)

## Running the Application

To run the application, use the provided run script:

```bash
python run.py
```

This will start both the server and the client application.

## Features

- End-to-end encryption for messages and files
- User authentication with JWT tokens
- Google OAuth integration (optional)
- reCAPTCHA protection (optional)
- Rate limiting to prevent abuse
- Secure file transfer
- Chat rooms

## Security Features

- End-to-end encryption using hybrid encryption (RSA + AES)
- Digital signatures for message authentication
- Password hashing with bcrypt
- JWT token-based authentication
- Input validation and sanitization
- Rate limiting
- CAPTCHA verification (optional)
- SSL/TLS support (optional)

## License

This project is licensed under the MIT License - see the LICENSE file for details.