import os
from dotenv import load_dotenv

def load_environment_variables():
    """Load environment variables from .env file"""
    # Load environment variables from .env file
    load_dotenv()
    
    # Check if required environment variables are set
    required_vars = ['SECRET_KEY', 'JWT_SECRET_KEY', 'DATABASE_URL', 'CHAT_DATABASE_URL']
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        print(f"Warning: The following environment variables are not set: {', '.join(missing_vars)}")
        print("Using default values for missing variables.")
    
    # Set default values for missing variables
    if not os.getenv('SECRET_KEY'):
        os.environ['SECRET_KEY'] = 'default_secret_key'
    
    if not os.getenv('JWT_SECRET_KEY'):
        os.environ['JWT_SECRET_KEY'] = 'default_jwt_secret_key'
    
    if not os.getenv('DATABASE_URL'):
        os.environ['DATABASE_URL'] = 'sqlite:///users.db'
    
    if not os.getenv('CHAT_DATABASE_URL'):
        os.environ['CHAT_DATABASE_URL'] = 'sqlite:///chat.db'
    
    print("Environment variables loaded successfully.")

if __name__ == "__main__":
    load_environment_variables()