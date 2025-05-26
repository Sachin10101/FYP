import PyInstaller.__main__
import sys
import os

def build_app():
    args = [
        'main.py',
        '--onefile',
        '--windowed',
        '--name=SecureChat',
        '--icon=assets/icon.ico',
        '--add-data=gui.kv:.',
    ]
    
    # Add platform-specific options
    if sys.platform.startswith('win'):
        args.extend(['--add-binary=SDL2.dll;.'])
    elif sys.platform.startswith('darwin'):
        args.extend(['--add-binary=/usr/local/opt/sdl2/lib/libSDL2.dylib:.'])
    
    PyInstaller.__main__.run(args)

if __name__ == '__main__':
    build_app()