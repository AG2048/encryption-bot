#!/usr/bin/env python3
"""
Simple launcher script for the encryption bot with environment loading
"""

import os
import sys
from pathlib import Path

def load_env_file():
    """Load environment variables from .env file if it exists"""
    env_file = Path(".env")
    if env_file.exists():
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        os.environ[key] = value
        print("✓ Loaded environment variables from .env file")
    else:
        print("ℹ️  No .env file found, using system environment variables")

def main():
    print("🔒 Encryption Bot Launcher")
    print("=" * 30)
    
    # Load environment variables
    load_env_file()
    
    # Check for bot token
    token = os.getenv('DISCORD_BOT_TOKEN')
    if not token:
        print("❌ Error: DISCORD_BOT_TOKEN environment variable not set")
        print("\nPlease either:")
        print("1. Create a .env file with: DISCORD_BOT_TOKEN=your_token_here")
        print("2. Set the environment variable: export DISCORD_BOT_TOKEN=your_token_here")
        return 1
    
    print(f"✓ Bot token found (length: {len(token)} characters)")
    
    # Import and start the bot
    try:
        from bot import bot
        print("✓ Bot module loaded successfully")
        print("🚀 Starting bot...")
        bot.run(token)
    except ImportError as e:
        print(f"❌ Error importing bot module: {e}")
        return 1
    except Exception as e:
        print(f"❌ Error starting bot: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())