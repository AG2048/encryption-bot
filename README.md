# Encryption Bot

A Discord bot that provides end-to-end encryption for messages using RSA encryption and digital signatures.

## Features

- **Message Encryption**: Encrypt messages for specific users using their public keys
- **Digital Signatures**: All encrypted messages are signed with the sender's private key for authenticity
- **Automatic Key Generation**: RSA-2048 key pairs are automatically generated for users when first needed
- **Secure Key Storage**: Private keys are stored securely in individual user directories
- **Base64 Encoding**: All encrypted data is encoded in base64 for easy transmission
- **Context Menu Decryption**: Right-click on encrypted messages to decrypt them
- **Public Key Sharing**: Get any user's public key for verification or external encryption

## Commands

### Slash Commands

- `/encrypt <message> <receiver>` - Encrypt a message for a specific user
- `/publickey <user>` - Get a user's public key

### Context Menu

- Right-click on any encrypted message → "Decrypt Message" - Decrypt and verify a message (only works if you're the intended recipient)

## Setup

1. Install Python 3.8 or higher
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Create a Discord application and bot at https://discord.com/developers/applications
4. Copy `.env.example` to `.env` and add your bot token:
   ```
   DISCORD_BOT_TOKEN=your_bot_token_here
   ```
5. Run the bot:
   ```bash
   python bot.py
   ```

## How it Works

1. **Key Generation**: When a user is first mentioned in an encrypt command or their public key is requested, the bot generates a 2048-bit RSA key pair and stores it in the `keys/` directory.

2. **Encryption Process**:
   - Message is encrypted with the recipient's public key using OAEP padding
   - Encrypted message is signed with the sender's private key using PSS padding
   - Both encrypted message and signature are combined and encoded in base64

3. **Decryption Process**:
   - Base64 data is decoded and split into encrypted message and signature
   - Signature is verified using the sender's public key
   - Message is decrypted using the recipient's private key
   - Only successful if both verification and decryption succeed

## Security Features

- **RSA-2048 Encryption**: Industry-standard encryption strength
- **OAEP Padding**: Optimal Asymmetric Encryption Padding for secure encryption
- **PSS Signatures**: Probabilistic Signature Scheme for tamper detection
- **SHA-256 Hashing**: Cryptographically secure hash function
- **Private Key Protection**: Keys are stored locally and never transmitted
- **Forward Secrecy**: Each message uses the full strength of RSA encryption

## File Structure

```
encryption-bot/
├── bot.py              # Main bot code
├── requirements.txt    # Python dependencies
├── .env.example       # Environment variable template
├── .gitignore         # Git ignore file
├── README.md          # This file
└── keys/              # User key storage (created automatically)
    └── <user_id>/
        ├── private_key.pem
        └── public_key.pem
```

## Usage Example

1. Alice wants to send an encrypted message to Bob:
   ```
   /encrypt "Hello Bob, this is a secret message!" @Bob
   ```

2. Bot generates keys for both users (if needed) and posts an encrypted message embed

3. Bob right-clicks on the encrypted message and selects "Decrypt Message"

4. Bot verifies Alice's signature and decrypts the message for Bob (shown only to Bob)

## Important Notes

- Private keys are stored locally in the `keys/` directory and should be kept secure
- The bot needs to be running and accessible to decrypt messages
- Users can only decrypt messages intended for them
- All encrypted messages include a digital signature for authenticity verification
- The bot automatically generates new key pairs for users when first needed
