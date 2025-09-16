import discord
from discord.ext import commands
import os
from dotenv import load_dotenv
import base64
import asyncio
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

# Create keys directory if it doesn't exist
KEYS_DIR = Path("keys")
KEYS_DIR.mkdir(exist_ok=True)

class PasswordModal(discord.ui.Modal, title='Enter Password'):
    """Modal for entering password for private key operations"""
    
    password = discord.ui.TextInput(
        label='Password',
        placeholder='Enter your private key password...',
        style=discord.TextStyle.short,
        max_length=256,
        required=True
    )
    
    def __init__(self, callback_func, *args, **kwargs):
        super().__init__(title='Enter Password')
        self.callback_func = callback_func
        self.args = args
        self.kwargs = kwargs
    
    async def on_submit(self, interaction: discord.Interaction):
        password = self.password.value
        # interaction is always first arg, the rest should all be passed as kwargs when instantiating PasswordModal
        await self.callback_func(interaction, password=password, *self.args, **self.kwargs)

class RegenerateKeyModal(discord.ui.Modal, title='Regenerate Private Key'):
    """Modal for regenerating private key with optional password"""
    
    password = discord.ui.TextInput(
        label='Password (Optional)',
        placeholder='Enter a password to protect your private key (leave empty for no password)',
        style=discord.TextStyle.short,
        max_length=256,
        required=False
    )
    
    def __init__(self, user_id: int):
        super().__init__()
        self.user_id = user_id
    
    async def on_submit(self, interaction: discord.Interaction):
        password = self.password.value.strip() if self.password.value else None
        
        try:
            await interaction.response.defer(ephemeral=True)
            
            # Generate new keys with optional password
            generate_user_keys(self.user_id, password)
            
            if password:
                await interaction.followup.send(
                    "✅ Your private key has been regenerated with password protection!\n"
                    "⚠️ **IMPORTANT**: Remember your password - it cannot be recovered if lost.\n"
                    "🔒 You will be asked for this password when decrypting messages or signing.",
                    ephemeral=True
                )
            else:
                await interaction.followup.send(
                    "✅ Your private key has been regenerated without password protection.\n"
                    "⚠️ All previously encrypted messages sent to you are now unreadable.",
                    ephemeral=True
                )
                
        except Exception as e:
            if interaction.response.is_done():
                await interaction.followup.send(f"❌ Error regenerating key: {str(e)}", ephemeral=True)
            else:
                await interaction.response.send_message(f"❌ Error regenerating key: {str(e)}", ephemeral=True)

class ConfirmRegenerateView(discord.ui.View):
    """View with confirmation button for key regeneration"""
    
    def __init__(self, user_id: int):
        super().__init__(timeout=300)  # 5 minute timeout
        self.user_id = user_id
    
    @discord.ui.button(label='Confirm Regenerate Key', style=discord.ButtonStyle.danger, emoji='⚠️')
    async def confirm_regenerate(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != self.user_id:
            await interaction.response.send_message("❌ You can only regenerate your own keys.", ephemeral=True)
            return
            
        modal = RegenerateKeyModal(self.user_id)
        await interaction.response.send_modal(modal)
    
    @discord.ui.button(label='Cancel', style=discord.ButtonStyle.secondary)
    async def cancel_regenerate(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != self.user_id:
            await interaction.response.send_message("❌ This is not your regeneration request.", ephemeral=True)
            return
            
        await interaction.response.send_message("❌ Key regeneration cancelled.", ephemeral=True)
        self.stop()

class EncryptionBot(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        intents.message_content = True
        super().__init__(command_prefix='!', intents=intents)
        
    async def setup_hook(self):
        """Called when the bot is starting up"""
        # Sync slash commands
        try:
            synced = await self.tree.sync()
            print(f"Synced {len(synced)} command(s)")
        except Exception as e:
            print(f"Failed to sync commands: {e}")

    async def on_ready(self):
        print(f'{self.user} has connected to Discord!')
        print(f'Bot is in {len(self.guilds)} guild(s)')

bot = EncryptionBot()

def get_user_keys_path(user_id: int) -> tuple[Path, Path]:
    """Get the file paths for a user's private and public keys"""
    user_dir = KEYS_DIR / str(user_id)
    user_dir.mkdir(exist_ok=True)
    private_key_path = user_dir / "private_key.pem"
    public_key_path = user_dir / "public_key.pem"
    return private_key_path, public_key_path

def generate_user_keys(user_id: int, password: str = None) -> tuple[bytes, bytes]:
    """Generate RSA key pair for a user and save to files"""
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Get public key
    public_key = private_key.public_key()
    
    # Serialize private key with or without password
    if password:
        encryption_algorithm = serialization.BestAvailableEncryption(password.encode('utf-8'))
    else:
        encryption_algorithm = serialization.NoEncryption()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm
    )
    
    # Serialize public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Save keys to files
    private_key_path, public_key_path = get_user_keys_path(user_id)
    
    with open(private_key_path, 'wb') as f:
        f.write(private_pem)
    
    with open(public_key_path, 'wb') as f:
        f.write(public_pem)
    
    return private_pem, public_pem

def is_private_key_encrypted(user_id: int) -> bool:
    """Check if a user's private key is password-protected"""
    private_key_path, _ = get_user_keys_path(user_id)
    
    if not private_key_path.exists():
        return False
    
    try:
        with open(private_key_path, 'rb') as f:
            private_pem = f.read()
        
        # Try to load without password
        serialization.load_pem_private_key(
            private_pem, password=None, backend=default_backend()
        )
        return False  # Successfully loaded without password
    except TypeError:
        return True  # Failed to load without password, so it's encrypted

def load_private_key_with_password(user_id: int, password: str = None):
    """Load a private key with optional password"""
    private_key_path, _ = get_user_keys_path(user_id)
    
    if not private_key_path.exists():
        raise ValueError("Private key not found")
    
    with open(private_key_path, 'rb') as f:
        private_pem = f.read()
    
    password_bytes = password.encode('utf-8') if password else None
    
    try:
        return serialization.load_pem_private_key(
            private_pem, password=password_bytes, backend=default_backend()
        )
    except (ValueError, TypeError) as e:
        if password is None:
            raise ValueError("Private key is password-protected but no password provided")
        else:
            raise ValueError("Invalid password for private key")

def load_user_keys(user_id: int) -> tuple[bytes, bytes]:
    """Load user's keys from files, generate if they don't exist"""
    private_key_path, public_key_path = get_user_keys_path(user_id)
    
    if not private_key_path.exists() or not public_key_path.exists():
        return generate_user_keys(user_id)
    
    with open(private_key_path, 'rb') as f:
        private_pem = f.read()
    
    with open(public_key_path, 'rb') as f:
        public_pem = f.read()
    
    return private_pem, public_pem

def encrypt_and_sign_message(message: str, sender_id: int, receiver_id: int) -> str:
    """Encrypt message with receiver's public key and sign with sender's private key (no password support)"""
    # Load sender's private key and receiver's public key
    sender_private_pem, _ = load_user_keys(sender_id)
    _, receiver_public_pem = load_user_keys(receiver_id)
    
    # Load keys
    sender_private_key = serialization.load_pem_private_key(
        sender_private_pem, password=None, backend=default_backend()
    )
    receiver_public_key = serialization.load_pem_public_key(
        receiver_public_pem, backend=default_backend()
    )
    
    # Encrypt the message with receiver's public key
    encrypted_message = receiver_public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Sign the encrypted message with sender's private key
    signature = sender_private_key.sign(
        encrypted_message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    # Combine encrypted message and signature, then encode in base64
    combined = encrypted_message + b"||SIGNATURE||" + signature
    return base64.b64encode(combined).decode('utf-8')

def encrypt_and_sign_message_with_password(message: str, sender_id: int, receiver_id: int, password: str = None) -> str:
    """Encrypt message with receiver's public key and sign with sender's private key (with password support)"""
    # Load sender's private key with password and receiver's public key
    sender_private_key = load_private_key_with_password(sender_id, password)
    _, receiver_public_pem = load_user_keys(receiver_id)
    
    receiver_public_key = serialization.load_pem_public_key(
        receiver_public_pem, backend=default_backend()
    )
    
    # Encrypt the message with receiver's public key
    encrypted_message = receiver_public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Sign the encrypted message with sender's private key
    signature = sender_private_key.sign(
        encrypted_message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    # Combine encrypted message and signature, then encode in base64
    combined = encrypted_message + b"||SIGNATURE||" + signature
    return base64.b64encode(combined).decode('utf-8')

def decrypt_and_verify_message(encrypted_data: str, sender_id: int, receiver_id: int) -> tuple[str, bool]:
    """Decrypt message with receiver's private key and verify signature with sender's public key (no password support)"""
    try:
        # Decode base64
        combined = base64.b64decode(encrypted_data.encode('utf-8'))
        
        # Split encrypted message and signature
        parts = combined.split(b"||SIGNATURE||")
        if len(parts) != 2:
            raise ValueError("Invalid message format")
        
        encrypted_message, signature = parts
        
        # Load receiver's private key and sender's public key
        receiver_private_pem, _ = load_user_keys(receiver_id)
        _, sender_public_pem = load_user_keys(sender_id)
        
        receiver_private_key = serialization.load_pem_private_key(
            receiver_private_pem, password=None, backend=default_backend()
        )
        sender_public_key = serialization.load_pem_public_key(
            sender_public_pem, backend=default_backend()
        )
        
        # Verify signature
        try:
            sender_public_key.verify(
                signature,
                encrypted_message,
                padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            signature_verified = True
        except Exception:
            signature_verified = False
        
        # Decrypt message
        decrypted_message = receiver_private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return decrypted_message.decode('utf-8'), signature_verified
    
    except Exception as e:
        raise ValueError(f"Failed to decrypt message: {str(e)}")

def decrypt_and_verify_message_with_password(encrypted_data: str, sender_id: int, receiver_id: int, password: str = None) -> tuple[str, bool]:
    """Decrypt message with receiver's private key and verify signature with sender's public key (with password support)"""
    try:
        # Decode base64
        combined = base64.b64decode(encrypted_data.encode('utf-8'))
        
        # Split encrypted message and signature
        parts = combined.split(b"||SIGNATURE||")
        if len(parts) != 2:
            raise ValueError("Invalid message format")
        
        encrypted_message, signature = parts
        
        # Load receiver's private key with password and sender's public key
        receiver_private_key = load_private_key_with_password(receiver_id, password)
        _, sender_public_pem = load_user_keys(sender_id)
        
        sender_public_key = serialization.load_pem_public_key(
            sender_public_pem, backend=default_backend()
        )

        # Verify signature
        try:
            sender_public_key.verify(
                signature,
                encrypted_message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            signature_verified = True
        except Exception:
            signature_verified = False
        
        # Decrypt message
        decrypted_message = receiver_private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return decrypted_message.decode('utf-8'), signature_verified
    
    except Exception as e:
        raise ValueError(f"Failed to decrypt message: {str(e)}")

def sign_message(message: str, sender_id: int) -> str:
    """Sign a message with sender's private key and return plaintext + signature (no password support)"""
    # Load sender's private key
    sender_private_pem, _ = load_user_keys(sender_id)
    
    sender_private_key = serialization.load_pem_private_key(
        sender_private_pem, password=None, backend=default_backend()
    )
    
    # Sign the message
    message_bytes = message.encode('utf-8')
    signature = sender_private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    # Combine message and signature, then encode in base64
    combined = message_bytes + b"||SIGNATURE||" + signature
    return base64.b64encode(combined).decode('utf-8')

def sign_message_with_password(message: str, sender_id: int, password: str = None) -> str:
    """Sign a message with sender's private key and return plaintext + signature (with password support)"""
    # Load sender's private key with password
    sender_private_key = load_private_key_with_password(sender_id, password)
    
    # Sign the message
    message_bytes = message.encode('utf-8')
    signature = sender_private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    # Combine message and signature, then encode in base64
    combined = message_bytes + b"||SIGNATURE||" + signature
    return base64.b64encode(combined).decode('utf-8')

def verify_signed_message(signed_data: str, sender_id: int) -> str:
    """Verify a signed message with sender's public key and return the original message"""
    try:
        # Decode base64
        combined = base64.b64decode(signed_data.encode('utf-8'))
        
        # Split message and signature
        parts = combined.split(b"||SIGNATURE||")
        if len(parts) != 2:
            raise ValueError("Invalid signed message format")
        
        message_bytes, signature = parts
        
        # Load sender's public key
        _, sender_public_pem = load_user_keys(sender_id)
        
        sender_public_key = serialization.load_pem_public_key(
            sender_public_pem, backend=default_backend()
        )
        
        # Verify signature
        sender_public_key.verify(
            signature,
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return message_bytes.decode('utf-8')
    
    except Exception as e:
        raise ValueError(f"Failed to verify signed message: {str(e)}")

@discord.app_commands.allowed_installs(guilds=True, users=True)
@discord.app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
@bot.tree.command(name="regenerate-key", description="Regenerate your private key (WARNING: You'll lose access to old messages)")
async def regenerate_key_command(interaction: discord.Interaction):
    """Regenerate user's private key with confirmation"""
    
    embed = discord.Embed(
        title="⚠️ Regenerate Private Key",
        description=(
            "**WARNING**: Regenerating your private key will make ALL previously encrypted messages "
            "sent to you **UNREADABLE FOREVER**.\n\n"
            "This includes:\n"
            "• Any encrypted messages you've received\n"
            "• Messages in your DMs or servers\n"
            "• Messages from any time period\n\n"
            "**This action CANNOT be undone!**\n\n"
            "You can optionally set a password to protect your new private key. "
            "If you set a password, you'll need to enter it every time you decrypt messages or sign content."
        ),
        color=0xff0000
    )
    
    embed.add_field(
        name="🔄 What happens next?",
        value=(
            "1. Click 'Confirm Regenerate Key' below\n"
            "2. Optionally enter a password for protection\n"
            "3. Your new key pair will be generated\n"
            "4. You can receive new encrypted messages"
        ),
        inline=False
    )
    
    embed.set_footer(text="⚠️ This action is PERMANENT and IRREVERSIBLE")
    
    view = ConfirmRegenerateView(interaction.user.id)
    await interaction.response.send_message(embed=embed, view=view, ephemeral=True)
@discord.app_commands.allowed_installs(guilds=True, users=True)
@discord.app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
@bot.tree.command(name="help", description="Get help with the encryption bot")
async def help_command(interaction: discord.Interaction):
    """Display help information"""
    embed = discord.Embed(
        title="🔒 Encryption Bot Help",
        description="This bot provides end-to-end encryption for Discord messages using RSA encryption.",
        color=0x7289da
    )
    
    embed.add_field(
        name="📝 Commands",
        value=(
            "`/encrypt <message> <receiver>` - Encrypt a message for a specific user\n"
            "`/sign <message>` - Sign a message for authenticity verification\n"
            "`/publickey <user>` - Get a user's public key\n"
            "`/regenerate-key` - Regenerate your private key (with optional password)\n"
            "`/help` - Show this help message"
        ),
        inline=False
    )
    
    embed.add_field(
        name="🖱️ Context Menu",
        value=(
            "Right-click on any encrypted message → **Decrypt Message**\n"
            "Right-click on any signed message → **Verify Signature**"
        ),
        inline=False
    )
    
    embed.add_field(
        name="🔐 How it works",
        value=(
            "1. The bot automatically generates RSA-2048 key pairs for users\n"
            "2. Messages are encrypted with the recipient's public key\n"
            "3. Messages are signed with the sender's private key\n"
            "4. Only the intended recipient can decrypt the message\n"
            "5. Signatures ensure message authenticity"
        ),
        inline=False
    )
    
    embed.add_field(
        name="🛡️ Security Features",
        value=(
            "• RSA-2048 encryption\n"
            "• Digital signatures for authenticity\n"
            "• OAEP padding for encryption\n"
            "• PSS padding for signatures\n"
            "• SHA-256 hashing\n"
            "• Base64 encoding for transport"
        ),
        inline=False
    )
    
    embed.add_field(
        name="➕ Add Bot to Your Server/DMs",
        value=(
            "**Want to decrypt messages or send encrypted messages?**\n"
            "This bot works in both Discord servers and direct messages!\n\n"
            "**To get the bot:**\n"
            "• Contact the bot owner for an official invite link\n"
            "• Or if you have admin permissions, generate an invite with:\n"
            "  - `applications.commands` and `bot` scopes\n"
            "  - `Send Messages` and `Use Slash Commands` permissions\n\n"
            "**Once added:** Use `/encrypt` to send encrypted messages!"
        ),
        inline=False
    )
    
    embed.set_footer(text="Your private keys are stored securely and never shared.")
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

async def encrypt_with_password_check(interaction: discord.Interaction, message: str, receiver: discord.User, password: str = None):
    """Helper function to encrypt message after password check"""
    try:
        # Ensure both users have keys
        load_user_keys(interaction.user.id)
        load_user_keys(receiver.id)
        
        # Encrypt and sign the message
        encrypted_data = encrypt_and_sign_message_with_password(message, interaction.user.id, receiver.id, password)
        
        # Create embed for the encrypted message
        embed = discord.Embed(
            title="🔒 Encrypted Message",
            description=f"**From:** {interaction.user.mention}\n**To:** {receiver.mention}",
            color=0x00ff00
        )
        embed.add_field(name="Encrypted Data", value=f"```{encrypted_data}```", inline=False)
        embed.add_field(
            name="🔓 How to Decrypt",
            value=(
                "**If you have the bot:** Right-click this message → 'Apps' → 'Decrypt Message'\n"
                "**Don't have the bot?** Add it to decrypt your messages:\n"
                "• Use `/help` in any server with this bot to get an invite link\n"
                "• Or ask the sender to share the bot invite link\n"
                "• The bot works in both servers and DMs!"
            ),
            inline=False
        )
        embed.set_footer(text="🔒 End-to-end encrypted with RSA-2048 • Only the recipient can decrypt")
        
        # Send confirmation to user first (ephemeral)
        if interaction.response.is_done():
            await interaction.followup.send("✅ Message encrypted successfully!", ephemeral=True)
        else:
            await interaction.response.send_message("✅ Message encrypted successfully!", ephemeral=True)

        # Send the encrypted message and ping the receiver
        await interaction.followup.send(
            content=f"{receiver.mention} You have received an encrypted message!",
            embed=embed,
            ephemeral=False
        )
        
    except Exception as e:
        error_msg = f"❌ Error encrypting message: {str(e)}"
        if interaction.response.is_done():
            await interaction.followup.send(error_msg, ephemeral=True)
        else:
            await interaction.response.send_message(error_msg, ephemeral=True)

@discord.app_commands.allowed_installs(guilds=True, users=True)
@discord.app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
@bot.tree.command(name="encrypt", description="Encrypt a message for a specific user")
async def encrypt_command(interaction: discord.Interaction, message: str, receiver: discord.User):
    """Encrypt a message for a specific user"""
    try:
        # Check if sender's private key is password-protected
        if is_private_key_encrypted(interaction.user.id):
            # Need password - show modal
            modal = PasswordModal(encrypt_with_password_check, message=message, receiver=receiver)
            await interaction.response.send_modal(modal)
        else:
            # No password needed - use regular function
            await interaction.response.defer(ephemeral=True)
            await encrypt_with_password_check(interaction, message, receiver)
            
    except Exception as e:
        if not interaction.response.is_done():
            await interaction.response.send_message(f"❌ Error encrypting message: {str(e)}", ephemeral=True)
        else:
            await interaction.followup.send(f"❌ Error encrypting message: {str(e)}", ephemeral=True)

@discord.app_commands.allowed_installs(guilds=True, users=True)
@discord.app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
@bot.tree.command(name="publickey", description="Get a user's public key")
async def publickey_command(interaction: discord.Interaction, user: discord.User):
    """Get a user's public key"""
    try:
        # Ensure user has keys
        _, public_pem = load_user_keys(user.id)
        
        # Encode public key in base64 for easier sharing
        public_key_b64 = base64.b64encode(public_pem).decode('utf-8')
        
        embed = discord.Embed(
            title="🔑 Public Key",
            description=f"**User:** {user.mention}",
            color=0x0099ff
        )
        embed.add_field(name="Public Key (Base64)", value=f"```{public_key_b64}```", inline=False)
        
        await interaction.response.send_message(embed=embed, ephemeral=True)
        
    except Exception as e:
        await interaction.response.send_message(f"❌ Error retrieving public key: {str(e)}", ephemeral=True)

async def sign_with_password_check(interaction: discord.Interaction, message: str, password: str = None):
    """Helper function to sign message after password check"""
    try:
        # Ensure user has keys
        load_user_keys(interaction.user.id)
        
        # Sign the message
        signed_data = sign_message_with_password(message, interaction.user.id, password)
        
        # Create embed for the signed message
        embed = discord.Embed(
            title="✍️ Signed Message",
            description=f"**From:** {interaction.user.mention}",
            color=0xffa500
        )
        embed.add_field(name="Message", value=message, inline=False)
        embed.add_field(name="Signature Data", value=f"```{signed_data}```", inline=False)
        embed.add_field(
            name="🔍 How to Verify",
            value=(
                "**If you have the bot:** Right-click this message → 'Apps' → 'Verify Signature'\n"
                "**Don't have the bot?** Add it to verify signatures:\n"
                "• Use `/help` in any server with this bot to get an invite link\n"
                "• Or ask the sender to share the bot invite link\n"
                "• The bot works in both servers and DMs!"
            ),
            inline=False
        )
        embed.set_footer(text="✍️ Digitally signed with RSA-2048 • Verify authenticity with the bot")
        
        # Send confirmation to user first (ephemeral)
        if interaction.response.is_done():
            await interaction.followup.send("✅ Message signed successfully!", ephemeral=True)
        else:
            await interaction.response.send_message("✅ Message signed successfully!", ephemeral=True)
        
        # Then send the signed message (public so others can see it)
        await interaction.followup.send(embed=embed, ephemeral=False)
        
    except Exception as e:
        error_msg = f"❌ Error signing message: {str(e)}"
        if interaction.response.is_done():
            await interaction.followup.send(error_msg, ephemeral=True)
        else:
            await interaction.response.send_message(error_msg, ephemeral=True)

@discord.app_commands.allowed_installs(guilds=True, users=True)
@discord.app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
@bot.tree.command(name="sign", description="Sign a message for authenticity verification")
async def sign_command(interaction: discord.Interaction, message: str):
    """Sign a message with digital signature"""
    try:
        # Check if sender's private key is password-protected
        if is_private_key_encrypted(interaction.user.id):
            # Need password - show modal
            modal = PasswordModal(sign_with_password_check, message=message)
            await interaction.response.send_modal(modal)
        else:
            # No password needed - use regular function
            await interaction.response.defer(ephemeral=True)
            await sign_with_password_check(interaction, message)
            
    except Exception as e:
        if not interaction.response.is_done():
            await interaction.response.send_message(f"❌ Error signing message: {str(e)}", ephemeral=True)
        else:
            await interaction.followup.send(f"❌ Error signing message: {str(e)}", ephemeral=True)

async def decrypt_with_password_check(interaction: discord.Interaction, password: str, encrypted_data: str, sender_id: int, receiver_id: int, intended_receiver_id: int):
    """Helper function to decrypt message after password check"""
    try:
        # Check if the user is the intended recipient
        if intended_receiver_id and intended_receiver_id != receiver_id:
            await interaction.response.send_message("❌ This message is not intended for you.", ephemeral=True)
            return
        
        if not interaction.response.is_done():
            await interaction.response.defer(ephemeral=True)
        
        # Decrypt and verify the message
        decrypted_message, signature_verified = decrypt_and_verify_message_with_password(encrypted_data, sender_id, receiver_id, password)
        
        # Send decrypted message (ephemeral so only the user can see it)
        embed = discord.Embed(
            title="🔓 Decrypted Message",
            description=f"**From:** <@{sender_id}>\n**To:** <@{receiver_id}>",
            color=0xff9900
        )
        embed.add_field(name="Original Message", value=decrypted_message, inline=False)
        if signature_verified:
            embed.set_footer(text="✅ Signature verified - message is authentic")
        else:
            embed.set_footer(text="❌ Signature could not be verified - message authenticity is uncertain")
        
        if interaction.response.is_done():
            await interaction.followup.send(embed=embed, ephemeral=True)
        else:
            await interaction.response.send_message(embed=embed, ephemeral=True)
        
    except ValueError as e:
        error_msg = f"❌ Decryption failed: {str(e)}"
        if interaction.response.is_done():
            await interaction.followup.send(error_msg, ephemeral=True)
        else:
            await interaction.response.send_message(error_msg, ephemeral=True)
    except Exception as e:
        error_msg = f"❌ Error decrypting message: {str(e)}"
        if interaction.response.is_done():
            await interaction.followup.send(error_msg, ephemeral=True)
        else:
            await interaction.response.send_message(error_msg, ephemeral=True)

# Context menu for message decryption
@discord.app_commands.allowed_installs(guilds=True, users=True)
@discord.app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
@bot.tree.context_menu(name="Decrypt Message")
async def decrypt_message_context(interaction: discord.Interaction, message: discord.Message):
    """Context menu to decrypt a message"""
    try:
        # Check if message contains an encrypted message embed
        if not message.embeds:
            await interaction.response.send_message("❌ This message doesn't contain an encrypted message.", ephemeral=True)
            return
        
        embed = message.embeds[0]
        if embed.title != "🔒 Encrypted Message":
            await interaction.response.send_message("❌ This message doesn't contain an encrypted message.", ephemeral=True)
            return
        
        # Check if the message is sent by the bot
        if message.author.id != bot.user.id:
            await interaction.response.send_message("❌ This message was not sent by the encryption bot.", ephemeral=True)
            return
        
        # Extract encrypted data from embed
        encrypted_data = None
        for field in embed.fields:
            if field.name == "Encrypted Data":
                encrypted_data = field.value.strip("```")
                break
        
        if not encrypted_data:
            await interaction.response.send_message("❌ Could not find encrypted data in message.", ephemeral=True)
            return
        
        # Extract sender and receiver information from embed description
        description_lines = embed.description.split('\n')
        sender_id = None
        intended_receiver_id = None
        
        for line in description_lines:
            if line.startswith("**From:**"):
                # Extract user ID from mention
                import re
                sender_match = re.search(r'<@(\d+)>', line)
                if sender_match:
                    sender_id = int(sender_match.group(1))
            elif line.startswith("**To:**"):
                # Extract user ID from mention
                import re
                receiver_match = re.search(r'<@(\d+)>', line)
                if receiver_match:
                    intended_receiver_id = int(receiver_match.group(1))
        
        if not sender_id:
            # Fallback to message author
            sender_id = message.author.id
        
        receiver_id = interaction.user.id
        
        # Check if receiver's private key is password-protected
        if is_private_key_encrypted(receiver_id):
            # Need password - show modal
            modal = PasswordModal(decrypt_with_password_check, encrypted_data=encrypted_data, sender_id=sender_id, receiver_id=receiver_id, intended_receiver_id=intended_receiver_id)
            await interaction.response.send_modal(modal)
        else:
            # No password needed - use regular function
            await decrypt_with_password_check(interaction, None, encrypted_data, sender_id, receiver_id, intended_receiver_id)
        
    except Exception as e:
        if not interaction.response.is_done():
            await interaction.response.send_message(f"❌ Error decrypting message: {str(e)}", ephemeral=True)
        else:
            await interaction.followup.send(f"❌ Error decrypting message: {str(e)}", ephemeral=True)

# Context menu for signature verification
@discord.app_commands.allowed_installs(guilds=True, users=True)
@discord.app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
@bot.tree.context_menu(name="Verify Signature")
async def verify_signature_context(interaction: discord.Interaction, message: discord.Message):
    """Context menu to verify a signed message"""
    try:
        # Check if message contains a signed message embed
        if not message.embeds:
            await interaction.response.send_message("❌ This message doesn't contain a signed message.", ephemeral=True)
            return
        
        embed = message.embeds[0]
        if embed.title != "✍️ Signed Message":
            await interaction.response.send_message("❌ This message doesn't contain a signed message.", ephemeral=True)
            return
        
        # Check if the message is sent by the bot
        if message.author.id != bot.user.id:
            await interaction.response.send_message("❌ This message was not sent by the encryption bot.", ephemeral=True)
            return
        
        # Extract signed data from embed
        signed_data = None
        original_message = None
        for field in embed.fields:
            if field.name == "Signature Data":
                signed_data = field.value.strip("```")
            elif field.name == "Message":
                original_message = field.value
        
        if not signed_data:
            await interaction.response.send_message("❌ Could not find signature data in message.", ephemeral=True)
            return
        
        # Extract sender information from embed description
        description_lines = embed.description.split('\n')
        sender_id = None
        
        for line in description_lines:
            if line.startswith("**From:**"):
                # Extract user ID from mention
                import re
                sender_match = re.search(r'<@(\d+)>', line)
                if sender_match:
                    sender_id = int(sender_match.group(1))
                break
        
        if not sender_id:
            await interaction.response.send_message("❌ Could not identify message sender.", ephemeral=True)
            return
        
        # Defer response since verification might take a moment
        await interaction.response.defer(ephemeral=True)
        
        # Verify the signed message
        verified_message = verify_signed_message(signed_data, sender_id)
        
        # Check if the verified message matches the displayed message
        is_authentic = verified_message == original_message
        
        # Send verification result (ephemeral so only the user can see it)
        embed = discord.Embed(
            title="🔍 Signature Verification Result",
            description=f"**From:** <@{sender_id}>",
            color=0x00ff00 if is_authentic else 0xff0000
        )
        
        if is_authentic:
            embed.add_field(name="✅ Verification Status", value="**AUTHENTIC** - Signature is valid", inline=False)
            embed.add_field(name="Original Message", value=verified_message, inline=False)
            embed.set_footer(text="✅ This message is authentic and has not been tampered with")
        else:
            embed.add_field(name="❌ Verification Status", value="**TAMPERED** - Message has been modified", inline=False)
            embed.add_field(name="Displayed Message", value=original_message or "N/A", inline=False)
            embed.add_field(name="Original Signed Message", value=verified_message, inline=False)
            embed.set_footer(text="⚠️ WARNING: The displayed message does not match the signed content!")
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except ValueError as e:
        if interaction.response.is_done():
            await interaction.followup.send(f"❌ Signature verification failed: {str(e)}", ephemeral=True)
        else:
            await interaction.response.send_message(f"❌ Signature verification failed: {str(e)}", ephemeral=True)
    except Exception as e:
        if interaction.response.is_done():
            await interaction.followup.send(f"❌ Error verifying signature: {str(e)}", ephemeral=True)
        else:
            await interaction.response.send_message(f"❌ Error verifying signature: {str(e)}", ephemeral=True)

if __name__ == "__main__":
    # You need to set your bot token as an environment variable
    load_dotenv()
    token = os.getenv('DISCORD_BOT_TOKEN')
    if not token:
        print("Please set the DISCORD_BOT_TOKEN environment variable")
        exit(1)
    
    bot.run(token)