import discord
from discord.ext import commands
import os
from dotenv import load_dotenv
import base64
import asyncio
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Create keys directory if it doesn't exist
KEYS_DIR = Path("keys")
KEYS_DIR.mkdir(exist_ok=True)

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

# Modal classes for password input
class PasswordModal(discord.ui.Modal):
    """Modal for collecting password input"""
    def __init__(self, title: str, label: str, placeholder: str = "Enter password", callback_func=None):
        super().__init__(title=title)
        self.callback_func = callback_func
        self.password_input = discord.ui.TextInput(
            label=label,
            placeholder=placeholder,
            style=discord.TextStyle.short,
            required=False,  # Allow empty password for no encryption
            max_length=128
        )
        self.add_item(self.password_input)
        
    async def on_submit(self, interaction: discord.Interaction):
        if self.callback_func:
            await self.callback_func(interaction, self.password_input.value)

class DecryptPasswordModal(discord.ui.Modal):
    """Modal for collecting decryption password"""
    def __init__(self, encrypted_data: str, sender_id: int, receiver_id: int):
        super().__init__(title="Enter Private Key Password")
        self.encrypted_data = encrypted_data
        self.sender_id = sender_id
        self.receiver_id = receiver_id
        
        self.password_input = discord.ui.TextInput(
            label="Private Key Password",
            placeholder="Enter your private key password",
            style=discord.TextStyle.short,
            required=True,
            max_length=128
        )
        self.add_item(self.password_input)
        
    async def on_submit(self, interaction: discord.Interaction):
        try:
            await interaction.response.defer(ephemeral=True)
            
            # Decrypt the message with the provided password
            decrypted_message = decrypt_and_verify_message(
                self.encrypted_data, self.sender_id, self.receiver_id, self.password_input.value
            )
            
            # Send decrypted message
            embed = discord.Embed(
                title="🔓 Decrypted Message",
                description=f"**From:** <@{self.sender_id}>\n**To:** {interaction.user.mention}",
                color=0xff9900
            )
            embed.add_field(name="Original Message", value=decrypted_message, inline=False)
            embed.set_footer(text="✅ Signature verified - message is authentic")
            
            await interaction.followup.send(embed=embed, ephemeral=True)
            
        except ValueError as e:
            await interaction.followup.send(f"❌ Decryption failed: {str(e)}", ephemeral=True)
        except Exception as e:
            await interaction.followup.send(f"❌ Error decrypting message: {str(e)}", ephemeral=True)

class EncryptPasswordModal(discord.ui.Modal):
    """Modal for collecting sender's private key password when encrypting"""
    def __init__(self, message: str, receiver_id: int, sender_id: int):
        super().__init__(title="Enter Your Private Key Password")
        self.message = message
        self.receiver_id = receiver_id
        self.sender_id = sender_id
        
        self.password_input = discord.ui.TextInput(
            label="Your Private Key Password",
            placeholder="Enter your private key password",
            style=discord.TextStyle.short,
            required=True,
            max_length=128
        )
        self.add_item(self.password_input)
        
    async def on_submit(self, interaction: discord.Interaction):
        try:
            await interaction.response.defer(ephemeral=True)
            
            # Encrypt and sign the message
            encrypted_data = encrypt_and_sign_message(
                self.message, self.sender_id, self.receiver_id, self.password_input.value
            )
            
            # Create embed for the encrypted message
            embed = discord.Embed(
                title="🔒 Encrypted Message",
                description=f"**From:** <@{self.sender_id}>\n**To:** <@{self.receiver_id}>",
                color=0x00ff00
            )
            embed.add_field(name="Encrypted Data", value=f"```{encrypted_data}```", inline=False)
            embed.set_footer(text="Right-click this message to decrypt (if you're the recipient)")
            
            # Send confirmation to user first (ephemeral)
            await interaction.followup.send("✅ Message encrypted successfully!", ephemeral=True)
            
            # Then send the encrypted message (public so recipient can see it)
            await interaction.followup.send(embed=embed, ephemeral=False)
            
        except ValueError as e:
            await interaction.followup.send(f"❌ Encryption failed: {str(e)}", ephemeral=True)
        except Exception as e:
            await interaction.followup.send(f"❌ Error encrypting message: {str(e)}", ephemeral=True)

class RegenerateKeyConfirmView(discord.ui.View):
    """Confirmation view for key regeneration"""
    def __init__(self, user_id: int):
        super().__init__(timeout=300)  # 5 minute timeout
        self.user_id = user_id
        
    @discord.ui.button(label="⚠️ Yes, Regenerate Keys", style=discord.ButtonStyle.danger)
    async def confirm_regenerate(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != self.user_id:
            await interaction.response.send_message("❌ This confirmation is not for you.", ephemeral=True)
            return
            
        # Show password modal for new key encryption
        modal = PasswordModal(
            title="Set Private Key Password (Optional)",
            label="Password (leave empty for no encryption)",
            placeholder="Enter password to encrypt your private key (optional)",
            callback_func=self.handle_password_input
        )
        await interaction.response.send_modal(modal)
        
    @discord.ui.button(label="❌ Cancel", style=discord.ButtonStyle.secondary)
    async def cancel_regenerate(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != self.user_id:
            await interaction.response.send_message("❌ This confirmation is not for you.", ephemeral=True)
            return
            
        await interaction.response.send_message("✅ Key regeneration cancelled.", ephemeral=True)
        self.stop()
        
    async def handle_password_input(self, interaction: discord.Interaction, password: str):
        try:
            await interaction.response.defer(ephemeral=True)
            
            # Generate new keys with optional password
            private_pem, public_pem = generate_user_keys(self.user_id, password if password else None)
            
            # Check if the new key is encrypted
            is_encrypted = is_private_key_encrypted(private_pem)
            
            embed = discord.Embed(
                title="🔑 Keys Regenerated Successfully",
                description="Your RSA key pair has been regenerated.",
                color=0x00ff00
            )
            
            if is_encrypted:
                embed.add_field(
                    name="🔒 Encryption Status", 
                    value="Your private key is **encrypted** with a password.", 
                    inline=False
                )
                embed.add_field(
                    name="⚠️ Important", 
                    value="Remember your password! You'll need it to decrypt messages and sign new ones.", 
                    inline=False
                )
            else:
                embed.add_field(
                    name="🔓 Encryption Status", 
                    value="Your private key is **not encrypted** (no password protection).", 
                    inline=False
                )
            
            embed.add_field(
                name="🛡️ Security", 
                value="Your old private key has been replaced. Previous encrypted messages may no longer be decryptable.", 
                inline=False
            )
            
            await interaction.followup.send(embed=embed, ephemeral=True)
            self.stop()
            
        except Exception as e:
            await interaction.followup.send(f"❌ Error regenerating keys: {str(e)}", ephemeral=True)
            self.stop()
            
    async def on_timeout(self):
        # Disable all buttons when timeout occurs
        for item in self.children:
            item.disabled = True

def get_user_keys_path(user_id: int) -> tuple[Path, Path]:
    """Get the file paths for a user's private and public keys"""
    user_dir = KEYS_DIR / str(user_id)
    user_dir.mkdir(exist_ok=True)
    private_key_path = user_dir / "private_key.pem"
    public_key_path = user_dir / "public_key.pem"
    return private_key_path, public_key_path

def is_private_key_encrypted(private_key_pem: bytes) -> bool:
    """Check if a private key is encrypted with a password"""
    try:
        # Try to load without password - if it succeeds, it's not encrypted
        serialization.load_pem_private_key(
            private_key_pem, password=None, backend=default_backend()
        )
        return False
    except TypeError:
        # TypeError is raised when password is required but not provided
        return True
    except Exception:
        # Other exceptions might indicate corruption or invalid format
        return False

def generate_user_keys(user_id: int, password: str = None) -> tuple[bytes, bytes]:
    """Generate RSA key pair for a user and save to files with optional password encryption"""
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Get public key
    public_key = private_key.public_key()
    
    # Determine encryption algorithm for private key
    if password:
        # Use password-based encryption
        encryption_algorithm = serialization.BestAvailableEncryption(password.encode('utf-8'))
    else:
        # No encryption
        encryption_algorithm = serialization.NoEncryption()
    
    # Serialize private key
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

def encrypt_and_sign_message(message: str, sender_id: int, receiver_id: int, sender_private_key_password: str = None) -> str:
    """Encrypt message with receiver's public key and sign with sender's private key"""
    # Load sender's private key and receiver's public key
    sender_private_pem, _ = load_user_keys(sender_id)
    _, receiver_public_pem = load_user_keys(receiver_id)
    
    # Load keys - handle encrypted private key
    try:
        sender_private_key = serialization.load_pem_private_key(
            sender_private_pem, password=sender_private_key_password.encode('utf-8') if sender_private_key_password else None, backend=default_backend()
        )
    except TypeError:
        raise ValueError("Your private key is encrypted - password required")
    except ValueError as e:
        if "Bad decrypt" in str(e) or "invalid" in str(e).lower():
            raise ValueError("Invalid password for your private key")
        raise ValueError(f"Failed to load your private key: {str(e)}")
        
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

def decrypt_and_verify_message(encrypted_data: str, sender_id: int, receiver_id: int, private_key_password: str = None) -> str:
    """Decrypt message with receiver's private key and verify signature with sender's public key"""
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
        
        # Load private key with password if needed
        try:
            receiver_private_key = serialization.load_pem_private_key(
                receiver_private_pem, password=private_key_password.encode('utf-8') if private_key_password else None, backend=default_backend()
            )
        except TypeError:
            raise ValueError("Private key is encrypted - password required")
        except ValueError as e:
            if "Bad decrypt" in str(e) or "invalid" in str(e).lower():
                raise ValueError("Invalid password for private key")
            raise ValueError(f"Failed to load private key: {str(e)}")
        
        sender_public_key = serialization.load_pem_public_key(
            sender_public_pem, backend=default_backend()
        )
        
        # Verify signature
        sender_public_key.verify(
            signature,
            encrypted_message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Decrypt message
        decrypted_message = receiver_private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return decrypted_message.decode('utf-8')
    
    except Exception as e:
        raise ValueError(f"Failed to decrypt/verify message: {str(e)}")

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
            "`/publickey <user>` - Get a user's public key\n"
            "`/keystatus` - Check your private key status and encryption\n"
            "`/regeneratekey` - Regenerate your private key (⚠️ previous messages will be lost!)\n"
            "`/help` - Show this help message"
        ),
        inline=False
    )
    
    embed.add_field(
        name="🖱️ Context Menu",
        value="Right-click on any encrypted message → **Decrypt Message**",
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
            "• Optional password-protected private keys\n"
            "• OAEP padding for encryption\n"
            "• PSS padding for signatures\n"
            "• SHA-256 hashing\n"
            "• Base64 encoding for transport"
        ),
        inline=False
    )
    
    embed.add_field(
        name="➕ Add Bot to Your Server",
        value=(
            "To add this bot to your own server:\n"
            "1. Contact the bot owner to get an invite link\n"
            "2. Or if you have admin permissions, generate an invite with:\n"
            "   • `applications.commands` scope\n"
            "   • `bot` scope with `Send Messages` and `Use Slash Commands` permissions\n"
            "3. The bot works in both servers and DMs!"
        ),
        inline=False
    )
    
    embed.set_footer(text="Your private keys are stored securely and can be password-protected for extra security.")
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

@discord.app_commands.allowed_installs(guilds=True, users=True)
@discord.app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
@bot.tree.command(name="encrypt", description="Encrypt a message for a specific user")
async def encrypt_command(interaction: discord.Interaction, message: str, receiver: discord.User):
    """Encrypt a message for a specific user"""
    try:
        # Defer response as ephemeral to hide the command from others
        await interaction.response.defer(ephemeral=True)
        
        # Ensure both users have keys
        sender_private_pem, _ = load_user_keys(interaction.user.id)
        load_user_keys(receiver.id)
        
        # Check if sender's private key is encrypted
        if is_private_key_encrypted(sender_private_pem):
            # Show password modal
            modal = EncryptPasswordModal(message, receiver.id, interaction.user.id)
            await interaction.followup.send("🔒 Your private key is encrypted. Please enter your password:", view=None, ephemeral=True)
            # We need to send a follow-up with the modal since we already deferred
            await interaction.edit_original_response(content="🔒 Your private key is encrypted. Please enter your password:")
            # Create a new interaction for the modal
            class ModalView(discord.ui.View):
                def __init__(self):
                    super().__init__(timeout=300)
                    
                @discord.ui.button(label="Enter Password", style=discord.ButtonStyle.primary)
                async def show_modal(self, modal_interaction: discord.Interaction, button: discord.ui.Button):
                    if modal_interaction.user.id != interaction.user.id:
                        await modal_interaction.response.send_message("❌ This is not for you.", ephemeral=True)
                        return
                    await modal_interaction.response.send_modal(modal)
                    
            view = ModalView()
            await interaction.edit_original_response(content="🔒 Your private key is encrypted. Click below to enter your password:", view=view)
        else:
            # Private key is not encrypted, proceed normally
            encrypted_data = encrypt_and_sign_message(message, interaction.user.id, receiver.id)
            
            # Create embed for the encrypted message
            embed = discord.Embed(
                title="🔒 Encrypted Message",
                description=f"**From:** {interaction.user.mention}\n**To:** {receiver.mention}",
                color=0x00ff00
            )
            embed.add_field(name="Encrypted Data", value=f"```{encrypted_data}```", inline=False)
            embed.set_footer(text="Right-click this message to decrypt (if you're the recipient)")
            
            # Send confirmation to user first (ephemeral)
            await interaction.followup.send("✅ Message encrypted successfully!", ephemeral=True)
            
            # Then send the encrypted message (public so recipient can see it)
            await interaction.followup.send(embed=embed, ephemeral=False)
        
    except Exception as e:
        if interaction.response.is_done():
            await interaction.followup.send(f"❌ Error encrypting message: {str(e)}", ephemeral=True)
        else:
            await interaction.response.send_message(f"❌ Error encrypting message: {str(e)}", ephemeral=True)

@discord.app_commands.allowed_installs(guilds=True, users=True)
@discord.app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
@bot.tree.command(name="regeneratekey", description="Regenerate your private key (WARNING: Previous messages will be lost!)")
async def regeneratekey_command(interaction: discord.Interaction):
    """Regenerate user's private key with confirmation"""
    embed = discord.Embed(
        title="⚠️ Regenerate Private Key",
        description=(
            "**WARNING:** Regenerating your private key will make it impossible to decrypt "
            "messages that were previously sent to you!\n\n"
            "**What happens when you regenerate:**\n"
            "• Your old private key will be permanently deleted\n"
            "• A new private key will be generated\n"
            "• You can optionally protect it with a password\n"
            "• All previous encrypted messages to you will become unreadable\n\n"
            "**Are you sure you want to continue?**"
        ),
        color=0xff6b6b
    )
    
    view = RegenerateKeyConfirmView(interaction.user.id)
    await interaction.response.send_message(embed=embed, view=view, ephemeral=True)

@discord.app_commands.allowed_installs(guilds=True, users=True)
@discord.app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
@bot.tree.command(name="keystatus", description="Check the status of your private key")
async def keystatus_command(interaction: discord.Interaction):
    """Check if user's private key exists and if it's encrypted"""
    try:
        private_key_path, public_key_path = get_user_keys_path(interaction.user.id)
        
        if not private_key_path.exists():
            embed = discord.Embed(
                title="🔑 Key Status",
                description="You don't have any keys yet. They will be generated automatically when you first encrypt or receive a message.",
                color=0xffa500
            )
        else:
            private_pem, _ = load_user_keys(interaction.user.id)
            is_encrypted = is_private_key_encrypted(private_pem)
            
            embed = discord.Embed(
                title="🔑 Key Status",
                description="Your RSA key pair exists and is ready to use.",
                color=0x00ff00
            )
            
            if is_encrypted:
                embed.add_field(
                    name="🔒 Encryption Status",
                    value="Your private key is **encrypted** with a password.",
                    inline=False
                )
                embed.add_field(
                    name="ℹ️ Note",
                    value="You'll need to enter your password when encrypting messages or decrypting messages sent to you.",
                    inline=False
                )
            else:
                embed.add_field(
                    name="🔓 Encryption Status",
                    value="Your private key is **not encrypted** (no password protection).",
                    inline=False
                )
                embed.add_field(
                    name="💡 Tip",
                    value="Consider regenerating your key with password protection for enhanced security.",
                    inline=False
                )
        
        await interaction.response.send_message(embed=embed, ephemeral=True)
        
    except Exception as e:
        await interaction.response.send_message(f"❌ Error checking key status: {str(e)}", ephemeral=True)

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
        
        # Check if the user is the intended recipient
        if intended_receiver_id and intended_receiver_id != receiver_id:
            await interaction.response.send_message("❌ This message is not intended for you.", ephemeral=True)
            return
        
        # Defer response since decryption might take a moment
        await interaction.response.defer(ephemeral=True)
        
        # Check if receiver's private key is encrypted
        receiver_private_pem, _ = load_user_keys(receiver_id)
        if is_private_key_encrypted(receiver_private_pem):
            # Show password modal
            modal = DecryptPasswordModal(encrypted_data, sender_id, receiver_id)
            await interaction.followup.send("🔒 Your private key is encrypted. Please enter your password:", ephemeral=True)
            
            # Create a view with button to show modal
            class DecryptModalView(discord.ui.View):
                def __init__(self):
                    super().__init__(timeout=300)
                    
                @discord.ui.button(label="Enter Password", style=discord.ButtonStyle.primary)
                async def show_modal(self, modal_interaction: discord.Interaction, button: discord.ui.Button):
                    if modal_interaction.user.id != interaction.user.id:
                        await modal_interaction.response.send_message("❌ This is not for you.", ephemeral=True)
                        return
                    await modal_interaction.response.send_modal(modal)
                    
            view = DecryptModalView()
            await interaction.edit_original_response(content="🔒 Your private key is encrypted. Click below to enter your password:", view=view)
        else:
            # Private key is not encrypted, proceed normally
            decrypted_message = decrypt_and_verify_message(encrypted_data, sender_id, receiver_id)
            
            # Send decrypted message (ephemeral so only the user can see it)
            embed = discord.Embed(
                title="🔓 Decrypted Message",
                description=f"**From:** <@{sender_id}>\n**To:** {interaction.user.mention}",
                color=0xff9900
            )
            embed.add_field(name="Original Message", value=decrypted_message, inline=False)
            embed.set_footer(text="✅ Signature verified - message is authentic")
            
            await interaction.followup.send(embed=embed, ephemeral=True)
        
    except ValueError as e:
        if interaction.response.is_done():
            await interaction.followup.send(f"❌ Decryption failed: {str(e)}", ephemeral=True)
        else:
            await interaction.response.send_message(f"❌ Decryption failed: {str(e)}", ephemeral=True)
    except Exception as e:
        if interaction.response.is_done():
            await interaction.followup.send(f"❌ Error decrypting message: {str(e)}", ephemeral=True)
        else:
            await interaction.response.send_message(f"❌ Error decrypting message: {str(e)}", ephemeral=True)

if __name__ == "__main__":
    # You need to set your bot token as an environment variable
    load_dotenv()
    token = os.getenv('DISCORD_BOT_TOKEN')
    if not token:
        print("Please set the DISCORD_BOT_TOKEN environment variable")
        exit(1)
    
    bot.run(token)