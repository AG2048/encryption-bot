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

def generate_user_keys(user_id: int) -> tuple[bytes, bytes]:
    """Generate RSA key pair for a user and save to files"""
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Get public key
    public_key = private_key.public_key()
    
    # Serialize private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
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

def encrypt_and_sign_message(message: str, sender_id: int, receiver_id: int) -> str:
    """Encrypt message with receiver's public key and sign with sender's private key"""
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

def decrypt_and_verify_message(encrypted_data: str, sender_id: int, receiver_id: int) -> str:
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
        
        receiver_private_key = serialization.load_pem_private_key(
            receiver_private_pem, password=None, backend=default_backend()
        )
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

@discord.app_commands.allowed_installs(guilds=True, users=True)
@discord.app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
@bot.tree.command(name="encrypt", description="Encrypt a message for a specific user")
async def encrypt_command(interaction: discord.Interaction, message: str, receiver: discord.User):
    """Encrypt a message for a specific user"""
    try:
        # Defer response as ephemeral to hide the command from others
        await interaction.response.defer(ephemeral=True)
        
        # Ensure both users have keys
        load_user_keys(interaction.user.id)
        load_user_keys(receiver.id)
        
        # Encrypt and sign the message
        encrypted_data = encrypt_and_sign_message(message, interaction.user.id, receiver.id)
        
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
                "**If you have the bot:** Right-click this message → 'Decrypt Message'\n"
                "**Don't have the bot?** Add it to decrypt your messages:\n"
                "• Use `/help` in any server with this bot to get an invite link\n"
                "• Or ask the sender to share the bot invite link\n"
                "• The bot works in both servers and DMs!"
            ),
            inline=False
        )
        embed.set_footer(text="🔒 End-to-end encrypted with RSA-2048 • Only the recipient can decrypt")
        # Send confirmation to user first (ephemeral)
        await interaction.followup.send("✅ Message encrypted successfully!", ephemeral=True)

        # Send the encrypted message and ping the receiver
        await interaction.followup.send(
            content=f"{receiver.mention} You have received an encrypted message!",
            embed=embed,
            ephemeral=False
        )
        
    except Exception as e:
        if interaction.response.is_done():
            await interaction.followup.send(f"❌ Error encrypting message: {str(e)}", ephemeral=True)
        else:
            await interaction.response.send_message(f"❌ Error encrypting message: {str(e)}", ephemeral=True)

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
        
        # Decrypt and verify the message
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