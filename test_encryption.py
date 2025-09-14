#!/usr/bin/env python3
"""
Test script for the encryption bot functionality
"""

import os
import shutil
from pathlib import Path
import sys

# Add the current directory to the path so we can import from bot.py
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bot import (
    generate_user_keys, 
    load_user_keys, 
    encrypt_and_sign_message, 
    decrypt_and_verify_message,
    KEYS_DIR
)

def test_key_generation():
    """Test RSA key generation and loading"""
    print("Testing key generation...")
    
    # Test user IDs
    alice_id = 123456789
    bob_id = 987654321
    
    # Clean up any existing test keys
    alice_dir = KEYS_DIR / str(alice_id)
    bob_dir = KEYS_DIR / str(bob_id)
    if alice_dir.exists():
        shutil.rmtree(alice_dir)
    if bob_dir.exists():
        shutil.rmtree(bob_dir)
    
    # Generate keys for Alice
    alice_private, alice_public = generate_user_keys(alice_id)
    print(f"✓ Generated keys for Alice (user {alice_id})")
    
    # Generate keys for Bob
    bob_private, bob_public = generate_user_keys(bob_id)
    print(f"✓ Generated keys for Bob (user {bob_id})")
    
    # Test loading keys
    alice_private_loaded, alice_public_loaded = load_user_keys(alice_id)
    bob_private_loaded, bob_public_loaded = load_user_keys(bob_id)
    
    assert alice_private == alice_private_loaded, "Alice's private key mismatch"
    assert alice_public == alice_public_loaded, "Alice's public key mismatch"
    assert bob_private == bob_private_loaded, "Bob's private key mismatch"
    assert bob_public == bob_public_loaded, "Bob's public key mismatch"
    
    print("✓ Key loading verified")
    return alice_id, bob_id

def test_encryption_decryption():
    """Test message encryption and decryption"""
    print("\nTesting encryption and decryption...")
    
    alice_id, bob_id = test_key_generation()
    
    # Test message
    original_message = "Hello Bob! This is a secret message from Alice. 🔒"
    
    # Alice encrypts a message for Bob
    encrypted_data = encrypt_and_sign_message(original_message, alice_id, bob_id)
    print(f"✓ Encrypted message (length: {len(encrypted_data)} chars)")
    print(f"  Preview: {encrypted_data[:50]}...")
    
    # Bob decrypts the message from Alice
    decrypted_message = decrypt_and_verify_message(encrypted_data, alice_id, bob_id)
    print(f"✓ Decrypted message: '{decrypted_message}'")
    
    assert original_message == decrypted_message, "Message decryption failed"
    print("✓ Encryption/decryption cycle successful")
    
    return alice_id, bob_id, encrypted_data

def test_signature_verification():
    """Test signature verification"""
    print("\nTesting signature verification...")
    
    alice_id, bob_id, encrypted_data = test_encryption_decryption()
    
    # Try to decrypt with wrong sender (should fail)
    try:
        decrypt_and_verify_message(encrypted_data, bob_id, bob_id)  # Wrong sender
        assert False, "Should have failed with wrong sender"
    except ValueError as e:
        print(f"✓ Correctly rejected wrong sender: {e}")
    
    # Try to decrypt with wrong receiver (should fail)
    try:
        decrypt_and_verify_message(encrypted_data, alice_id, alice_id)  # Wrong receiver
        assert False, "Should have failed with wrong receiver"
    except ValueError as e:
        print(f"✓ Correctly rejected wrong receiver: {e}")
    
    print("✓ Signature verification working correctly")

def test_multiple_messages():
    """Test multiple message encryption/decryption"""
    print("\nTesting multiple messages...")
    
    alice_id = 111111111
    bob_id = 222222222
    charlie_id = 333333333
    
    # Clean up test keys
    for user_id in [alice_id, bob_id, charlie_id]:
        user_dir = KEYS_DIR / str(user_id)
        if user_dir.exists():
            shutil.rmtree(user_dir)
    
    messages = [
        "Short message",
        "This is a longer message with more content to test encryption of various message lengths.",
        "Message with special characters: àáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ !@#$%^&*()_+-=[]{}|;':\",./<>?",
        "Emoji test: 🔒🔑💻🛡️🔐⚡🚀🎉",
        ""  # Empty message
    ]
    
    for i, message in enumerate(messages):
        print(f"  Testing message {i+1}: '{message[:30]}{'...' if len(message) > 30 else ''}'")
        
        # Alice sends to Bob
        encrypted = encrypt_and_sign_message(message, alice_id, bob_id)
        decrypted = decrypt_and_verify_message(encrypted, alice_id, bob_id)
        assert message == decrypted, f"Message {i+1} failed"
        
        # Bob sends to Charlie
        encrypted = encrypt_and_sign_message(message, bob_id, charlie_id)
        decrypted = decrypt_and_verify_message(encrypted, bob_id, charlie_id)
        assert message == decrypted, f"Message {i+1} failed"
    
    print("✓ All messages encrypted/decrypted successfully")

def cleanup_test_data():
    """Clean up test data"""
    print("\nCleaning up test data...")
    test_user_ids = [123456789, 987654321, 111111111, 222222222, 333333333]
    
    for user_id in test_user_ids:
        user_dir = KEYS_DIR / str(user_id)
        if user_dir.exists():
            shutil.rmtree(user_dir)
            print(f"  Removed keys for user {user_id}")
    
    print("✓ Cleanup complete")

def main():
    """Run all tests"""
    print("🔒 Encryption Bot Test Suite")
    print("=" * 40)
    
    try:
        test_key_generation()
        test_encryption_decryption()
        test_signature_verification()
        test_multiple_messages()
        
        print("\n" + "=" * 40)
        print("🎉 All tests passed!")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    finally:
        cleanup_test_data()
    
    return 0

if __name__ == "__main__":
    exit(main())