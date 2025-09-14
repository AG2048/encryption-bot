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
    is_private_key_encrypted,
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

def test_password_protected_keys():
    """Test password-protected private key functionality"""
    print("\nTesting password-protected keys...")
    
    alice_id = 444444444
    bob_id = 555555555
    password = "test_password_123"
    
    # Clean up test keys
    for user_id in [alice_id, bob_id]:
        user_dir = KEYS_DIR / str(user_id)
        if user_dir.exists():
            shutil.rmtree(user_dir)
    
    # Generate Alice's key with password
    alice_private, alice_public = generate_user_keys(alice_id, password)
    print(f"✓ Generated password-protected keys for Alice (user {alice_id})")
    
    # Generate Bob's key without password
    bob_private, bob_public = generate_user_keys(bob_id)
    print(f"✓ Generated unprotected keys for Bob (user {bob_id})")
    
    # Test encryption detection
    assert is_private_key_encrypted(alice_private), "Alice's key should be encrypted"
    assert not is_private_key_encrypted(bob_private), "Bob's key should not be encrypted"
    print("✓ Encryption detection working correctly")
    
    # Test message encryption/decryption with password-protected keys
    message = "Secret message from Alice to Bob with password protection!"
    
    # Alice (with password) sends to Bob (without password)
    encrypted_data = encrypt_and_sign_message(message, alice_id, bob_id, password)
    decrypted_message = decrypt_and_verify_message(encrypted_data, alice_id, bob_id)
    assert message == decrypted_message, "Message encryption/decryption failed"
    print("✓ Alice (password-protected) → Bob (unprotected) successful")
    
    # Bob (without password) sends to Alice (with password) 
    encrypted_data = encrypt_and_sign_message(message, bob_id, alice_id)
    decrypted_message = decrypt_and_verify_message(encrypted_data, bob_id, alice_id, password)
    assert message == decrypted_message, "Message encryption/decryption failed"
    print("✓ Bob (unprotected) → Alice (password-protected) successful")
    
    # Test wrong password scenarios
    try:
        encrypt_and_sign_message(message, alice_id, bob_id, "wrong_password")
        assert False, "Should have failed with wrong password"
    except ValueError as e:
        print(f"✓ Correctly rejected wrong encryption password: {e}")
    
    try:
        decrypt_and_verify_message(encrypted_data, bob_id, alice_id, "wrong_password")
        assert False, "Should have failed with wrong password"
    except ValueError as e:
        print(f"✓ Correctly rejected wrong decryption password: {e}")
    
    # Test missing password scenarios
    try:
        encrypt_and_sign_message(message, alice_id, bob_id)  # No password provided
        assert False, "Should have failed without password"
    except ValueError as e:
        print(f"✓ Correctly required password for encryption: {e}")
    
    try:
        decrypt_and_verify_message(encrypted_data, bob_id, alice_id)  # No password provided
        assert False, "Should have failed without password"
    except ValueError as e:
        print(f"✓ Correctly required password for decryption: {e}")
    
    print("✓ Password-protected key functionality working correctly")

def test_key_regeneration():
    """Test key regeneration functionality"""
    print("\nTesting key regeneration...")
    
    charlie_id = 666666666
    
    # Clean up test keys
    charlie_dir = KEYS_DIR / str(charlie_id)
    if charlie_dir.exists():
        shutil.rmtree(charlie_dir)
    
    # Generate initial keys
    original_private, original_public = generate_user_keys(charlie_id, "original_password")
    print(f"✓ Generated initial keys for Charlie (user {charlie_id})")
    
    # Generate new keys with different password
    new_private, new_public = generate_user_keys(charlie_id, "new_password")
    print(f"✓ Regenerated keys for Charlie with new password")
    
    # Verify keys are different
    assert original_private != new_private, "Private keys should be different after regeneration"
    assert original_public != new_public, "Public keys should be different after regeneration"
    print("✓ Keys are different after regeneration")
    
    # Verify new keys work
    message = "Test message after key regeneration"
    encrypted_data = encrypt_and_sign_message(message, charlie_id, charlie_id, "new_password")
    decrypted_message = decrypt_and_verify_message(encrypted_data, charlie_id, charlie_id, "new_password")
    assert message == decrypted_message, "New keys should work correctly"
    print("✓ New keys work correctly")
    
    # Verify old password doesn't work
    try:
        encrypt_and_sign_message(message, charlie_id, charlie_id, "original_password")
        assert False, "Old password should not work after regeneration"
    except ValueError:
        print("✓ Old password correctly rejected after regeneration")

def test_mixed_encryption_scenarios():
    """Test various combinations of encrypted and unencrypted keys"""
    print("\nTesting mixed encryption scenarios...")
    
    # Test user IDs
    user1 = 777777777  # No password
    user2 = 888888888  # With password
    user3 = 999999999  # Different password
    
    passwords = {
        user1: None,
        user2: "password_user2",
        user3: "password_user3"
    }
    
    # Clean up test keys
    for user_id in [user1, user2, user3]:
        user_dir = KEYS_DIR / str(user_id)
        if user_dir.exists():
            shutil.rmtree(user_dir)
    
    # Generate keys with different protection levels
    for user_id, password in passwords.items():
        generate_user_keys(user_id, password)
        private_pem, _ = load_user_keys(user_id)
        expected_encrypted = password is not None
        actual_encrypted = is_private_key_encrypted(private_pem)
        assert actual_encrypted == expected_encrypted, f"User {user_id} encryption status mismatch"
        print(f"✓ User {user_id}: {'encrypted' if password else 'unencrypted'} key generated correctly")
    
    # Test all combinations of message sending
    message = "Test message for mixed scenarios"
    combinations = [
        (user1, user2), (user1, user3),  # Unencrypted → Encrypted
        (user2, user1), (user3, user1),  # Encrypted → Unencrypted
        (user2, user3), (user3, user2),  # Encrypted → Encrypted (different passwords)
    ]
    
    for sender_id, receiver_id in combinations:
        sender_password = passwords[sender_id]
        receiver_password = passwords[receiver_id]
        
        # Encrypt message
        encrypted_data = encrypt_and_sign_message(message, sender_id, receiver_id, sender_password)
        
        # Decrypt message
        decrypted_message = decrypt_and_verify_message(encrypted_data, sender_id, receiver_id, receiver_password)
        
        assert message == decrypted_message, f"Failed for sender {sender_id} → receiver {receiver_id}"
        print(f"✓ User {sender_id} → User {receiver_id} successful")
    
    print("✓ All mixed encryption scenarios successful")

def cleanup_test_data():
    """Clean up test data"""
    print("\nCleaning up test data...")
    test_user_ids = [123456789, 987654321, 111111111, 222222222, 333333333, 
                     444444444, 555555555, 666666666, 777777777, 888888888, 999999999]
    
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
        test_password_protected_keys()
        test_key_regeneration()
        test_mixed_encryption_scenarios()
        
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