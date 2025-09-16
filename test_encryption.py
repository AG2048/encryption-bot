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
    verify_signed_message,
    KEYS_DIR,
    # Password-related functions
    is_private_key_encrypted,
    load_private_key_with_password,
    encrypt_and_sign_message_with_password,
    decrypt_and_verify_message_with_password,
    sign_message_with_password
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
    
    # Alice encrypts a message for Bob (no password needed for new keys)
    encrypted_data = encrypt_and_sign_message_with_password(original_message, alice_id, bob_id, None)
    print(f"✓ Encrypted message (length: {len(encrypted_data)} chars)")
    print(f"  Preview: {encrypted_data[:50]}...")
    
    # Bob decrypts the message from Alice (no password needed for new keys)
    decrypted_message, signature_verified = decrypt_and_verify_message_with_password(encrypted_data, alice_id, bob_id, None)
    print(f"✓ Decrypted message: '{decrypted_message}'")
    print(f"✓ Signature verified: {signature_verified}")
    
    assert original_message == decrypted_message, "Message decryption failed"
    assert signature_verified == True, "Signature verification failed"
    print("✓ Encryption/decryption cycle successful")
    
    return alice_id, bob_id, encrypted_data

def test_signature_verification():
    """Test signature verification"""
    print("\nTesting signature verification...")
    
    alice_id, bob_id, encrypted_data = test_encryption_decryption()
    
    # Try to decrypt with wrong sender (should return False signature verification)
    try:
        decrypted_message, signature_verified = decrypt_and_verify_message_with_password(encrypted_data, bob_id, bob_id, None)  # Wrong sender
        if not signature_verified:
            print("✓ Correctly detected wrong sender (signature verification failed)")
        else:
            assert False, "Should have detected wrong sender"
    except ValueError as e:
        print(f"✓ Correctly rejected wrong sender: {e}")
    
    # Try to decrypt with wrong receiver (should fail due to decryption)
    try:
        decrypt_and_verify_message_with_password(encrypted_data, alice_id, alice_id, None)  # Wrong receiver
        assert False, "Should have failed with wrong receiver"
    except ValueError as e:
        print(f"✓ Correctly rejected wrong receiver: {e}")
    
    print("✓ Signature verification working correctly")

def test_sign_verify_message():
    """Test message signing and verification"""
    print("\nTesting message signing and verification...")
    
    alice_id = 444444444
    bob_id = 555555555
    
    # Clean up test keys
    for user_id in [alice_id, bob_id]:
        user_dir = KEYS_DIR / str(user_id)
        if user_dir.exists():
            shutil.rmtree(user_dir)
    
    # Test message
    original_message = "Hello! This is a signed message from Alice. ✍️"
    
    # Generate keys for Alice before signing
    generate_user_keys(alice_id)
    
    # Alice signs a message (no password needed for new keys)
    signed_data = sign_message_with_password(original_message, alice_id, None)
    print(f"✓ Signed message (length: {len(signed_data)} chars)")
    print(f"  Preview: {signed_data[:50]}...")
    
    # Verify the signed message
    verified_message = verify_signed_message(signed_data, alice_id)
    print(f"✓ Verified message: '{verified_message}'")
    
    assert original_message == verified_message, "Message verification failed"
    print("✓ Sign/verify cycle successful")
    
    # Try to verify with wrong sender (should fail)
    # Generate keys for Bob before using him as wrong sender
    generate_user_keys(bob_id)
    try:
        verify_signed_message(signed_data, bob_id)  # Wrong sender
        assert False, "Should have failed with wrong sender"
    except ValueError as e:
        print(f"✓ Correctly rejected wrong sender: {e}")
    
    print("✓ Signature verification working correctly for signed messages")
    
    return alice_id, bob_id, signed_data

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
    
    # Generate keys for all users
    generate_user_keys(alice_id)
    generate_user_keys(bob_id) 
    generate_user_keys(charlie_id)
    
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
        encrypted = encrypt_and_sign_message_with_password(message, alice_id, bob_id, None)
        decrypted, verified = decrypt_and_verify_message_with_password(encrypted, alice_id, bob_id, None)
        assert message == decrypted, f"Message {i+1} failed"
        assert verified == True, f"Signature verification failed for message {i+1}"
        
        # Bob sends to Charlie
        encrypted = encrypt_and_sign_message_with_password(message, bob_id, charlie_id, None)
        decrypted, verified = decrypt_and_verify_message_with_password(encrypted, bob_id, charlie_id, None)
        assert message == decrypted, f"Message {i+1} failed"
        assert verified == True, f"Signature verification failed for message {i+1}"
    
    print("✓ All messages encrypted/decrypted successfully")

def test_multiple_signed_messages():
    """Test multiple message signing/verification"""
    print("\nTesting multiple signed messages...")
    
    alice_id = 666666666
    bob_id = 777777777
    
    # Clean up test keys
    for user_id in [alice_id, bob_id]:
        user_dir = KEYS_DIR / str(user_id)
        if user_dir.exists():
            shutil.rmtree(user_dir)
    
    # Generate keys for both users
    generate_user_keys(alice_id)
    generate_user_keys(bob_id)
    
    messages = [
        "Short signed message",
        "This is a longer signed message with more content to test signing of various message lengths.",
        "Signed message with special characters: àáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ !@#$%^&*()_+-=[]{}|;':\",./<>?",
        "Signed emoji test: ✍️📝🔏✅🔍⚡🚀🎉",
        ""  # Empty message
    ]
    
    for i, message in enumerate(messages):
        print(f"  Testing signed message {i+1}: '{message[:30]}{'...' if len(message) > 30 else ''}'")
        
        # Alice signs message
        signed = sign_message_with_password(message, alice_id, None)
        verified = verify_signed_message(signed, alice_id)
        assert message == verified, f"Signed message {i+1} failed"
        
        # Bob signs message
        signed = sign_message_with_password(message, bob_id, None)
        verified = verify_signed_message(signed, bob_id)
        assert message == verified, f"Signed message {i+1} failed"
    
    print("✓ All signed messages verified successfully")

def test_password_protected_keys():
    """Test password-protected key generation and detection"""
    print("\nTesting password-protected keys...")
    
    alice_id = 888888888
    bob_id = 999999999
    
    # Clean up test keys
    for user_id in [alice_id, bob_id]:
        user_dir = KEYS_DIR / str(user_id)
        if user_dir.exists():
            shutil.rmtree(user_dir)
    
    # Generate password-protected key for Alice
    alice_password = "supersecret123!"
    alice_private, alice_public = generate_user_keys(alice_id, alice_password)
    print(f"✓ Generated password-protected keys for Alice")
    
    # Generate regular key for Bob (no password)
    bob_private, bob_public = generate_user_keys(bob_id)
    print(f"✓ Generated regular keys for Bob")
    
    # Test key encryption detection
    assert is_private_key_encrypted(alice_id) == True, "Alice's key should be detected as encrypted"
    assert is_private_key_encrypted(bob_id) == False, "Bob's key should be detected as unencrypted"
    print("✓ Key encryption detection working correctly")
    
    # Test loading private key with password
    alice_key = load_private_key_with_password(alice_id, alice_password)
    print("✓ Successfully loaded Alice's private key with password")
    
    # Test loading private key without password (should fail for Alice)
    try:
        load_private_key_with_password(alice_id, None)
        assert False, "Should have failed loading encrypted key without password"
    except ValueError as e:
        assert "password-protected" in str(e).lower()
        print("✓ Correctly rejected loading encrypted key without password")
    
    # Test loading private key with wrong password (should fail)
    try:
        load_private_key_with_password(alice_id, "wrongpassword")
        assert False, "Should have failed with wrong password"
    except ValueError as e:
        assert "invalid password" in str(e).lower()
        print("✓ Correctly rejected wrong password")
    
    # Test loading Bob's key (no password required)
    bob_key = load_private_key_with_password(bob_id, None)
    print("✓ Successfully loaded Bob's private key without password")
    
    return alice_id, bob_id, alice_password

def test_password_protected_encryption():
    """Test encryption and decryption with password-protected keys"""
    print("\nTesting password-protected encryption/decryption...")
    
    alice_id, bob_id, alice_password = test_password_protected_keys()
    
    # Test message
    original_message = "Hello Bob! This is encrypted with Alice's password-protected key. 🔐"
    
    # Alice encrypts a message for Bob (Alice's key is password-protected)
    encrypted_data = encrypt_and_sign_message_with_password(original_message, alice_id, bob_id, alice_password)
    print(f"✓ Encrypted message with password-protected sender key")
    
    # Bob decrypts the message from Alice (Bob's key is not password-protected)
    decrypted_message, signature_verified = decrypt_and_verify_message_with_password(encrypted_data, alice_id, bob_id, None)
    print(f"✓ Decrypted message: '{decrypted_message}'")
    print(f"✓ Signature verified: {signature_verified}")
    
    assert original_message == decrypted_message, "Message encryption/decryption failed"
    assert signature_verified == True, "Signature verification failed"
    print("✓ Password-protected encryption/decryption cycle successful")
    
    # Test decryption with wrong sender password (should fail during encryption)
    try:
        encrypt_and_sign_message_with_password(original_message, alice_id, bob_id, "wrongpassword")
        assert False, "Should have failed with wrong sender password"
    except ValueError as e:
        print(f"✓ Correctly rejected encryption with wrong sender password")
    
    return alice_id, bob_id, alice_password, encrypted_data

def test_password_protected_signing():
    """Test signing and verification with password-protected keys"""
    print("\nTesting password-protected signing/verification...")
    
    alice_id, bob_id, alice_password, _ = test_password_protected_encryption()
    
    # Test message
    original_message = "This is a signed message from Alice with her password-protected key. ✍️🔐"
    
    # Alice signs a message (Alice's key is password-protected)
    signed_data = sign_message_with_password(original_message, alice_id, alice_password)
    print(f"✓ Signed message with password-protected key")
    
    # Verify the signed message
    verified_message = verify_signed_message(signed_data, alice_id)
    print(f"✓ Verified message: '{verified_message}'")
    
    assert original_message == verified_message, "Message signing/verification failed"
    print("✓ Password-protected signing/verification cycle successful")
    
    # Test signing with wrong password (should fail)
    try:
        sign_message_with_password(original_message, alice_id, "wrongpassword")
        assert False, "Should have failed with wrong password"
    except ValueError as e:
        print(f"✓ Correctly rejected signing with wrong password")
    
    return alice_id, bob_id, alice_password

def test_mixed_password_scenarios():
    """Test scenarios with mixed password-protected and regular keys"""
    print("\nTesting mixed password scenarios...")
    
    alice_id, bob_id, alice_password = test_password_protected_signing()
    charlie_id = 1010101010
    
    # Clean up Charlie's keys
    charlie_dir = KEYS_DIR / str(charlie_id)
    if charlie_dir.exists():
        shutil.rmtree(charlie_dir)
    
    # Generate password-protected key for Charlie too
    charlie_password = "charlie_secret_789"
    generate_user_keys(charlie_id, charlie_password)
    print(f"✓ Generated password-protected keys for Charlie")
    
    # Test: Alice (password-protected) sends to Charlie (password-protected)
    message1 = "Hello Charlie from Alice! Both our keys are password-protected. 🔐🔐"
    encrypted1 = encrypt_and_sign_message_with_password(message1, alice_id, charlie_id, alice_password)
    decrypted1, verified1 = decrypt_and_verify_message_with_password(encrypted1, alice_id, charlie_id, charlie_password)
    assert message1 == decrypted1, "Password-to-password encryption failed"
    assert verified1 == True, "Password-to-password signature verification failed"
    print("✓ Password-protected sender to password-protected receiver works")
    
    # Test: Bob (no password) sends to Charlie (password-protected)
    message2 = "Hello Charlie from Bob! My key has no password but yours does. 🔓🔐"
    encrypted2 = encrypt_and_sign_message_with_password(message2, bob_id, charlie_id, None)
    decrypted2, verified2 = decrypt_and_verify_message_with_password(encrypted2, bob_id, charlie_id, charlie_password)
    assert message2 == decrypted2, "No-password-to-password encryption failed"
    assert verified2 == True, "No-password-to-password signature verification failed"
    print("✓ Non-password sender to password-protected receiver works")
    
    # Test: Alice (password-protected) sends to Bob (no password)
    message3 = "Hello Bob from Alice! My key has password but yours doesn't. 🔐🔓"
    encrypted3 = encrypt_and_sign_message_with_password(message3, alice_id, bob_id, alice_password)
    decrypted3, verified3 = decrypt_and_verify_message_with_password(encrypted3, alice_id, bob_id, None)
    assert message3 == decrypted3, "Password-to-no-password encryption failed"
    assert verified3 == True, "Password-to-no-password signature verification failed"
    print("✓ Password-protected sender to non-password receiver works")
    
    print("✓ All mixed password scenarios working correctly")
    
    return alice_id, bob_id, charlie_id, alice_password, charlie_password


    
    return alice_id, bob_id, charlie_id

def cleanup_password_test_data():
    """Clean up password test data"""
    print("\nCleaning up password test data...")
    test_user_ids = [888888888, 999999999, 1010101010]
    
    for user_id in test_user_ids:
        user_dir = KEYS_DIR / str(user_id)
        if user_dir.exists():
            shutil.rmtree(user_dir)
            print(f"  Removed keys for user {user_id}")
    
    print("✓ Password test cleanup complete")

def cleanup_test_data():
    """Clean up test data"""
    print("\nCleaning up test data...")
    test_user_ids = [123456789, 987654321, 111111111, 222222222, 333333333, 444444444, 555555555, 666666666, 777777777]
    
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
        # Original tests
        test_key_generation()
        test_encryption_decryption()
        test_signature_verification()
        test_sign_verify_message()
        test_multiple_messages()
        test_multiple_signed_messages()
        
        # New password protection tests
        test_password_protected_keys()
        test_password_protected_encryption()
        test_password_protected_signing()
        test_mixed_password_scenarios()
        
        print("\n" + "=" * 40)
        print("🎉 All tests passed!")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    finally:
        cleanup_test_data()
        cleanup_password_test_data()
    
    return 0

if __name__ == "__main__":
    exit(main())