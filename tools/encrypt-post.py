#!/bin/bash
"exec" "$(dirname $0)/.venv/bin/python3" "$0" "$@"
# Above trick: bash runs first line, which exec's the venv python with this script
"""
Encrypt Jekyll posts for use with the encrypted.html layout.
Produces CryptoJS-compatible AES encryption.

Usage:
    ./encrypt-post.py <file1> [file2] [file3] ...
    ./encrypt-post.py _drafts/*

Examples:
    ./encrypt-post.py _drafts/secret-post.md
    ./encrypt-post.py _drafts/*.md
    ./encrypt-post.py _drafts/post1.md _drafts/post2.md
"""

import sys
import os
import re
import getpass
import hashlib
import base64
import glob
from datetime import datetime

# Try to import Crypto, provide helpful error if missing
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
except ImportError:
    print("Error: pycryptodome is required.")
    print("Install with: pip3 install pycryptodome")
    sys.exit(1)

# Try to import markdown for HTML conversion
try:
    import markdown
    HAS_MARKDOWN = True
except ImportError:
    HAS_MARKDOWN = False
    print("Warning: markdown module not found. Content will not be converted to HTML.")
    print("Install with: pip3 install markdown")


def evp_bytes_to_key(password: bytes, salt: bytes, key_len: int = 32, iv_len: int = 16):
    """
    OpenSSL EVP_BytesToKey key derivation (used by CryptoJS).
    """
    d = b''
    d_i = b''
    while len(d) < key_len + iv_len:
        d_i = hashlib.md5(d_i + password + salt).digest()
        d += d_i
    return d[:key_len], d[key_len:key_len + iv_len]


def encrypt_cryptojs_format(plaintext: str, password: str) -> str:
    """
    Encrypt text using CryptoJS-compatible AES encryption.
    Returns base64-encoded ciphertext in OpenSSL format.
    """
    salt = get_random_bytes(8)
    key, iv = evp_bytes_to_key(password.encode('utf-8'), salt)

    # PKCS7 padding
    block_size = 16
    padding_len = block_size - (len(plaintext.encode('utf-8')) % block_size)
    padded = plaintext.encode('utf-8') + bytes([padding_len] * padding_len)

    # Encrypt
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded)

    # OpenSSL format: "Salted__" + salt + ciphertext
    openssl_data = b'Salted__' + salt + ciphertext

    return base64.b64encode(openssl_data).decode('utf-8')


def parse_front_matter(content: str):
    """
    Parse YAML front matter from markdown file.
    Returns (front_matter_dict, body_content).
    """
    pattern = r'^---\s*\n(.*?)\n---\s*\n(.*)$'
    match = re.match(pattern, content, re.DOTALL)

    if not match:
        return {}, content

    front_matter_str = match.group(1)
    body = match.group(2)

    # Simple YAML parsing (key: value)
    front_matter = {}
    for line in front_matter_str.split('\n'):
        if ':' in line:
            key, value = line.split(':', 1)
            front_matter[key.strip()] = value.strip()

    return front_matter, body


def markdown_to_html(text: str) -> str:
    """Convert markdown to HTML."""
    if HAS_MARKDOWN:
        return markdown.markdown(text, extensions=['extra', 'codehilite', 'toc'])
    return f"<pre>{text}</pre>"


def get_output_path(input_file: str) -> str:
    """Generate output path in _posts/ directory."""
    basename = os.path.basename(input_file)

    # Check if filename already has date prefix
    date_pattern = r'^\d{4}-\d{2}-\d{2}-'
    if re.match(date_pattern, basename):
        return os.path.join('_posts', basename)
    else:
        # Add today's date
        date_prefix = datetime.now().strftime('%Y-%m-%d')
        return os.path.join('_posts', f"{date_prefix}-{basename}")


def encrypt_file(input_file: str, password: str) -> tuple:
    """
    Encrypt a single file.
    Returns (output_file, success, message).
    """
    try:
        # Read input file
        with open(input_file, 'r', encoding='utf-8') as f:
            content = f.read()

        # Parse front matter and body
        front_matter, body = parse_front_matter(content)

        if not body.strip():
            return (None, False, "Empty content")

        # Generate output path
        output_file = get_output_path(input_file)

        # Convert markdown body to HTML
        html_body = markdown_to_html(body.strip())

        # Encrypt the HTML content
        encrypted = encrypt_cryptojs_format(html_body, password)

        # Build output front matter
        front_matter['layout'] = 'encrypted'

        # Reconstruct front matter string
        front_matter_lines = ['---']
        for key, value in front_matter.items():
            front_matter_lines.append(f"{key}: {value}")
        front_matter_lines.append('---')
        front_matter_str = '\n'.join(front_matter_lines)

        # Write output file
        output_content = f"{front_matter_str}\n\n{encrypted}\n"

        os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(output_content)

        return (output_file, True, f"{len(body)} → {len(encrypted)} chars")

    except Exception as e:
        return (None, False, str(e))


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    # Collect all input files (shell already expands globs, but handle manually too)
    input_files = []
    for arg in sys.argv[1:]:
        if '*' in arg or '?' in arg:
            # Manual glob expansion
            expanded = glob.glob(arg)
            input_files.extend(expanded)
        elif os.path.isfile(arg):
            input_files.append(arg)
        elif os.path.isdir(arg):
            # If directory, get all .md files
            input_files.extend(glob.glob(os.path.join(arg, '*.md')))

    # Filter to only .md files
    input_files = [f for f in input_files if f.endswith('.md')]

    if not input_files:
        print("Error: No markdown files found")
        sys.exit(1)

    # Remove duplicates and sort
    input_files = sorted(set(input_files))

    print(f"\n📁 Found {len(input_files)} file(s) to encrypt:")
    for f in input_files:
        print(f"   • {f}")

    # Get password once for all files
    print()
    password = getpass.getpass("Enter encryption password: ")
    password_confirm = getpass.getpass("Confirm password: ")

    if password != password_confirm:
        print("Error: Passwords do not match!")
        sys.exit(1)

    if len(password) < 4:
        print("Error: Password too short (minimum 4 characters)")
        sys.exit(1)

    # Encrypt all files
    print(f"\n🔐 Encrypting...\n")
    results = []
    for input_file in input_files:
        output_file, success, message = encrypt_file(input_file, password)
        results.append((input_file, output_file, success, message))

        if success:
            print(f"   ✓ {os.path.basename(input_file)} → {output_file}")
        else:
            print(f"   ✗ {os.path.basename(input_file)}: {message}")

    # Summary
    successful = sum(1 for r in results if r[2])
    failed = len(results) - successful

    print(f"\n{'─' * 40}")
    print(f"✓ Encrypted: {successful}  ✗ Failed: {failed}")

    if successful > 0:
        print(f"\n⚠️  Remember: Only commit _posts/, not _drafts/!")


if __name__ == '__main__':
    main()
