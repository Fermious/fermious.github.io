#!/bin/bash
"exec" "$(dirname $0)/.venv/bin/python3" "$0" "$@"
# Above trick: bash runs first line, which exec's the venv python with this script
"""
Encrypt/Decrypt Jekyll posts for use with the encrypted.html layout.
Produces CryptoJS-compatible AES encryption.

Usage:
    # Encrypt
    ./encrypt-post.py <file1> [file2] [file3] ...
    ./encrypt-post.py _drafts/*

    # Decrypt
    ./encrypt-post.py -d <encrypted_post>
    ./encrypt-post.py --decrypt _posts/2024-01-01-secret.md

Examples:
    ./encrypt-post.py _drafts/secret-post.md
    ./encrypt-post.py _drafts/*.md
    ./encrypt-post.py --decrypt _posts/2024-01-01-my-post.md
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

# Try to import html2text for HTML→markdown conversion
try:
    import html2text
    HAS_HTML2TEXT = True
except ImportError:
    HAS_HTML2TEXT = False


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


def decrypt_cryptojs_format(ciphertext_b64: str, password: str) -> str:
    """
    Decrypt CryptoJS-compatible AES encryption.
    Returns plaintext string.
    """
    # Decode base64
    data = base64.b64decode(ciphertext_b64)

    # Check OpenSSL format: "Salted__" + 8-byte salt + ciphertext
    if not data.startswith(b'Salted__'):
        raise ValueError("Invalid format: missing 'Salted__' prefix")

    salt = data[8:16]
    ciphertext = data[16:]

    # Derive key and IV
    key, iv = evp_bytes_to_key(password.encode('utf-8'), salt)

    # Decrypt
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = cipher.decrypt(ciphertext)

    # Remove PKCS7 padding
    padding_len = padded[-1]
    if padding_len > 16:
        raise ValueError("Invalid padding")
    plaintext = padded[:-padding_len]

    return plaintext.decode('utf-8')


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


def html_to_markdown(html: str) -> tuple:
    """
    Convert HTML to markdown.
    Returns (markdown_text, list_of_warnings).
    """
    warnings = []

    if not HAS_HTML2TEXT:
        warnings.append("html2text not installed - returning raw HTML")
        return html, warnings

    # Detect potential formatting loss before conversion
    if '<pre' in html or '<code' in html:
        code_blocks = len(re.findall(r'<pre[^>]*>', html))
        if code_blocks > 0:
            warnings.append(f"{code_blocks} code block(s) - syntax highlighting may be lost")

    if '<table' in html:
        tables = len(re.findall(r'<table[^>]*>', html))
        warnings.append(f"{tables} table(s)")

    if '<figure' in html or '<figcaption' in html:
        figures = len(re.findall(r'<figure[^>]*>', html))
        warnings.append(f"{figures} figure(s) with captions")

    if re.search(r'class="[^"]*"', html) or '<style' in html:
        warnings.append("custom CSS/styling")

    if '<sup' in html and 'footnote' in html.lower():
        warnings.append("footnotes")

    # Convert
    h = html2text.HTML2Text()
    h.ignore_links = False
    h.ignore_images = False
    h.body_width = 0  # Don't wrap lines
    md = h.handle(html)

    return md.strip(), warnings


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


def get_draft_output_path(input_file: str) -> str:
    """Generate output path in _drafts/ directory (strips date prefix)."""
    basename = os.path.basename(input_file)

    # Remove date prefix if present
    date_pattern = r'^\d{4}-\d{2}-\d{2}-'
    basename = re.sub(date_pattern, '', basename)

    return os.path.join('_drafts', basename)


def find_original_draft(encrypted_file: str) -> str:
    """
    Look for original draft file that matches the encrypted post.
    Returns path if found, None otherwise.
    """
    basename = os.path.basename(encrypted_file)

    # Remove date prefix
    date_pattern = r'^\d{4}-\d{2}-\d{2}-'
    draft_name = re.sub(date_pattern, '', basename)

    draft_path = os.path.join('_drafts', draft_name)

    if os.path.exists(draft_path):
        return draft_path
    return None


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


def decrypt_file(input_file: str, password: str) -> tuple:
    """
    Decrypt a single encrypted post.
    Returns (output_file, success, message, warnings).
    """
    warnings = []

    try:
        # Check if original draft exists
        original_draft = find_original_draft(input_file)
        if original_draft:
            output_file = get_draft_output_path(input_file)
            # Just copy the original
            import shutil
            shutil.copy2(original_draft, output_file)
            return (output_file, True, "Restored from original draft", [])

        # Read encrypted file
        with open(input_file, 'r', encoding='utf-8') as f:
            content = f.read()

        # Parse front matter and encrypted body
        front_matter, encrypted_body = parse_front_matter(content)

        if not encrypted_body.strip():
            return (None, False, "Empty content", [])

        # Extract base64 ciphertext (strip whitespace)
        ciphertext = encrypted_body.strip()

        # Decrypt
        html_content = decrypt_cryptojs_format(ciphertext, password)

        # Convert HTML to markdown
        md_content, conv_warnings = html_to_markdown(html_content)
        warnings.extend(conv_warnings)

        # Update front matter (remove encrypted layout)
        if front_matter.get('layout') == 'encrypted':
            del front_matter['layout']

        # Reconstruct front matter string
        front_matter_lines = ['---']
        for key, value in front_matter.items():
            front_matter_lines.append(f"{key}: {value}")
        front_matter_lines.append('---')
        front_matter_str = '\n'.join(front_matter_lines)

        # Generate output path
        output_file = get_draft_output_path(input_file)

        # Write output file
        output_content = f"{front_matter_str}\n\n{md_content}\n"

        os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(output_content)

        return (output_file, True, f"{len(ciphertext)} → {len(md_content)} chars", warnings)

    except ValueError as e:
        if "padding" in str(e).lower() or "invalid" in str(e).lower():
            return (None, False, "Wrong password or corrupted data", [])
        return (None, False, str(e), [])
    except Exception as e:
        return (None, False, str(e), [])


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    # Check for decrypt flag
    decrypt_mode = False
    args = sys.argv[1:]

    if args[0] in ['-d', '--decrypt']:
        decrypt_mode = True
        args = args[1:]

    if not args:
        print("Error: No files specified")
        sys.exit(1)

    # Collect all input files
    input_files = []
    for arg in args:
        if '*' in arg or '?' in arg:
            expanded = glob.glob(arg)
            input_files.extend(expanded)
        elif os.path.isfile(arg):
            input_files.append(arg)
        elif os.path.isdir(arg):
            input_files.extend(glob.glob(os.path.join(arg, '*.md')))

    # Filter to only .md files
    input_files = [f for f in input_files if f.endswith('.md')]

    if not input_files:
        print("Error: No markdown files found")
        sys.exit(1)

    # Remove duplicates and sort
    input_files = sorted(set(input_files))

    mode_str = "decrypt" if decrypt_mode else "encrypt"
    print(f"\n📁 Found {len(input_files)} file(s) to {mode_str}:")
    for f in input_files:
        print(f"   • {f}")

    # Get password
    print()
    password = getpass.getpass(f"Enter {'decryption' if decrypt_mode else 'encryption'} password: ")

    if not decrypt_mode:
        password_confirm = getpass.getpass("Confirm password: ")
        if password != password_confirm:
            print("Error: Passwords do not match!")
            sys.exit(1)

    if len(password) < 4:
        print("Error: Password too short (minimum 4 characters)")
        sys.exit(1)

    # Process files
    icon = "🔓" if decrypt_mode else "🔐"
    print(f"\n{icon} {'Decrypting' if decrypt_mode else 'Encrypting'}...\n")

    results = []
    all_warnings = []

    for input_file in input_files:
        if decrypt_mode:
            output_file, success, message, warnings = decrypt_file(input_file, password)
            all_warnings.extend(warnings)
        else:
            output_file, success, message = encrypt_file(input_file, password)
            warnings = []

        results.append((input_file, output_file, success, message))

        if success:
            print(f"   ✓ {os.path.basename(input_file)} → {output_file}")
        else:
            print(f"   ✗ {os.path.basename(input_file)}: {message}")

    # Summary
    successful = sum(1 for r in results if r[2])
    failed = len(results) - successful

    print(f"\n{'─' * 40}")
    print(f"✓ {'Decrypted' if decrypt_mode else 'Encrypted'}: {successful}  ✗ Failed: {failed}")

    # Show warnings for decrypt mode
    if decrypt_mode and all_warnings:
        print(f"\n⚠️  Formatting warnings:")
        for w in all_warnings:
            print(f"   • {w}")

    if not decrypt_mode and successful > 0:
        print(f"\n⚠️  Remember: Only commit _posts/, not _drafts/!")


if __name__ == '__main__':
    main()
