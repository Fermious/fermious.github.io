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
    Returns (front_matter_dict, front_matter_raw_str, body_content).

    The dict contains only root-level keys for simple lookups.
    The raw string preserves the original structure including nested YAML.
    """
    pattern = r'^---\s*\n(.*?)\n---\s*\n(.*)$'
    match = re.match(pattern, content, re.DOTALL)

    if not match:
        return {}, '', content

    front_matter_str = match.group(1)
    body = match.group(2)

    # Simple YAML parsing for root-level keys only (for lookups)
    front_matter = {}
    for line in front_matter_str.split('\n'):
        # Only parse root-level keys (lines that don't start with whitespace)
        if line and not line[0].isspace() and ':' in line:
            key, value = line.split(':', 1)
            front_matter[key.strip()] = value.strip()

    return front_matter, front_matter_str, body


def update_front_matter(raw_front_matter: str, updates: dict = None, removals: list = None) -> str:
    """
    Update/add/remove keys in front matter while preserving structure.
    Only modifies root-level keys. Nested content under a key is preserved or removed with it.

    Args:
        raw_front_matter: The original front matter string (without --- delimiters)
        updates: Dict of {key: value} to update or add
        removals: List of keys to remove

    Returns:
        Updated front matter string
    """
    updates = updates or {}
    removals = removals or []

    lines = raw_front_matter.split('\n')
    result_lines = []
    skip_until_root = False
    updated_keys = set()

    i = 0
    while i < len(lines):
        line = lines[i]

        # Check if this is a root-level key (no leading whitespace)
        if line and not line[0].isspace() and ':' in line:
            key = line.split(':', 1)[0].strip()

            if key in removals:
                # Skip this line and any indented lines that follow
                i += 1
                while i < len(lines) and lines[i] and lines[i][0].isspace():
                    i += 1
                continue

            if key in updates:
                # Replace this line with updated value
                result_lines.append(f"{key}: {updates[key]}")
                updated_keys.add(key)
                # Skip any indented lines that follow (nested content is replaced)
                i += 1
                while i < len(lines) and lines[i] and lines[i][0].isspace():
                    i += 1
                continue

        result_lines.append(line)
        i += 1

    # Add any new keys that weren't updates to existing ones
    for key, value in updates.items():
        if key not in updated_keys:
            result_lines.append(f"{key}: {value}")

    return '\n'.join(result_lines)


def markdown_to_html(text: str) -> str:
    """Convert markdown to HTML."""
    if HAS_MARKDOWN:
        return markdown.markdown(text, extensions=['extra', 'codehilite', 'toc'])
    return f"<pre>{text}</pre>"


# Regex pattern for :::encrypted blocks with optional {title="..." hint="..."} attributes
ENCRYPTED_BLOCK_PATTERN = r'^:::encrypted(?:\{([^}]*)\})?\s*\n(.*?)\n^:::(?:\s*$|\n)'


def parse_block_attrs(attrs_str: str) -> dict:
    """
    Parse title="value" hint="value" from attribute string.
    Returns dict with 'title' and 'hint' keys (None if not specified).
    """
    if not attrs_str:
        return {'title': None, 'hint': None}

    title_match = re.search(r'title="([^"]*)"', attrs_str)
    hint_match = re.search(r'hint="([^"]*)"', attrs_str)

    return {
        'title': title_match.group(1) if title_match else None,
        'hint': hint_match.group(1) if hint_match else None
    }


def find_encrypted_blocks(content: str) -> list:
    """
    Find all :::encrypted ... ::: blocks in content.
    Returns list of tuples: [(start, end, block_content, attrs_dict), ...]
    """
    blocks = []
    for match in re.finditer(ENCRYPTED_BLOCK_PATTERN, content, re.MULTILINE | re.DOTALL):
        attrs = parse_block_attrs(match.group(1))
        blocks.append((match.start(), match.end(), match.group(2), attrs))
    return blocks


def has_encrypted_blocks(content: str) -> bool:
    """Check if content contains :::encrypted blocks."""
    return bool(re.search(ENCRYPTED_BLOCK_PATTERN, content, re.MULTILINE | re.DOTALL))


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


def encrypt_partial_file(input_file: str, passwords: list) -> tuple:
    """
    Encrypt a file with :::encrypted blocks (partial encryption).
    Each block can have a different password.
    Returns (output_file, success, message).
    """
    try:
        # Read input file
        with open(input_file, 'r', encoding='utf-8') as f:
            content = f.read()

        # Parse front matter and body
        front_matter, front_matter_raw, body = parse_front_matter(content)

        if not body.strip():
            return (None, False, "Empty content")

        # Find encrypted blocks
        blocks = find_encrypted_blocks(body)

        if len(blocks) != len(passwords):
            return (None, False, f"Password count mismatch: {len(blocks)} blocks, {len(passwords)} passwords")

        # Process content: replace each :::encrypted block with encrypted HTML
        # Work backwards to preserve indices
        result = body
        for i, (start, end, block_content, attrs) in enumerate(reversed(blocks)):
            block_idx = len(blocks) - i  # 1-indexed from the end
            password = passwords[len(blocks) - 1 - i]

            # Get custom title and hint, or use defaults
            custom_title = attrs.get('title')
            custom_hint = attrs.get('hint')
            title = custom_title or f"Encrypted Section {block_idx}"
            hint = custom_hint or "Password"

            # Convert block content to HTML
            html_content = markdown_to_html(block_content.strip())

            # Encrypt the HTML
            encrypted = encrypt_cryptojs_format(html_content, password)

            # Build data attributes (only include title/hint if custom values were set)
            data_attrs = f'data-encrypted="{encrypted}" data-block="{block_idx}"'
            if custom_title:
                data_attrs += f' data-title="{custom_title}"'
            if custom_hint:
                data_attrs += f' data-hint="{custom_hint}"'

            # Create the encrypted block HTML (compact bar style)
            encrypted_html = f'''<div class="encrypted-bar" {data_attrs}>
  <div class="bar-left">
    <i class="fas fa-lock bar-icon"></i>
    <span class="bar-title">{title}</span>
  </div>
  <div class="bar-right">
    <input type="password" placeholder="{hint}">
    <button class="bar-unlock" type="button"><i class="fas fa-unlock-alt"></i></button>
  </div>
  <span class="bar-error"><i class="fas fa-times"></i></span>
</div>
<div class="encrypted-content"></div>'''

            result = result[:start] + encrypted_html + result[end:]

        # Convert remaining markdown to HTML (the non-encrypted parts)
        # We need to be careful here - the encrypted blocks are already HTML
        # So we use a placeholder approach
        placeholder_prefix = "<!--ENCRYPTED_PLACEHOLDER_"
        placeholder_suffix = "_END-->"

        # Replace encrypted bars with placeholders
        encrypted_divs = []
        temp_result = result
        # Match the encrypted bar + its content div
        div_pattern = r'<div class="encrypted-bar".*?</div>\s*<div class="encrypted-content"></div>'
        for match in re.finditer(div_pattern, result, re.DOTALL):
            encrypted_divs.append(match.group(0))

        for i, div in enumerate(encrypted_divs):
            temp_result = temp_result.replace(div, f"{placeholder_prefix}{i}{placeholder_suffix}", 1)

        # Convert markdown to HTML
        html_result = markdown_to_html(temp_result)

        # Restore encrypted divs
        for i, div in enumerate(encrypted_divs):
            html_result = html_result.replace(f"{placeholder_prefix}{i}{placeholder_suffix}", div)

        # Generate output path
        output_file = get_output_path(input_file)

        # Add has_encrypted_sections flag (keep original layout intact)
        updated_front_matter = update_front_matter(front_matter_raw, {'has_encrypted_sections': 'true'})

        # Write output file
        output_content = f"---\n{updated_front_matter}\n---\n\n{html_result}\n"

        os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(output_content)

        return (output_file, True, f"{len(blocks)} encrypted block(s)")

    except Exception as e:
        return (None, False, str(e))


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
        front_matter, front_matter_raw, body = parse_front_matter(content)

        if not body.strip():
            return (None, False, "Empty content")

        # Generate output path
        output_file = get_output_path(input_file)

        # Convert markdown body to HTML
        html_body = markdown_to_html(body.strip())

        # Encrypt the HTML content
        encrypted = encrypt_cryptojs_format(html_body, password)

        # Update front matter with layout (preserves nested YAML structure)
        updated_front_matter = update_front_matter(front_matter_raw, {'layout': 'encrypted'})

        # Write output file
        output_content = f"---\n{updated_front_matter}\n---\n\n{encrypted}\n"

        os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(output_content)

        return (output_file, True, f"{len(body)} → {len(encrypted)} chars")

    except Exception as e:
        return (None, False, str(e))


def decrypt_partial_file(input_file: str, passwords: list) -> tuple:
    """
    Decrypt a partial-encrypted post.
    Returns (output_file, success, message, warnings).
    """
    warnings = []

    try:
        # Check if original draft exists
        original_draft = find_original_draft(input_file)
        if original_draft:
            output_file = get_draft_output_path(input_file)
            import shutil
            shutil.copy2(original_draft, output_file)
            return (output_file, True, "Restored from original draft", [])

        # Read encrypted file
        with open(input_file, 'r', encoding='utf-8') as f:
            content = f.read()

        # Parse front matter and HTML body
        front_matter, front_matter_raw, html_body = parse_front_matter(content)

        if not html_body.strip():
            return (None, False, "Empty content", [])

        # Find all encrypted bars in HTML (with optional title/hint attributes)
        block_pattern = r'<div class="encrypted-bar" data-encrypted="([^"]+)" data-block="(\d+)"(?:\s+data-title="([^"]*)")?(?:\s+data-hint="([^"]*)")?>'
        blocks = list(re.finditer(block_pattern, html_body))

        if len(blocks) != len(passwords):
            return (None, False, f"Password count mismatch: {len(blocks)} blocks, {len(passwords)} passwords", [])

        # Decrypt each block and rebuild markdown
        result = html_body

        # Process in reverse to preserve indices
        for i, match in enumerate(reversed(blocks)):
            block_idx = len(blocks) - i - 1
            ciphertext = match.group(1)
            password = passwords[block_idx]
            custom_title = match.group(3)  # May be None
            custom_hint = match.group(4)   # May be None

            try:
                # Decrypt
                html_content = decrypt_cryptojs_format(ciphertext, password)

                # Convert HTML to markdown
                md_content, conv_warnings = html_to_markdown(html_content)
                warnings.extend(conv_warnings)

                # Find the full bar + content div and replace with :::encrypted block
                div_start = match.start()
                # Find the closing encrypted-content div
                content_div = '<div class="encrypted-content"></div>'
                div_end = result.find(content_div, div_start)
                if div_end != -1:
                    div_end += len(content_div)
                else:
                    # Fallback: find end of bar div
                    div_end = result.find('</div>', div_start)
                    if div_end != -1:
                        div_end += len('</div>')

                # Reconstruct :::encrypted block with optional attributes
                attrs_parts = []
                if custom_title:
                    attrs_parts.append(f'title="{custom_title}"')
                if custom_hint:
                    attrs_parts.append(f'hint="{custom_hint}"')

                if attrs_parts:
                    encrypted_block = f":::encrypted{{{' '.join(attrs_parts)}}}\n{md_content}\n:::"
                else:
                    encrypted_block = f":::encrypted\n{md_content}\n:::"

                result = result[:div_start] + encrypted_block + result[div_end:]

            except ValueError as e:
                return (None, False, f"Block {block_idx + 1}: Wrong password or corrupted data", [])

        # Convert remaining HTML to markdown
        md_result, conv_warnings = html_to_markdown(result)
        warnings.extend(conv_warnings)

        # Update front matter - remove has_encrypted_sections flag (preserves nested YAML structure)
        updated_front_matter = update_front_matter(front_matter_raw, removals=['has_encrypted_sections'])

        # Generate output path
        output_file = get_draft_output_path(input_file)

        # Write output file
        output_content = f"---\n{updated_front_matter}\n---\n\n{md_result}\n"

        os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(output_content)

        return (output_file, True, f"Decrypted {len(blocks)} block(s)", warnings)

    except Exception as e:
        return (None, False, str(e), [])


def decrypt_file(input_file: str, password: str) -> tuple:
    """
    Decrypt a single encrypted post (full encryption).
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
        front_matter, front_matter_raw, encrypted_body = parse_front_matter(content)

        if not encrypted_body.strip():
            return (None, False, "Empty content", [])

        # Extract base64 ciphertext (strip whitespace)
        ciphertext = encrypted_body.strip()

        # Decrypt
        html_content = decrypt_cryptojs_format(ciphertext, password)

        # Convert HTML to markdown
        md_content, conv_warnings = html_to_markdown(html_content)
        warnings.extend(conv_warnings)

        # Update front matter - remove layout (preserves nested YAML structure)
        updated_front_matter = update_front_matter(front_matter_raw, removals=['layout'])

        # Generate output path
        output_file = get_draft_output_path(input_file)

        # Write output file
        output_content = f"---\n{updated_front_matter}\n---\n\n{md_content}\n"

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


def get_file_layout(filepath: str) -> str:
    """Get the layout from a file's front matter."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        front_matter, _, _ = parse_front_matter(content)
        return front_matter.get('layout', '')
    except:
        return ''


def has_encrypted_sections(filepath: str) -> bool:
    """Check if a file has encrypted sections (partial encryption)."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        front_matter, _, _ = parse_front_matter(content)
        return front_matter.get('has_encrypted_sections', '').lower() == 'true'
    except:
        return False


def count_encrypted_blocks_in_file(filepath: str) -> int:
    """Count encrypted bars in a partial-encrypted file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        # Match bars with optional title/hint attributes
        block_pattern = r'<div class="encrypted-bar" data-encrypted="[^"]+" data-block="\d+"'
        return len(re.findall(block_pattern, content))
    except:
        return 0


def prompt_passwords_for_blocks(num_blocks: int, decrypt_mode: bool = False) -> list:
    """
    Prompt for passwords for each encrypted block.
    Returns list of passwords.
    """
    passwords = []

    for i in range(num_blocks):
        block_num = i + 1
        if i == 0:
            password = getpass.getpass(f"   Password for block {block_num}: ")
            if not decrypt_mode:
                confirm = getpass.getpass(f"   Confirm password for block {block_num}: ")
                if password != confirm:
                    print("   Error: Passwords do not match!")
                    sys.exit(1)
        else:
            password = getpass.getpass(f"   Password for block {block_num} (Enter for same): ")
            if not password:
                password = passwords[-1]  # Use previous password
            elif not decrypt_mode:
                # Only confirm if different from previous
                if password != passwords[-1]:
                    confirm = getpass.getpass(f"   Confirm password for block {block_num}: ")
                    if password != confirm:
                        print("   Error: Passwords do not match!")
                        sys.exit(1)

        if len(password) < 4:
            print("   Error: Password too short (minimum 4 characters)")
            sys.exit(1)

        passwords.append(password)

    return passwords


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

    # Process files
    icon = "🔓" if decrypt_mode else "🔐"
    print(f"\n{icon} {'Decrypting' if decrypt_mode else 'Encrypting'}...\n")

    results = []
    all_warnings = []

    for input_file in input_files:
        print(f"   Processing: {os.path.basename(input_file)}")

        if decrypt_mode:
            # Check if partial encryption (has_encrypted_sections flag)
            if has_encrypted_sections(input_file):
                # Partial decryption
                num_blocks = count_encrypted_blocks_in_file(input_file)
                print(f"   Found {num_blocks} encrypted block(s)")
                passwords = prompt_passwords_for_blocks(num_blocks, decrypt_mode=True)
                output_file, success, message, warnings = decrypt_partial_file(input_file, passwords)
            else:
                # Full decryption
                password = getpass.getpass("   Enter decryption password: ")
                if len(password) < 4:
                    print("   Error: Password too short (minimum 4 characters)")
                    results.append((input_file, None, False, "Password too short"))
                    continue
                output_file, success, message, warnings = decrypt_file(input_file, password)

            all_warnings.extend(warnings)

        else:
            # Encryption - check for :::encrypted blocks
            with open(input_file, 'r', encoding='utf-8') as f:
                content = f.read()
            _, _, body = parse_front_matter(content)
            blocks = find_encrypted_blocks(body)

            if blocks:
                # Partial encryption
                print(f"   Found {len(blocks)} :::encrypted block(s)")
                passwords = prompt_passwords_for_blocks(len(blocks), decrypt_mode=False)
                output_file, success, message = encrypt_partial_file(input_file, passwords)
            else:
                # Full encryption
                password = getpass.getpass("   Enter encryption password: ")
                password_confirm = getpass.getpass("   Confirm password: ")
                if password != password_confirm:
                    print("   Error: Passwords do not match!")
                    results.append((input_file, None, False, "Passwords do not match"))
                    continue
                if len(password) < 4:
                    print("   Error: Password too short (minimum 4 characters)")
                    results.append((input_file, None, False, "Password too short"))
                    continue
                output_file, success, message = encrypt_file(input_file, password)

        results.append((input_file, output_file, success, message))

        if success:
            print(f"   ✓ → {output_file} ({message})")
        else:
            print(f"   ✗ {message}")

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
