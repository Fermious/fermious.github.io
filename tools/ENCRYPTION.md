# Post Encryption Tool

Encrypt blog posts so only readers with the password can view the content. Supports both full post encryption and partial encryption (specific sections only).

## Files

| File | Purpose |
|------|---------|
| `tools/encrypt-post.py` | Python script for encrypting/decrypting posts |
| `_layouts/encrypted.html` | Layout for fully encrypted posts |
| `_layouts/partial-encrypted.html` | Layout for partially encrypted posts |
| `assets/js/decrypt.js` | Browser decryption for full encryption |
| `assets/js/partial-decrypt.js` | Browser decryption for partial encryption |

## Requirements

Python packages (install in `tools/.venv`):
```bash
pip install pycryptodome markdown html2text
```

## Usage

### Full Encryption

Encrypt an entire post:

```bash
./tools/encrypt-post.py _drafts/my-secret-post.md
```

The script will:
1. Prompt for a password (with confirmation)
2. Convert markdown to HTML
3. Encrypt the content using AES-256-CBC
4. Output to `_posts/` with `layout: encrypted`

### Partial Encryption

Encrypt only specific sections using `:::encrypted` blocks:

```markdown
---
title: My Post
---

This content is public and visible to everyone.

:::encrypted
This section is encrypted and requires a password.
It supports **markdown** formatting.
:::

Back to public content.

:::encrypted
Another encrypted section (can have different password).
:::
```

Run the same command:
```bash
./tools/encrypt-post.py _drafts/my-post.md
```

The script will:
1. Detect the `:::encrypted` blocks
2. Prompt for a password for each block
3. Output to `_posts/` with `layout: partial-encrypted`

### Custom Title and Hint

Add custom labels and password hints:

```markdown
:::encrypted{title="Personal Journal" hint="childhood pet"}
My private thoughts...
:::
```

- `title` - Label shown on the encrypted bar (default: "Encrypted Section N")
- `hint` - Placeholder text in password field (default: "Password")

### Password Prompting

For partial encryption with multiple blocks:
```
Found 3 :::encrypted block(s)
Password for block 1: ****
Confirm password for block 1: ****
Password for block 2 (Enter for same):
Password for block 3 (Enter for same): ****
```

Press Enter to reuse the previous password, or enter a new one.

### Decryption

Decrypt a post back to markdown:

```bash
./tools/encrypt-post.py -d _posts/2024-01-01-my-post.md
```

If the original draft exists in `_drafts/`, it will be restored from there.

## Security

- Uses AES-256-CBC encryption (OpenSSL/CryptoJS compatible)
- Password-based key derivation using EVP_BytesToKey
- Decryption happens client-side in the browser
- Passwords stored in `sessionStorage` for page refresh persistence
- Original drafts in `_drafts/` are git-ignored

## Browser Experience

### Full Encryption
- Glassmorphism card with pulsing lock icon
- Password field with key icon
- Shake animation on wrong password
- Smooth unlock animation on success

### Partial Encryption
- Compact bar with left accent border
- Title on left, password field on right
- Bar collapses and content reveals on unlock
- Each section can have a different password
