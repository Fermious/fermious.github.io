(function() {
  const form = document.getElementById('password-form');
  const input = document.getElementById('password-input');
  const btn = document.getElementById('decrypt-btn');
  const error = document.getElementById('error-message');
  const encryptedData = document.getElementById('encrypted-data').textContent.trim();
  const decryptedContainer = document.getElementById('decrypted-content');

  function decrypt() {
    const password = input.value;
    if (!password) return;

    try {
      // CryptoJS AES decrypt
      const decrypted = CryptoJS.AES.decrypt(encryptedData, password);
      const plaintext = decrypted.toString(CryptoJS.enc.Utf8);

      if (!plaintext) {
        throw new Error('Decryption failed');
      }

      // Success - show decrypted content
      form.style.display = 'none';
      decryptedContainer.innerHTML = plaintext;
      decryptedContainer.style.display = 'block';

      // Store in session (optional - for page refresh)
      sessionStorage.setItem('decrypt_' + window.location.pathname, password);

    } catch (e) {
      // Wrong password
      error.style.display = 'block';
      input.classList.add('is-invalid');
      input.select();
    }
  }

  // Event listeners
  btn.addEventListener('click', decrypt);
  input.addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
      decrypt();
    }
  });
  input.addEventListener('input', function() {
    error.style.display = 'none';
    input.classList.remove('is-invalid');
  });

  // Check sessionStorage for previously entered password
  const savedPassword = sessionStorage.getItem('decrypt_' + window.location.pathname);
  if (savedPassword) {
    input.value = savedPassword;
    decrypt();
  }
})();
