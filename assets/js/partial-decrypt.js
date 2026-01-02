(function() {
  // Find all encrypted bars
  const encryptedBars = document.querySelectorAll('.encrypted-bar[data-encrypted]');

  // If no encrypted bars, nothing to do
  if (encryptedBars.length === 0) return;

  // Set up each bar with its own decryption handler
  encryptedBars.forEach((bar) => {
    const blockNum = bar.dataset.block;
    const input = bar.querySelector('input[type="password"]');
    const btn = bar.querySelector('.bar-unlock');
    const errorIcon = bar.querySelector('.bar-error');
    const ciphertext = bar.dataset.encrypted;
    const contentDiv = bar.nextElementSibling; // The .encrypted-content div

    // Session storage key for this block
    const storageKey = 'partial_decrypt_' + window.location.pathname + '_block_' + blockNum;

    function decryptBar() {
      const password = input.value;
      if (!password) return;

      try {
        // CryptoJS AES decrypt
        const decrypted = CryptoJS.AES.decrypt(ciphertext, password);
        const plaintext = decrypted.toString(CryptoJS.enc.Utf8);

        if (!plaintext) {
          throw new Error('Decryption failed');
        }

        // Success - animate bar collapse and show content
        bar.classList.add('unlocked');

        if (contentDiv && contentDiv.classList.contains('encrypted-content')) {
          contentDiv.innerHTML = plaintext;
          setTimeout(() => {
            contentDiv.classList.add('show');
          }, 100);
        }

        // Store password in session
        sessionStorage.setItem(storageKey, password);

      } catch (e) {
        // Wrong password - shake and show error
        input.classList.add('shake');
        if (errorIcon) {
          errorIcon.classList.add('show');
        }

        setTimeout(() => {
          input.classList.remove('shake');
        }, 400);

        input.select();
      }
    }

    // Event listeners
    if (btn) {
      btn.addEventListener('click', decryptBar);
    }

    if (input) {
      input.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
          decryptBar();
        }
      });

      input.addEventListener('input', function() {
        if (errorIcon) {
          errorIcon.classList.remove('show');
        }
      });

      // Check sessionStorage for previously entered password
      const savedPassword = sessionStorage.getItem(storageKey);
      if (savedPassword) {
        input.value = savedPassword;
        decryptBar();
      }
    }
  });
})();
