/* =========================================================
   Application Security Prototype - Interactive Scripts
   ========================================================= */

document.addEventListener('DOMContentLoaded', () => {
  // 1. Interactive Password Validation Checker
  const passwordInput = document.getElementById('reg-password');
  if (passwordInput) {
    const ruleLen = document.getElementById('rule-len');
    const ruleUpper = document.getElementById('rule-upper');
    const ruleLower = document.getElementById('rule-lower');
    const ruleNum = document.getElementById('rule-num');
    const ruleSpecial = document.getElementById('rule-special');
    const pwBar = document.getElementById('pw-bar');

    passwordInput.addEventListener('input', () => {
      const val = passwordInput.value;

      const hasLen = val.length >= 8;
      const hasUpper = /[A-Z]/.test(val);
      const hasLower = /[a-z]/.test(val);
      const hasNum = /[0-9]/.test(val);
      const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(val);

      updateRule(ruleLen, hasLen);
      updateRule(ruleUpper, hasUpper);
      updateRule(ruleLower, hasLower);
      updateRule(ruleNum, hasNum);
      updateRule(ruleSpecial, hasSpecial);

      // Score 0 to 5
      const score = [hasLen, hasUpper, hasLower, hasNum, hasSpecial].filter(Boolean).length;
      const percentage = (score / 5) * 100;
      
      if (pwBar) {
        pwBar.style.width = percentage + '%';
        if (score <= 2) {
          pwBar.style.backgroundColor = '#ef4444'; // Red
        } else if (score <= 4) {
          pwBar.style.backgroundColor = '#f59e0b'; // Amber
        } else {
          pwBar.style.backgroundColor = '#10b981'; // Green
        }
      }
    });
  }

  function updateRule(element, isValid) {
    if (!element) return;
    if (isValid) {
      element.classList.remove('invalid');
      element.classList.add('valid');
      element.querySelector('.rule-icon').textContent = '✓';
    } else {
      element.classList.remove('valid');
      element.classList.add('invalid');
      element.querySelector('.rule-icon').textContent = '○';
    }
  }

  // 2. Alert Dismiss Handlers
  document.querySelectorAll('.alert-close').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const alertBox = e.target.closest('.alert');
      if (alertBox) {
        alertBox.style.opacity = '0';
        setTimeout(() => alertBox.remove(), 250);
      }
    });
  });
});

// Quick credential filler for rapid 3-minute demonstration
function fillDemoCredentials(identifier, password) {
  const idField = document.getElementById('login-identifier');
  const pwField = document.getElementById('login-password');
  if (idField && pwField) {
    idField.value = identifier;
    pwField.value = password;
    idField.focus();
  }
}
