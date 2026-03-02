import { viewSecret, decryptWithPassword, SecretViewError, getErrorMessage } from '/frontend/secret-viewer.js';

var loadingSection = document.getElementById('loading-section');
var passwordSection = document.getElementById('password-section');
var secretSection = document.getElementById('secret-section');
var errorSection = document.getElementById('error-section');
var passwordForm = document.getElementById('password-form');
var pwInput = document.getElementById('pw-input');
var pwError = document.getElementById('pw-error');
var pwSubmit = document.getElementById('pw-submit');
var pwBtnText = document.getElementById('pw-btn-text');
var pwBtnSpinner = document.getElementById('pw-btn-spinner');
var secretContent = document.getElementById('secret-content');
var copyBtn = document.getElementById('copy-btn');
var copyIconDefault = document.getElementById('copy-icon-default');
var copyIconCheck = document.getElementById('copy-icon-check');
var copyLabel = document.getElementById('copy-label');
var copyFeedback = document.getElementById('copy-feedback');
var errorTitle = document.getElementById('error-title');
var errorMessage = document.getElementById('error-message');

var ERROR_ICONS = ['viewed','not-found','invalid','network','decrypt','server','password','unknown'];
var pendingPasswordResult = null;

function hideAllSections() {
  loadingSection.classList.add('hidden');
  passwordSection.classList.remove('visible');
  secretSection.classList.remove('visible');
  errorSection.classList.remove('visible');
}

function showSection(id) {
  hideAllSections();
  if (id === 'loading') loadingSection.classList.remove('hidden');
  else if (id === 'password') passwordSection.classList.add('visible');
  else if (id === 'secret') secretSection.classList.add('visible');
  else if (id === 'error') errorSection.classList.add('visible');
}

function showErrorIcon(type) {
  ERROR_ICONS.forEach(function(name) {
    var el = document.getElementById('err-icon-' + name);
    if (el) el.classList.add('hidden');
  });
  var icon = document.getElementById('err-icon-' + type);
  if (icon) icon.classList.remove('hidden');
  else {
    var fallback = document.getElementById('err-icon-unknown');
    if (fallback) fallback.classList.remove('hidden');
  }
}

function mapErrorType(errorType) {
  var map = {
    'INVALID_URL': 'invalid',
    'NOT_FOUND': 'not-found',
    'SECRET_NOT_FOUND': 'not-found',
    'ALREADY_VIEWED': 'viewed',
    'SECRET_ALREADY_VIEWED': 'viewed',
    'NETWORK_ERROR': 'network',
    'DECRYPTION_FAILED': 'decrypt',
    'SERVER_ERROR': 'server',
    'PASSWORD_REQUIRED': 'password',
    'INVALID_PASSWORD': 'password',
    'WRONG_PASSWORD': 'password',
    'INVALID_RESPONSE': 'server'
  };
  return map[errorType] || 'unknown';
}

function showError(title, message, iconType) {
  errorTitle.textContent = title;
  errorMessage.textContent = message;
  showErrorIcon(iconType || 'unknown');
  showSection('error');
}

function showSecret(content) {
  secretContent.textContent = content;
  showSection('secret');
}

async function copyToClipboard() {
  var text = secretContent.textContent;
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      var ta = document.createElement('textarea');
      ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta);
    }
    copyFeedback.classList.add('visible');
    copyIconDefault.classList.add('hidden');
    copyIconCheck.classList.remove('hidden');
    copyLabel.textContent = 'Copied!';
    copyBtn.classList.add('copied');
    setTimeout(function() {
      copyFeedback.classList.remove('visible');
      copyIconDefault.classList.remove('hidden');
      copyIconCheck.classList.add('hidden');
      copyLabel.textContent = 'Copy Secret';
      copyBtn.classList.remove('copied');
    }, 3000);
  } catch (err) { console.error('Copy failed:', err); }
}

async function handlePasswordSubmit(e) {
  e.preventDefault();
  var password = pwInput.value;
  if (!password) { pwInput.focus(); return; }
  pwError.classList.remove('visible');
  pwSubmit.disabled = true;
  pwBtnText.textContent = 'Decrypting\u2026';
  pwBtnSpinner.classList.remove('hidden');
  try {
    var result = await decryptWithPassword(pendingPasswordResult, password);
    if (result.status === 'password_required') {
      pendingPasswordResult = result;
      pwError.classList.add('visible');
      pwInput.value = '';
      pwInput.focus();
    } else {
      // Successful decryption — tell the server to delete the secret now
      try {
        await fetch('/api/secrets/' + pendingPasswordResult.secretId, { method: 'DELETE' });
      } catch (e) { /* best-effort delete */ }
      showSecret(result.content);
    }
  } catch (err) {
    console.error('Password decrypt failed:', err);
    if (err instanceof SecretViewError && err.type === 'WRONG_PASSWORD') {
      // Stay on password form and show inline error for retry
      pwError.classList.add('visible');
      pwInput.value = '';
      pwInput.focus();
    } else if (err instanceof SecretViewError) {
      showError(getErrorMessage(err), err.message, mapErrorType(err.type));
    } else {
      showError('Decryption Failed', err.message || 'Could not decrypt the secret.', 'decrypt');
    }
  } finally {
    pwSubmit.disabled = false;
    pwBtnText.textContent = 'Decrypt Secret';
    pwBtnSpinner.classList.add('hidden');
  }
}

async function init() {
  showSection('loading');
  try {
    var result = await viewSecret(window.location.href);
    if (result.status === 'password_required') {
      pendingPasswordResult = result;
      showSection('password');
      pwInput.focus();
    } else {
      showSecret(result.content);
    }
  } catch (err) {
    console.error('View secret failed:', err);
    if (err instanceof SecretViewError) {
      var iconType = mapErrorType(err.type);
      var title = 'Error';
      if (err.type === 'SECRET_ALREADY_VIEWED' || err.type === 'ALREADY_VIEWED') title = 'Already Viewed';
      else if (err.type === 'SECRET_NOT_FOUND' || err.type === 'NOT_FOUND') title = 'Secret Not Found';
      else if (err.type === 'INVALID_URL') title = 'Invalid Link';
      else if (err.type === 'NETWORK_ERROR') title = 'Connection Error';
      else if (err.type === 'DECRYPTION_FAILED') title = 'Decryption Failed';
      else if (err.type === 'SERVER_ERROR' || err.type === 'INVALID_RESPONSE') title = 'Server Error';
      showError(title, err.message || getErrorMessage(err), iconType);
    } else {
      showError('Something Went Wrong', err.message || 'An unexpected error occurred.', 'unknown');
    }
  }
}

copyBtn.addEventListener('click', copyToClipboard);
passwordForm.addEventListener('submit', handlePasswordSubmit);

// Prevent secret from being visible when page is restored from bfcache
// (e.g. undo close tab, browser restart with tab restore)
window.addEventListener('pageshow', function(event) {
  if (event.persisted) {
    // Page was restored from bfcache — wipe any displayed secret and reload
    secretContent.textContent = '';
    pendingPasswordResult = null;
    window.location.reload();
  }
});

init();
