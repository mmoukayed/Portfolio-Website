const setupPanel = document.querySelector('#setupPanel');
const loginPanel = document.querySelector('#loginPanel');
const setupTokenLabel = document.querySelector('#setupTokenLabel');
const setupTokenInput = document.querySelector('#setupToken');
const authStatus = document.querySelector('#authStatus');
const setupButton = document.querySelector('#setupPasskey');
const loginButton = document.querySelector('#loginPasskey');

async function request(path, body = {}) {
  const response = await fetch(path, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'The request could not be completed.');
  return result;
}

async function loadStatus() {
  try {
    const response = await fetch('/api/admin/status', { cache: 'no-store', credentials: 'same-origin' });
    const status = await response.json();
    if (status.authenticated) {
      window.location.replace('/admin');
      return;
    }
    if (status.setupRequired) {
      if (!status.setupAllowed) {
        authStatus.textContent = 'Passkey setup is disabled. Configure ADMIN_SETUP_TOKEN with at least 32 characters, then restart the server.';
        return;
      }
      setupPanel.hidden = false;
      setupTokenLabel.hidden = !status.setupTokenRequired;
      authStatus.textContent = status.setupTokenRequired ? 'Enter the one-time setup token, then create your passkey.' : 'This local admin is ready for its first passkey.';
      return;
    }
    loginPanel.hidden = false;
    authStatus.textContent = 'Your passkey is required to open the content editor.';
  } catch {
    authStatus.textContent = 'Could not reach the server. Start the site with npm start and open the printed localhost address.';
  }
}

setupButton.addEventListener('click', async () => {
  setupButton.disabled = true;
  authStatus.textContent = 'Waiting for your passkey…';
  try {
    const setupToken = setupTokenInput.value;
    const ceremony = await request('/api/admin/setup/options', { setupToken });
    const credential = await SimpleWebAuthnBrowser.startRegistration({ optionsJSON: ceremony.options });
    await request('/api/admin/setup/verify', { setupToken, ceremonyId: ceremony.ceremonyId, credential });
    setupTokenInput.value = '';
    window.location.assign('/admin');
  } catch (error) {
    authStatus.textContent = error.message || 'Passkey setup failed. Try again.';
    setupButton.disabled = false;
  }
});

loginButton.addEventListener('click', async () => {
  loginButton.disabled = true;
  authStatus.textContent = 'Waiting for your passkey…';
  try {
    const ceremony = await request('/api/admin/login/options');
    const credential = await SimpleWebAuthnBrowser.startAuthentication({ optionsJSON: ceremony.options });
    await request('/api/admin/login/verify', { ceremonyId: ceremony.ceremonyId, credential });
    window.location.assign('/admin');
  } catch (error) {
    authStatus.textContent = error.message || 'Passkey sign-in failed. Try again.';
    loginButton.disabled = false;
  }
});

loadStatus();
