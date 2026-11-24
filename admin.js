const form = document.querySelector('#contentForm');
const status = document.querySelector('#saveStatus');
const securityStatus = document.querySelector('#securityStatus');

async function postJSON(path, body = {}) {
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

async function loadContent() {
  try {
    const response = await fetch('/api/content');
    if (!response.ok) throw new Error('Could not load content.');
    const content = await response.json();
    for (const [key, value] of Object.entries(content)) {
      if (form.elements[key]) form.elements[key].value = value;
    }
  } catch {
    status.textContent = 'Could not load content. Check that the admin service is available.';
  }
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const submit = form.querySelector('[type="submit"]');
  submit.disabled = true;
  status.textContent = 'Saving…';
  const content = Object.fromEntries(new FormData(form));
  try {
    const response = await fetch('/api/content', {
      method: 'PUT',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(content)
    });
    if (response.status === 401) throw new Error('Your session expired. Sign in with your passkey again.');
    if (!response.ok) throw new Error('Save failed.');
    status.textContent = 'Saved. Your portfolio is up to date.';
  } catch (error) {
    status.textContent = error.message || 'Save failed. Check that the admin service is available.';
  } finally {
    submit.disabled = false;
  }
});

document.querySelector('#addPasskey').addEventListener('click', async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  securityStatus.textContent = 'Waiting for your new passkey…';
  try {
    const ceremony = await postJSON('/api/admin/credentials/options');
    const credential = await SimpleWebAuthnBrowser.startRegistration({ optionsJSON: ceremony.options });
    await postJSON('/api/admin/credentials/verify', { ceremonyId: ceremony.ceremonyId, credential });
    securityStatus.textContent = 'Passkey added. You can use it for future sign-ins.';
  } catch (error) {
    securityStatus.textContent = error.message || 'Could not add a passkey. Try again.';
  } finally {
    button.disabled = false;
  }
});

document.querySelector('#signOut').addEventListener('click', async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    await postJSON('/api/admin/logout');
    window.location.assign('/admin');
  } catch (error) {
    securityStatus.textContent = error.message || 'Could not sign out.';
    button.disabled = false;
  }
});

loadContent();
