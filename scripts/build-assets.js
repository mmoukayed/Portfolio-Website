const fs = require('node:fs/promises');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const publicDirectory = path.join(root, 'public');
const files = ['index.html', 'admin.html', 'admin-login.html', 'styles.css', 'app.js', 'admin.js', 'admin-login.js'];

async function buildAssets() {
  await fs.mkdir(path.join(publicDirectory, 'assets'), { recursive: true });
  await Promise.all(files.map((file) => fs.copyFile(path.join(root, file), path.join(publicDirectory, file))));
  await fs.copyFile(
    path.join(root, 'node_modules/@simplewebauthn/browser/dist/bundle/index.umd.min.js'),
    path.join(publicDirectory, 'assets/webauthn-browser.js'),
  );
}

buildAssets().catch((error) => {
  console.error(`Could not prepare Worker assets: ${error.message}`);
  process.exitCode = 1;
});
