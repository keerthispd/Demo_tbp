Demo of our team based project-CryptoSafe, which we plan to deploy as an Android app. This is a web version for demonstration until the app development and deployment is completed.

## Flask Backend (Current)

This demo now uses Flask + SQLite for registration.

### Features
- Register with `userid` and `password`
- Biometric passkey enrollment during registration (WebAuthn)
- Password is hashed before storage (not plain text)[temporary hash algorithm only for demo not for deployment]
- Duplicate user IDs are rejected on the registration page with an inline message
- Login with two-phase lock: password first, biometric verification second
- Accounts lock for 24 hours after 3 failed password attempts
- Success/failure landing page after account creation
- Retry option on failure
- Dashboard home page after login

### Run Locally
1. Create and activate a virtual environment (recommended).
2. Install dependencies:
	`pip install -r requirements.txt`
3. Start the server:
	`python app.py`
4. Open:
	`http://127.0.0.1:5000/registration.html`
	`http://127.0.0.1:5000/login.html`
	`http://127.0.0.1:5000/biometric.html` (phase 2 page, reached automatically after password login)

### Biometric Notes
- A browser/device with WebAuthn passkey support is required for registration and login.
- For local testing, use `localhost` or `127.0.0.1` consistently from registration through login.
