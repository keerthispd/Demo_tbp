Demo of our team based project-CryptoSafe, which we plan to deploy as an Android app. This is a web version for demonstration until the app development and deployment is completed.

## Flask Backend (Current)

This demo now uses Flask + SQLite for registration.

### Features
- Register with `userid` and `password`
- Password is hashed before storage (not plain text)[temporary hash algorithm only for demo not for deployment]
- Success/failure landing page after account creation
- Retry option on failure
- View stored records at `/users`

### Run Locally
1. Create and activate a virtual environment (recommended).
2. Install dependencies:
	`pip install -r requirements.txt`
3. Start the server:
	`python app.py`
4. Open:
	`http://127.0.0.1:5000/registration.html
