import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(__file__), 'cryptosafe.db')
print('Using DB:', DB_PATH)
if not os.path.exists(DB_PATH):
    print('Database file not found.')
    raise SystemExit(1)

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

# Total users
cur.execute('SELECT COUNT(*) FROM users')
users_count = cur.fetchone()[0]
print('Total users:', users_count)

# Show first 10 users
print('\nSample users (userid, password_hash prefix, passcode_hash prefix):')
cur.execute('SELECT userid, password_hash, passcode_hash FROM users LIMIT 10')
for row in cur.fetchall():
    userid, ph, pch = row
    ph_pref = (ph or '')[:30]
    pch_pref = (pch or '')[:30]
    print(f'- {userid}: password_hash[{ph_pref}], passcode_hash[{pch_pref}]')

# Detect passcode hashes that don't look like common hash prefixes
cur.execute("""
SELECT userid, passcode_hash FROM users
WHERE passcode_hash != ''
AND passcode_hash NOT LIKE 'pbkdf2:%'
AND passcode_hash NOT LIKE 'argon2:%'
AND passcode_hash NOT LIKE 'scrypt:%'
AND passcode_hash NOT LIKE 'bcrypt:%'
"""
)
rows = cur.fetchall()
print('\nSuspicious passcode entries (non-standard hash prefixes):')
if not rows:
    print('None found.')
else:
    for r in rows:
        print('-', r[0], (r[1] or '')[:80])

conn.close()
print('\nDone.')
