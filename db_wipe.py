import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(__file__), 'cryptosafe.db')
print('Using DB:', DB_PATH)
if not os.path.exists(DB_PATH):
    print('Database file not found.')
    raise SystemExit(1)

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

print('Deleting from user_files...')
cur.execute('DELETE FROM user_files')
print('Deleting from users...')
cur.execute('DELETE FROM users')
conn.commit()

# confirm counts
cur.execute('SELECT COUNT(*) FROM users')
users_count = cur.fetchone()[0]
cur.execute('SELECT COUNT(*) FROM user_files')
files_count = cur.fetchone()[0]
print('Users after wipe:', users_count)
print('User files after wipe:', files_count)

conn.close()
print('Wipe complete.')
