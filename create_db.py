import sqlite3

# Create a connection to the SQLite database (this will create the file if it doesn't exist)
conn = sqlite3.connect('database.db')

# Create a cursor object to execute SQL commands
cursor = conn.cursor()

# Define the table structure
cursor.execute('''
    CREATE TABLE IF NOT EXISTS user (
        id INTEGER PRIMARY KEY,
        username VARCHAR(20) NULL UNIQUE,
        password VARCHAR(60) NULL,
        secret VARCHAR(32) NOT NULL,
        fa_enabled BOOLEAN DEFAULT FALSE,
        email VARCHAR(255) UNIQUE,
        oauthProvider VARCHAR(20),
        googleID VARCHAR(21),
        name VARCHAR(100),
        locked BOOLEAN DEFAULT FALSE,
        lockedUntil DATETIME,
        failedLogin INTEGER
    )
''')


# Commit the changes and close the connection
conn.commit()
conn.close()

print("Database structure created.")
