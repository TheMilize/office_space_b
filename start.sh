#!/bin/sh

# Initialize the database
echo "Initializing database..."
node init_db.js

# Start the server
echo "Starting server..."
node server.js 