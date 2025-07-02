#!/bin/bash

echo "⏳ Waiting for requirements.txt to become available..."

# Wait up to 30 seconds for requirements.txt
for i in {1..30}; do
  if [ -f /home/site/wwwroot/requirements.txt ]; then
    echo "✅ requirements.txt found!"
    break
  fi
  echo "  ...still waiting ($i seconds)"
  sleep 1
done

# Install dependencies
pip install -r /home/site/wwwroot/requirements.txt

# Start the app
gunicorn -w 1 -k uvicorn.workers.UvicornWorker main:app
