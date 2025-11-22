#!/bin/bash

# Exit on error
set -e

echo "Setting up Enterprise LLM Security Gateway..."

# 1. Install Dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt

# 2. Download Spacy Model for Presidio
echo "Downloading Spacy model (en_core_web_lg)..."
python -m spacy download en_core_web_lg

# 3. Start the Server
echo "Starting FastAPI Server..."
# Use uvicorn to run the app. 
# --reload enables auto-reload on code changes (useful for dev).
# --host 0.0.0.0 allows external access if needed.
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
