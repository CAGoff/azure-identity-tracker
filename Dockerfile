# Use official Python image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy dependencies
COPY requirements.txt .

# Install dependencies
RUN pip install -r requirements.txt

# Copy application code
COPY . .

# Expose port for Uvicorn
EXPOSE 8000

# Start app with hot reload off (you can toggle it)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
