# Use official Python image
FROM python:3.11-slim

# Install required system packages
RUN apt-get update && apt-get install -y \
    gcc libmagic-dev clamav clamav-daemon \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy app files
COPY . /app

# Upgrade pip and install dependencies
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Expose the port FastAPI runs on
EXPOSE 8000

# Run the application with uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]