FROM python:3.13-slim

WORKDIR /app

# install build dependencies and curl
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    curl && \
    rm -rf /var/lib/apt/lists/*

# create directory structure
RUN mkdir -p /app/models/random_forest_model /app/logs/extension_backend && \
    chmod -R 777 /app/logs

# Copy requirements first to leverage Docker caching
COPY requirements.txt /app/

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . /app/

# Expose the port the app runs on
EXPOSE 8000

# Command to run the application
CMD ["python", "-m", "src.main"]