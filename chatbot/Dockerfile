FROM python:3.13-slim

WORKDIR /app

# install necessary system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    curl \
    && rm -rf /var/lib/apt/lists/*

# copy requirements file
COPY requirements.txt .

# install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# copy source code
COPY . .

# create necessary directories if they don't exist
RUN mkdir -p /app/logs/chatbot

# set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# expose the port
EXPOSE 8001

# command to run the API server
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8001"]