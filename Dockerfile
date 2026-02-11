ARG BUILD_FROM
FROM ${BUILD_FROM}

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        nmap \
        proxychains4 && \
    rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY server.py script.js index.html styles.css ./

# Create exports directory
RUN mkdir -p /app/exports

ENV PORT=5000

CMD ["python3", "server.py"]
