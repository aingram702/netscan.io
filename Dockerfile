ARG BUILD_FROM
FROM ${BUILD_FROM}

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        nmap \
        proxychains4 && \
    rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
WORKDIR /app
COPY requirements.txt ./
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# Copy application files
COPY server.py script.js index.html styles.css ./

# Create exports directory
RUN mkdir -p /app/exports

# Register as s6-overlay service (s6 init must be PID 1)
RUN mkdir -p /etc/services.d/netscan
COPY run.sh /etc/services.d/netscan/run
RUN chmod a+x /etc/services.d/netscan/run
