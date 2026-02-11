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

# Copy run script
COPY run.sh /
RUN chmod a+x /run.sh

CMD ["/run.sh"]
