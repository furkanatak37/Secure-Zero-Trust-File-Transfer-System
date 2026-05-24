FROM python:3.12-slim

LABEL description="Secure Zero-Trust File Drop System — CSE4057"

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

# Create necessary runtime directories
RUN mkdir -p ca/logs server/logs server/storage server/db \
             client/logs client/downloads \
             "{ca,server}" 2>/dev/null || true

# Default: run the full demo
CMD ["python", "demo.py"]
