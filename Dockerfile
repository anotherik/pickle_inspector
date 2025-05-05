# ------------------------------------------------------------------------------
# Dockerfile for pickle_inspector - Static analysis for insecure deserialization
# ------------------------------------------------------------------------------

# Use official lightweight Python 3 image
FROM python:3.10-slim

# Set environment variables for safer builds
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory inside container
WORKDIR /app

# ------------------------------------------------------------------------------
# Install required system packages
# ------------------------------------------------------------------------------
# - lib2to3: for Python 2 to 3 code conversion (used with --py2-support)
# - Clean up apt cache afterward to reduce image size
RUN apt-get update && \
    apt-get install -y --no-install-recommends lib2to3 && \
    rm -rf /var/lib/apt/lists/*

# ------------------------------------------------------------------------------
# Copy source code into container
# ------------------------------------------------------------------------------
COPY . /app

# ------------------------------------------------------------------------------
# Install Python dependencies from requirements.txt
# ------------------------------------------------------------------------------
RUN pip install --no-cache-dir -r requirements.txt

# ------------------------------------------------------------------------------
# Set default command to run the scanner
# ------------------------------------------------------------------------------
# NOTE: Use volumes to pass in the code to scan
ENTRYPOINT ["python3", "cli.py"]
