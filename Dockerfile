# Use Python as the base image
FROM python:3.9

# Set the working directory
WORKDIR /app

# Copy application code to the container
COPY . /app

# Update package list and install libzbar0
RUN apt-get update && \
    apt-get install -y libzbar0 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose the application port
EXPOSE 5000

# Set the startup command
CMD ["python", "main.py"]
