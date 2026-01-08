FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY log_template_processor.py .
COPY main.py .

# Create non-root user for security
RUN useradd -r -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Cloud Run sets PORT environment variable
ENV PORT=8080

# Use gunicorn for production
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 main:app
