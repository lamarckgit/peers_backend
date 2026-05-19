FROM python:3.9

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    default-libmysqlclient-dev \
    libmariadb-dev \
    && rm -rf /var/lib/apt/lists/*

# Set workdir
WORKDIR /app

# Copy the app code (but not secrets/certs)
COPY ./safexs_backend_prod /app

# If you have requirements.txt (make sure it exists!)
COPY ./safexs_backend_prod/myenv/requirements.txt /app/requirements.txt

# Install dependencies (in the image, not venv, since Docker isolates)
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Expose the application port
EXPOSE 8000

# Entrypoint - you can override this with docker-compose/systemd as well
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--ssl-keyfile", "/certs/privkey.pem", "--ssl-certfile", "/certs/fullchain.pem", "--log-level", "debug"]