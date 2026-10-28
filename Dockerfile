# Training image for the intentionally vulnerable app.
# Bind to localhost only when running: docker run -p 127.0.0.1:5000:5000 vulnshop
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN python database.py

EXPOSE 5000
CMD ["python", "app.py"]
