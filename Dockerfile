FROM python:3.11-slim
WORKDIR /app
COPY . .
CMD ["python", "root_ns/root_ns.py"]
