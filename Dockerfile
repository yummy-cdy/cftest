FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV PORT=8000
ENV CF_DATA_DIR=/app/data
EXPOSE 8000
CMD ["python", "app.py"]
