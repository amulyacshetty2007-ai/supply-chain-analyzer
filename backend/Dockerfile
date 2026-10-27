FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN useradd -r -u 10001 appuser
COPY backend/app ./app
COPY backend/data ./data
COPY frontend ./frontend
USER appuser
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
