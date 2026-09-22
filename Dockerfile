FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY agent/ agent/
COPY api/ api/
COPY app/ app/
COPY correlation/ correlation/
COPY detection/ detection/
COPY ingestion/ ingestion/
COPY knowledge_graph/ knowledge_graph/
COPY persistence/ persistence/
COPY rag/ rag/

COPY detection/models/ detection/models/

EXPOSE 8000

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
