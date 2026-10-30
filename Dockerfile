FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY api.py storage.py net_controller.py agent_engine.py landing.html DADEREZO.html frontend.html favicon.svg favicon.ico apple-touch-icon.png og-image.png agent_client.py collector.py make_dashboard.py devices.json ./
EXPOSE 8000
CMD ["sh", "-c", "uvicorn api:app --host 0.0.0.0 --port ${PORT:-8000}"]
