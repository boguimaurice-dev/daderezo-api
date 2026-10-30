FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY api.py storage.py net_controller.py agent_engine.py landing.html DADEREZO.html frontend.html favicon.svg favicon.ico favicon.png apple-touch-icon.png logo-icon.png logo-orbit.png og-image.png banner-network.jpg banner-partner.jpg agent_client.py collector.py make_dashboard.py devices.json ./
EXPOSE 8000
CMD ["sh", "-c", "uvicorn api:app --host 0.0.0.0 --port ${PORT:-8000}"]
