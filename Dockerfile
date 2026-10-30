FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY api.py storage.py net_controller.py agent_engine.py contabo_watchdog.py docker-compose.contabo.yml landing.html DADEREZO.html frontend.html offline.html manifest.webmanifest sw.js favicon.svg favicon.ico favicon.png apple-touch-icon.png icon-192.png icon-512.png icon-maskable-512.png logo-icon.png logo-orbit.png og-image.png banner-network.jpg banner-partner.jpg agent_client.py collector.py make_dashboard.py devices.json ./
EXPOSE 8000
CMD ["sh", "-c", "uvicorn api:app --host 0.0.0.0 --port ${PORT:-8000}"]
