# linux/amd64 is the published Firefox engine. The Mac has no build of it.
# Source is mounted at /src at run time, so a code change does not rebuild
# this image or download the engine again.
FROM --platform=linux/amd64 python:3.12-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    INVISIBLE_PLAYWRIGHT_ENGINE_DIR=/opt/invisible \
    OBY_LINUX_HOST=1 \
    PYTHONPATH=/src \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      xvfb \
      x11vnc \
      x11-utils \
      ca-certificates \
      fonts-liberation \
      libasound2 \
      libatk-bridge2.0-0 \
      libatk1.0-0 \
      libatspi2.0-0 \
      libcairo2 \
      libcups2 \
      libdbus-1-3 \
      libdbus-glib-1-2 \
      libdrm2 \
      libfontconfig1 \
      libfreetype6 \
      libgbm1 \
      libgtk-3-0 \
      libnspr4 \
      libnss3 \
      libpango-1.0-0 \
      libx11-6 \
      libxcb1 \
      libxcomposite1 \
      libxcursor1 \
      libxdamage1 \
      libxext6 \
      libxfixes3 \
      libxi6 \
      libxkbcommon0 \
      libxrandr2 \
      libxshmfence1 \
      libxtst6 \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
      "invisible-playwright>=0.51" \
      "invisible-playwright-mcp>=0.73" \
      "mitmcloak>=0.1" \
      "cursory>=2.1" \
      "certifi" \
 && python -c "from invisible_playwright import ensure_binary; ensure_binary()" \
 && chmod -R a+rX /opt/invisible

WORKDIR /src
