FROM node:20-alpine AS frontend-build

WORKDIR /frontend

COPY webui/frontend/package.json /frontend/package.json
COPY webui/frontend/postcss.config.js /frontend/postcss.config.js
COPY webui/frontend/tailwind.config.js /frontend/tailwind.config.js
COPY webui/frontend/vite.config.js /frontend/vite.config.js
COPY webui/frontend/index.html /frontend/index.html
COPY webui/frontend/src /frontend/src

RUN npm install --no-audit --no-fund && npm run build


FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /app/requirements.txt

COPY . /app
COPY --from=frontend-build /frontend/dist /app/webui/frontend/dist

EXPOSE 8080

CMD ["uvicorn", "webui.app:app", "--host", "0.0.0.0", "--port", "8080"]
