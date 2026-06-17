# Container image for any host (Fly.io, Railway, Cloud Run, a VPS, etc.).
# Build:  docker build -t dronewatch .
# Run:    docker run -p 5173:5173 -e BASIC_AUTH_PASS=yourpass dronewatch
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY . .
ENV PORT=5173
EXPOSE 5173
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:5173/api/health >/dev/null 2>&1 || exit 1
CMD ["node", "server.mjs"]
