# backend/Dockerfile
FROM node:20-alpine

# Setări de runtime
ENV NODE_ENV=production \
    PORT=3001 \
    DATA_DIR=/app/data

# Director app
WORKDIR /app

# Instalăm doar deps necesare
COPY package*.json ./
RUN npm ci --omit=dev

# Copiem codul
COPY . .

# Asigurăm folderul de date
RUN mkdir -p /app/data && chown -R node:node /app

# Rulează ca utilizator non-root
USER node

EXPOSE 3001

# Healthcheck simplu (opțional, dar util în compose/k8s)
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD wget -qO- http://127.0.0.1:3001/api/servers || exit 1

CMD ["node", "server.js"]
