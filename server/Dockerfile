# Server Dockerfile
FROM node:20-alpine

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY index.js ./

# Non-root
RUN addgroup -S mcp && adduser -S mcp -G mcp
USER mcp

ENV NODE_ENV=production
EXPOSE 8080
CMD ["node", "index.js"]
