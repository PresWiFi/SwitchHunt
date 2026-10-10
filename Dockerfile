# Stage 1: build the static site
FROM node:24-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

# Stage 2: one Node process serves dist/ and builds .intunewin packages on disk.
# server/ has no npm dependencies - Node 24 runs the TypeScript directly - so nothing is installed here.
FROM node:24-alpine
ENV NODE_ENV=production PORT=8080 DATA_DIR=/data
WORKDIR /app
COPY package.json ./
COPY server ./server
COPY --from=build /app/dist ./dist
# Packages are written here while they wait to be downloaded. Mount a volume with room for your
# largest installer (the package is the installer's size plus a few KB).
RUN mkdir /data && chown node:node /data
USER node
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- "http://127.0.0.1:${PORT}/api/health" || exit 1
CMD ["node", "server/main.ts"]
