# Stage 1: Build frontend
FROM node:20-alpine AS builder

WORKDIR /app

# Copy project files
COPY package*.json ./
COPY vite.config.* ./
COPY index.html ./
COPY public ./public
COPY src ./src

# Install dependencies and build
RUN npm install
RUN npm run build

# Stage 2: Serve with Express
FROM node:20-alpine

WORKDIR /app

# Only copy what's needed at runtime
COPY package*.json ./
COPY gateway.mjs ./gateway.mjs
COPY dist ./dist

RUN npm install --omit=dev

ENV NODE_ENV=production
ENV PORT=8080

EXPOSE 8080

CMD ["node", "gateway.mjs"]