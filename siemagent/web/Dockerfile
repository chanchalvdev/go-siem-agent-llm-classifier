# syntax=docker/dockerfile:1.7
# Dashboard image: static Vite build served by unprivileged nginx, which also
# proxies /api, /ws, /health and /docs to the API container.

FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci
COPY . .
RUN npx tsc -b && npx vite build

FROM nginxinc/nginx-unprivileged:1.27-alpine
# Rendered by the image's envsubst entrypoint into conf.d/default.conf.
ENV API_UPSTREAM=http://api:8080
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
