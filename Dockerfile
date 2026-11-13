FROM oven/bun:1.1-alpine

WORKDIR /app

COPY package.json bun.lock* ./
RUN bun install --production || bun install

COPY . .

ENV PORT=8080
ENV HOST=0.0.0.0
EXPOSE 8080

CMD ["bun", "run", "server.ts"]
