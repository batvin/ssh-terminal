FROM oven/bun:1.2-alpine

WORKDIR /app

RUN apk add --no-cache python3 make g++ openssl wget ca-certificates

COPY package.json ./
RUN bun install

COPY server.ts scan.ts ./

RUN mkdir -p vendor \
 && wget -q -O index.html https://ssh-terminal-b6dc5.sprites.app/ \
 && wget -q -O vendor/xterm.js https://ssh-terminal-b6dc5.sprites.app/vendor/xterm.js \
 && wget -q -O vendor/xterm.css https://ssh-terminal-b6dc5.sprites.app/vendor/xterm.css \
 && wget -q -O vendor/fit.js https://ssh-terminal-b6dc5.sprites.app/vendor/fit.js \
 && test -s index.html && test -s vendor/xterm.js

ENV PORT=8080
ENV HOST=0.0.0.0
EXPOSE 8080

CMD ["bun", "run", "server.ts"]
