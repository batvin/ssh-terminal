FROM node:22-bookworm-slim

WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends wget ca-certificates python3 make g++ \
 && rm -rf /var/lib/apt/lists/*

COPY package.json ./
RUN npm install --omit=dev

COPY server.mjs scan.mjs ./

RUN mkdir -p vendor \
 && wget -q -O index.html https://ssh-terminal-b6dc5.sprites.app/ \
 && wget -q -O vendor/xterm.js https://ssh-terminal-b6dc5.sprites.app/vendor/xterm.js \
 && wget -q -O vendor/xterm.css https://ssh-terminal-b6dc5.sprites.app/vendor/xterm.css \
 && wget -q -O vendor/fit.js https://ssh-terminal-b6dc5.sprites.app/vendor/fit.js \
 && test -s index.html && test -s vendor/xterm.js

ENV PORT=8080
ENV HOST=0.0.0.0
EXPOSE 8080

CMD ["node", "server.mjs"]
