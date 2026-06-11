FROM node:18-alpine

# Install build dependencies for sqlite3 (if needed, though sqlite3 npm package has prebuilt binaries for alpine)
RUN apk add --no-cache python3 make g++

WORKDIR /usr/src/app

COPY package*.json ./

RUN npm install --only=production

COPY . .

EXPOSE 3000

ENV NODE_ENV=production

CMD ["npm", "start"]
