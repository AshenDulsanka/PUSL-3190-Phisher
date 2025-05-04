FROM node:23-alpine

WORKDIR /app

# copy package files
COPY package*.json ./

# install dependencies
RUN npm install --omit=dev

# create necessary directories
RUN mkdir -p database/prisma

# copy prisma schema and migrations
COPY ./database/prisma/ ./database/prisma/

# copy source code
COPY . .

# environment variables
ENV NODE_ENV=production

# expose the application port
EXPOSE 8080

# start the application
CMD ["sh", "-c", "ls -la /app && ls -la /app/database && ls -la /app/database/prisma && echo 'Starting server...' && npx prisma generate --schema=/app/database/prisma/schema.prisma && npx prisma migrate deploy --schema=/app/database/prisma/schema.prisma && node src/server.js"]