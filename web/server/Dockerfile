FROM node:23-alpine

WORKDIR /app

# copy package files
COPY web/server/package*.json ./

# install dependencies
RUN npm install --omit=dev

# create necessary directories
RUN mkdir -p database/prisma

# copy prisma schema and migrations
COPY ./database/prisma/ ./database/prisma/

# copy source code
COPY web/server/ .

# environment variables
ENV NODE_ENV=production

# expose the application port
EXPOSE 8080

# start the application
CMD ["sh", "-c", "echo 'Starting server...' && env && echo 'Running prisma generate...' && npx prisma generate --schema=/app/database/prisma/schema.prisma && echo 'Running prisma migrate...' && npx prisma migrate deploy --schema=/app/database/prisma/schema.prisma && echo 'Starting Node.js application...' && node src/server.js"]