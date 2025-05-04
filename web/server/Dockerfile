FROM node:23-alpine

WORKDIR /app

# copy package files
COPY package*.json ./

# install dependencies
RUN npm ci --production

# copy source code
COPY . .

ENV NODE_ENV=production

# generate Prisma client
RUN npx prisma generate --schema=/app/database/prisma/schema.prisma

EXPOSE 8080

# use nodemon for development
CMD ["sh", "-c", "npx prisma migrate deploy --schema=/app/database/prisma/schema.prisma && node src/server.js"]