FROM node:23-alpine

WORKDIR /app

# copy package files
COPY package*.json ./

# install dependencies
RUN npm install --omit=dev

# copy source code
COPY . .

# environment variables
ENV NODE_ENV=production

# expose the application port
EXPOSE 8080

# start the application
CMD ["sh", "-c", "npx prisma generate --schema=/app/prisma/schema.prisma && npx prisma migrate deploy --schema=/app/prisma/schema.prisma && node src/server.js"]