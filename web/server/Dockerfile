FROM node:23-alpine

WORKDIR /app

# copy package files
COPY package*.json ./

# install dependencies
RUN npm install

# copy source code
COPY . .

EXPOSE 5000

# use nodemon for development
CMD ["sh", "-c", "echo 'Waiting for database...' && sleep 5 && npx prisma generate --schema=/app/database/prisma/schema.prisma && npx prisma migrate deploy --schema=/app/database/prisma/schema.prisma && npm run dev"]