FROM node:23-alpine

WORKDIR /app

# copy package files
COPY package*.json ./

# install dependencies
RUN npm install

# copy source code
COPY . .

# generate Prisma client
RUN npx prisma generate --schema=/app/database/prisma/schema.prisma

EXPOSE 5000

# use nodemon for development
CMD ["npm", "run", "dev"]