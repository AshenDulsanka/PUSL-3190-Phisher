FROM node:23-alpine

WORKDIR /app

# copy package files
COPY package*.json ./

# install dependencies
RUN npm install

# copy source code
COPY . .

# expose dev server port
EXPOSE 3000

# start the development server with host set for docker
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]