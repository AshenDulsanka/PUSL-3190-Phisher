FROM node:23-alpine

WORKDIR /app

# copy package files
COPY package*.json ./

# install dependencies
RUN npm install

# copy source code
COPY . .

# build the app
RUN npm run build

# simple server to serve the static files
RUN npm install -g serve

# expose dev server port
EXPOSE 8080

# start the built app on port 8080
CMD ["serve", "-s", "dist", "-l", "8080"]