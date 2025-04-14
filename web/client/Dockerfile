FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy source code
COPY . .

# Expose dev server port
EXPOSE 3000

# Start the development server with host set for Docker
CMD ["npm", "run", "dev"]