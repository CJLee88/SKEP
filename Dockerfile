FROM node:16.19.0-slim

# Create app directory
WORKDIR /usr/src/app

# Install app dependencies
# A wildcard is used to ensure both package.json and package-lock.json are copied
COPY package*.json ./
RUN npm install
# If you are building your code for production
# RUN npm ci --only=production

# Bundle app source
COPY . .

# Create /data directory and grant full permissions for SQLite persistence
RUN mkdir -p /data && chmod -R 777 /data

EXPOSE 8080
CMD ["node", "server.js"]
