FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

# Make the startup script executable
RUN chmod +x start.sh

EXPOSE 5001

CMD ["./start.sh"] 