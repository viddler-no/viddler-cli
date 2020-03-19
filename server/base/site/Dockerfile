FROM node:13-stretch

WORKDIR /usr/app

# Process manager
RUN npm install --global pm2

COPY build/package*.json ./

RUN npm install --production

COPY build/ ./

RUN npm run build

EXPOSE 3000

USER node

CMD ["pm2-runtime", "npm", "--", "start"]