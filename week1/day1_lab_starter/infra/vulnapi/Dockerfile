FROM node:20-alpine
RUN npm i -g json-server@0.17.4
WORKDIR /app
COPY db.json /data/db.json
EXPOSE 3000
CMD ["sh", "-c", "json-server --host 0.0.0.0 --port 3000 /data/db.json"]
