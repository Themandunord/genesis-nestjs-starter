
FROM node:alpine as dist

RUN apk --no-cache --virtual build-dependencies add \
  openssl \
  python \
  make \
  g++

WORKDIR /tmp/
COPY package.json tsconfig.json tsconfig.build.json ./
COPY .env.prod ./.env
COPY src/ src/
COPY templates/dist templates/dist
RUN yarn install
RUN yarn build
RUN apk del build-dependencies

FROM node:alpine as node_modules
RUN apk --no-cache --virtual build-dependencies add \
  openssl \
  python \
  make \
  g++
WORKDIR /tmp/
COPY package.json ./
RUN yarn install --production
RUN apk del build-dependencies

FROM node:alpine

ENV DOCKERIZE_VERSION v0.6.1
RUN wget https://github.com/jwilder/dockerize/releases/download/$DOCKERIZE_VERSION/dockerize-alpine-linux-amd64-$DOCKERIZE_VERSION.tar.gz \
  && tar -C /usr/local/bin -xzvf dockerize-alpine-linux-amd64-$DOCKERIZE_VERSION.tar.gz \
  && rm dockerize-alpine-linux-amd64-$DOCKERIZE_VERSION.tar.gz
WORKDIR /usr/local/api
COPY --from=node_modules /tmp/node_modules ./node_modules
COPY --from=dist /tmp/dist ./
COPY --from=dist /tmp/.env ./.env
COPY --from=dist /tmp/templates ./templates

ENV NODE_ENV production
EXPOSE 4000
CMD dockerize -wait tcp://postgres:5432 -wait tcp://redis:6379 -timeout 6m node main.js
