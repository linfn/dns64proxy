FROM golang:alpine AS build

RUN apk update && apk add git

WORKDIR /dns64proxy
COPY . .

ARG GOPROXY
RUN go build .

FROM alpine

WORKDIR /app

COPY --from=build /dns64proxy/dns64proxy .
COPY --from=build /dns64proxy/dns64proxy.yaml .

ENTRYPOINT [ "./dns64proxy" ]
