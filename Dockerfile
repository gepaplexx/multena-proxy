FROM golang:1.19.2-alpine3.16 as go-builder
WORKDIR /app/namespace-proxy
RUN apk add --no-cache gcc g++ make
COPY go.mod go.sum ./
RUN go mod verify
COPY . .
RUN go build .

FROM alpine:3.17
RUN apk add --no-cache ca-certificates curl wget bash
WORKDIR /app/
ENV GOPS_CONFIG_DIR /app/.config
RUN mkdir /app/.config


COPY --from=go-builder /app/namespace-proxy/namespace-proxy .

RUN chgrp -R 0 /app && chmod -R g=u /app
EXPOSE 8080
ENTRYPOINT [ "/app/namespace-proxy" ]