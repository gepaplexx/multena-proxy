FROM golang:1.20.0-alpine3.17 as go-builder

LABEL maintainer="Winkler@Gepardec"

WORKDIR /app/multena-proxy
RUN apk add --no-cache gcc g++ make
COPY go.mod go.sum ./
RUN go mod verify
COPY . .
RUN go build .

FROM registry.access.redhat.com/ubi8/ubi-minimal:8
WORKDIR /app/
ENV GOPS_CONFIG_DIR /app/.config
RUN mkdir /app/.config


COPY --from=go-builder /app/multena-proxy/multena-proxy .

RUN chgrp -R 0 /app && chmod -R g=u /app
EXPOSE 8080
ENTRYPOINT [ "/app/multena-proxy" ]