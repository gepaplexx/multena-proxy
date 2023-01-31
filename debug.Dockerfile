FROM golang:1.19.2-alpine3.16 as go-builder
ENV CGO_ENABLED 0
WORKDIR /go/src/
RUN go install -ldflags "-s -w -extldflags '-static'" github.com/go-delve/delve/cmd/dlv@latest
WORKDIR /app/multena-proxy
RUN apk add --no-cache gcc g++ make
COPY go.mod go.sum ./
RUN go mod verify
COPY . .
RUN go build -gcflags="all=-N -l"



FROM alpine:3.17
WORKDIR /app/
ENV GOPS_CONFIG_DIR /app/.config
RUN mkdir /app/.config

COPY --from=go-builder /app/multena-proxy/multena-proxy .
COPY --from=go-builder /go/bin/dlv .

RUN chgrp -R 0 /app && chmod -R g=u /app

EXPOSE 8080 40000

ENTRYPOINT [ "./dlv" , "--listen=:40000", "--headless=true", "--api-version=2", "--accept-multiclient", "exec", "multena-proxy"]