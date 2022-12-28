FROM golang:1.19.2-alpine3.16 as go-builder
WORKDIR /build
RUN apk add --no-cache gcc g++ make
COPY go.mod go.sum ./
RUN go mod verify
COPY . .
RUN go build -ldflags="-s -w" .

FROM alpine:3.17
COPY --from=go-builder /build/token-exchange-namespace-proxy ./bin/

EXPOSE 3000
ENTRYPOINT [ "/bin/token-exchange-namespace-proxy" ]