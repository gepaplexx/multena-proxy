FROM golang:1.19.2-alpine3.16 as go-builder
ENV CGO_ENABLED 0
WORKDIR /app/namespace-proxy
RUN apk add --no-cache gcc g++ make
COPY go.mod go.sum ./
RUN go mod verify
COPY . .
RUN go build -gcflags="all=-N -l"

WORKDIR /go/src/
RUN go get github.com/go-delve/delve/cmd/dlv

FROM alpine:3.17
COPY --from=go-builder /app/namespace-proxy/namespace-proxy /bin/
COPY --from=go-builder /go/bin/dlv /bin/

EXPOSE 8080 40000

CMD ["/bin/dlv", "--listen=:40000", "--headless=true", "--api-version=2", "exec", "/bin/namespace-proxy"]