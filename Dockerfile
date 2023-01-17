FROM golang:1.19.2-alpine3.16 as go-builder
WORKDIR /app/namespace-proxy
RUN apk add --no-cache gcc g++ make
COPY go.mod go.sum ./
RUN go mod verify
COPY . .
RUN go build .

FROM alpine:3.17
WORKDIR /app/
RUN mkdir /apps/.config
COPY --from=go-builder /app/namespace-proxy ./app/

EXPOSE 8080
ENTRYPOINT [ "/app/namespace-proxy" ]