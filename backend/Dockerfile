FROM golang:1.22-alpine AS builder
RUN apk add --no-cache git
WORKDIR /build
COPY go.mod go.sum* ./
RUN go mod download || true
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o warta ./cmd/server

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /build/warta .
RUN mkdir -p /app/uploads
EXPOSE 8080
CMD ["./warta"]
