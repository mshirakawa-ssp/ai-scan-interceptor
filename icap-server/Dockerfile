FROM golang:1.21-alpine AS builder
WORKDIR /src
COPY go.mod .
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /ai-scan-interceptor .

FROM scratch
COPY --from=builder /ai-scan-interceptor /ai-scan-interceptor
EXPOSE 1344
ENTRYPOINT ["/ai-scan-interceptor"]
