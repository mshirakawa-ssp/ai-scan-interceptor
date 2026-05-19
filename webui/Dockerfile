FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o webui .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /app/webui .
EXPOSE 8080
CMD ["/app/webui"]
