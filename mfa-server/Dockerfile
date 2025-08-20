FROM golang:1.24.5 AS builder
WORKDIR /app
COPY go.mod ./
ENV GOTOOLCHAIN=auto
RUN go mod download || true
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o mfa-server

FROM gcr.io/distroless/base-debian12
WORKDIR /
COPY --from=builder /app/mfa-server /mfa-server
ENV PORT=8080
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/mfa-server"]

