# Use the latest Go official image to build the Go application
FROM golang:latest AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy the Go module files and install dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application code
COPY . .

# Build the Go application
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/twistythreat /app/cmd/twistythreat/main.go

# Verify the Go binary
RUN ls -la /app/twistythreat

# Use an official Python runtime as a parent image
FROM python:3.12-alpine

# Install dnstwist and other dependencies
RUN apk add --no-cache build-base git && \
    pip install dnstwist

# Set the working directory inside the container
WORKDIR /app

# Copy the built Go application from the builder stage
COPY --from=builder /app/twistythreat /app/twistythreat

# Copy necessary files for the application
COPY domains.txt /app/domains.txt
COPY .env /app/.env

# Run the application
CMD ["/app/twistythreat"]