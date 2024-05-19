# Use an official Python runtime as a parent image
FROM python:3.12-alpine

# Install Go and other dependencies
RUN apk add --no-cache go git build-base

# Install dnstwist
RUN pip install dnstwist

# Set the working directory inside the container
WORKDIR /app

# Clone the GitHub repository
RUN git clone https://github.com/jwhitt3r/twistythreat.git .

# Set up the Go environment and install dependencies
RUN go mod download

# Build the Go application
RUN go build -o twistythreat cmd/twistythreat/main.go

# Run the application
CMD ["./twistythreat"]