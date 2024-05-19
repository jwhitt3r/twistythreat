# Use an appropriate base image with Go and cron installed
FROM golang:1.18-alpine

# Set the working directory
WORKDIR /app

# Copy the Go binary and the script into the container
COPY enhance_dnstwist /app/enhance_dnstwist
COPY run_app.sh /app/run_app.sh
COPY cronjob /etc/crontabs/root

# Ensure the script is executable
RUN chmod +x /app/run_app.sh

# Install cron
RUN apk update && apk add --no-cache \
    bash \
    curl \
    busybox-suid \
    cronie

# Add command to start cron in the foreground (so Docker container stays alive)
CMD ["crond", "-f"]