# TwistyThreat

TwistyThreat is a Go-based application that integrates with `dnstwist` and VirusTotal to analyze domain names for potential security threats. The application reads a list of domains, performs DNS permutation analysis using `dnstwist`, checks the status of each domain using VirusTotal, categorizes the results, and sends a condensed report of suspicious domains to an HTTP endpoint.

## Features

- Domain permutation analysis using `dnstwist`
- Integration with VirusTotal for threat intelligence
- Categorizes domains as registered, unregistered, or suspicious
- Sends condensed suspicious domain reports to a specified HTTP endpoint
- Dockerized for easy deployment

## Prerequisites

- Docker
- Docker Compose

## Installation

1. **Clone the repository:**

    ```sh
    git clone https://github.com/your-username/your-repo.git
    cd your-repo
    ```

2. **Create a `.env` file in the root directory with your environment variables:**

    ```sh
    VIRUSTOTAL_API_KEY=your_api_key_here
    ```

3. **Create a `domains.txt` file with the list of domains to analyze, one per line:**

    ```txt
    example1.com
    example2.org
    example3.net
    ```

## Docker Setup

1. **Dockerfile:**

    The Dockerfile sets up the environment for both `dnstwist` and your Go application.

    ```dockerfile
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
    ```

2. **Docker Compose:**

    Create a `docker-compose.yml` file to define the services and configurations.

    ```yaml

    services:
      twistythreat:
        build: .
        env_file:
          - .env
        volumes:
          - ./output:/app/output
        command: ["./twistythreat"]
    ```

## Usage

1. **Build and run the application using Docker Compose:**

    ```sh
    docker-compose up --build
    ```

2. **The application will:**
    - Read the domains from `domains.txt`
    - Perform analysis using `dnstwist`
    - Check each domain's status with VirusTotal
    - Categorize the results into registered, unregistered, and suspicious
    - Save the results to respective files (`registered.txt`, `unregistered.txt`, `suspicious.txt`)
    - Send the condensed suspicious report to the specified HTTP endpoint

## Environment Configuration

- **.env File:**

    Create a `.env` file in the root directory of your project with the following content:

    ```sh
    VIRUSTOTAL_API_KEY=your_api_key_here
    HTTP_ENDPOINT=your_domain_here
    ```

- **domains.txt File:**

    Create a `domains.txt` file in the root directory of your project with the list of domains to analyze, one per line:

    ```txt
    example1.com
    example2.org
    example3.net
    ```

## Example Output
All outputs listed below will be saved into the `output` directory:

- **registered.txt:** Contains domains that are currently registered.
- **unregistered.txt:** Contains domains that are not registered.
- **suspicious.txt:** Contains domains flagged as suspicious by VirusTotal.
- **condensed_suspicious.txt:** Contains a condensed report of suspicious domains, including the domain name, VirusTotal link, and determination.

## Sending Condensed Report to HTTP Endpoint

The application sends the `condensed_suspicious.txt` file to a specified HTTP endpoint. Modify the `HTTP_ENDPOINT` variable in `.env` to your desired endpoint:

# License
This project is licensed under the GNU General Public License v3.0 License. See the LICENSE file for details.

# Acknowledgements
dnstwist: This project uses dnstwist, a tool for domain name permutation analysis to detect potential threats. dnstwist is licensed under the Apache License 2.0.

# Contact
For any questions or issues, please open an issue on GitHub or contact me at Mastodon: @jwhitter@mastodon.social

