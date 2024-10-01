FROM ubuntu:latest

# Avoid prompts from apt
ENV DEBIAN_FRONTEND=noninteractive

# Update and upgrade the system
RUN apt-get update && \
    apt-get install -y \
    nodejs \
    npm \
    kmod \
    util-linux

RUN apt-get full-upgrade -y && \
    apt-get install -y build-essential gcc-12 linux-headers-$(uname -r)

# Set up working directory
WORKDIR /app

# Copy the kernel module source and Node.js server files
COPY kernel /app/kernel
COPY api /app/api

# Build the kernel module
RUN cd /app/kernel && make

# Install Node.js dependencies
RUN cd /app/api && npm install

# Copy the startup script
COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

# Expose the API port
EXPOSE 80

# Run the startup script
CMD ["/app/start.sh"]