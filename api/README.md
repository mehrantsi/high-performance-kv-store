# HPKV API Server

## Overview

The HPKV API Server is a high-performance key-value store API built on top of the HPKV kernel module. It provides a RESTful interface for storing, retrieving, and managing key-value pairs with multi-tenancy support, designed for high concurrency and low latency operations.

## Features

- RESTful API for key-value operations (GET, POST, DELETE)
- Multi-tenancy support with API key authentication
- Cluster mode for improved performance and scalability
- Rate limiting to prevent abuse
- Partial update support for efficient data modifications
- Statistics endpoint for monitoring system performance
- Timeout handling for kernel operations

## API Design

The API is built using Express.js and is designed with the following principles:

1. **Multi-tenancy**: Each request is associated with a tenant ID, ensuring data isolation.
2. **Security**: API key authentication is required for all requests.
3. **Performance**: The server uses cluster mode to utilize all available CPU cores.
4. **Scalability**: The underlying HPKV kernel module allows for high-performance operations.
5. **Reliability**: Error handling and logging are implemented throughout the application.

## Setup and Installation

### Prerequisites

- Node.js (v14 or later)
- npm (v6 or later)
- Linux system with the HPKV kernel module installed

### Installation Steps

1. Clone the repository:

```sh
git clone https://github.com/mehrantsi/high-performance-key-value-store.git
cd high-performance-key-value-store/api
```

2. Install dependencies:

```sh
npm install
```

3. Create a `.env` file in the root directory and add the following:

```
PORT=3000
```

4. Create a `config.json` file in the root directory with your API keys and tenant IDs:

   ```json
   {
     "apiKeys": [
       {"key": "your-api-key-1", "tenantId": "tenant1"},
       {"key": "your-api-key-2", "tenantId": "tenant2"}
     ]
   }
   ```

5. Ensure the HPKV kernel module is loaded:

```sh
sudo insmod /path/to/hpkv_module.ko
```

## Running the Server

### Development Mode

To run the server in development mode:

```sh
npm run dev
```

### Production Mode

To run the server in production mode:

1. Build the application:

```sh
npm run build
```

2. Start the server:

```sh
npm start
```

It's recommended to use a process manager like PM2 for production deployments:

```sh
npm install -g pm2
pm2 start npm --name "hpkv-api" -- start
```

## Monitoring and Logging

### Monitoring

- The `/stats` endpoint provides real-time statistics about the HPKV system.
- Use monitoring tools like Prometheus and Grafana to collect and visualize metrics.

### Logging

- Application logs are output to the console.
- In production, use a log aggregation service (e.g., ELK stack, Splunk) to collect and analyze logs.
- Configure your process manager (e.g., PM2) to manage log rotation and persistence.

## API Endpoints

- `POST /record`: Insert or update a record
- `GET /record/:key`: Retrieve a record
- `DELETE /record/:key`: Delete a record
- `GET /stats`: Get system statistics
- `GET /ping`: Health check endpoint

Refer to the API documentation for detailed information on request/response formats and authentication requirements.

## API Usage Examples

Here are some curl examples to demonstrate how to use the API:

1. Insert or update a record:

```bash
curl -X POST http://localhost:3000/record \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key-1" \
  -d '{"key": "example_key", "value": "example_value"}'
```

2. Retrieve a record:

```bash
curl -X GET http://localhost:3000/record/example_key \
  -H "X-API-Key: your-api-key-1"
```

3. Delete a record:

```bash
curl -X DELETE http://localhost:3000/record/example_key \
  -H "X-API-Key: your-api-key-1"
```

4. Get system statistics:

```bash
curl -X GET http://localhost:3000/stats \
  -H "X-API-Key: your-api-key-1"
```

5. Perform a health check:

```bash
curl -X GET http://localhost:3000/ping \
  -H "X-API-Key: your-api-key-1"
```

## Performance Considerations

- The API server uses cluster mode to leverage multiple CPU cores.
- The HPKV kernel module provides high-performance key-value operations.
- Rate limiting is implemented to prevent abuse and ensure fair usage.

## Security

- API key authentication is required for all requests.
- Input validation is performed on all endpoints to prevent injection attacks.
- HTTPS should be configured in production to encrypt all traffic.
