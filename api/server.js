require('dotenv').config(); // Load environment variables from .env file
const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs').promises;
const ioctl = require('ioctl');
const { body, param, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const config = require('./config.json'); // Load configuration file
const cluster = require('cluster');
const os = require('os');

const numCPUs = os.cpus().length;
const PORT = process.env.PORT || 3000;

// Define ioctl commands
const HPKV_IOCTL_GET = 0;
const HPKV_IOCTL_DELETE = 1;
const HPKV_IOCTL_PARTIAL_UPDATE = 2;
const HPKV_IOCTL_PURGE = 3;

const MAX_KEY_SIZE = 256;
const MAX_VALUE_SIZE = 1000;

if (cluster.isMaster) {
    console.log(`Master ${process.pid} is running`);

    // Fork workers.
    for (let i = 0; i < numCPUs; i++) {
        cluster.fork();
    }

    cluster.on('exit', (worker, code, signal) => {
        console.log(`Worker ${worker.process.pid} died`);
        cluster.fork();
    });
} else {
    const app = express();

    app.use(bodyParser.json());

    // Rate limiting middleware
    const limiter = rateLimit({
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 100000, // limit each IP to 100000 requests per windowMs
        message: { error: 'Too many requests, please try again later.' }
    });

    app.use(limiter);

    // Middleware for API key validation and tenant ID extraction
    app.use((req, res, next) => {
        const apiKey = req.headers['x-api-key'];
        const apiKeyEntry = config.apiKeys.find(entry => entry.key === apiKey);
        if (!apiKeyEntry) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        req.tenantId = apiKeyEntry.tenantId;
        next();
    });

    // Helper function to perform ioctl operations with timeout
    function hpkvIoctl(cmd, key, value = '', timeout = 5000) {
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                reject(new Error('Operation timed out'));
            }, timeout);

            fs.open('/dev/hpkv', 'r+')
                .then(fd => {
                    let buffer;
                    switch (cmd) {
                        case HPKV_IOCTL_GET:
                        case HPKV_IOCTL_DELETE:
                            buffer = Buffer.alloc(MAX_KEY_SIZE + MAX_VALUE_SIZE);
                            buffer.write(key);
                            break;
                        case HPKV_IOCTL_PARTIAL_UPDATE:
                            buffer = Buffer.alloc(MAX_KEY_SIZE + MAX_VALUE_SIZE);
                            buffer.write(key);
                            buffer.write(value, MAX_KEY_SIZE);
                            break;
                        case HPKV_IOCTL_PURGE:
                            buffer = Buffer.alloc(0);  // No data needed for purge
                            break;
                        default:
                            clearTimeout(timer);
                            fd.close().catch(closeError => console.error('Error closing file:', closeError));
                            reject(new Error('Invalid ioctl command'));
                            return;
                    }

                    try {
                        const result = ioctl(fd.fd, cmd, buffer);
                        clearTimeout(timer);
                        fd.close().then(() => {
                            if (cmd === HPKV_IOCTL_GET) {
                                if (Buffer.isBuffer(result)) {
                                    // Find the actual length of the value (up to the first null byte or end of buffer)
                                    const valueLength = result.indexOf(0) !== -1 ? result.indexOf(0) : result.length;
                                    // Convert only the valid part of the buffer to a string
                                    resolve(result.toString('utf8', 0, valueLength));
                                } else {
                                    console.error('Unexpected result type:', typeof result);
                                    resolve(result.toString());
                                }
                            } else {
                                resolve(result);
                            }
                        }).catch(closeError => {
                            console.error('Error closing file:', closeError);
                            resolve(result);
                        });
                    } catch (ioctlError) {
                        clearTimeout(timer);
                        fd.close().catch(closeError => console.error('Error closing file:', closeError));
                        reject(ioctlError);
                    }
                })
                .catch(openError => {
                    clearTimeout(timer);
                    reject(openError);
                });
        });
    }

    // Insert/Update Record
    app.post('/record', [
        body('key').isString().isLength({ min: 1, max: MAX_KEY_SIZE - 4 }).trim().escape(),
        body('value').isString().isLength({ min: 1, max: MAX_VALUE_SIZE }).trim().escape(),
        body('partialUpdate').optional().isBoolean()
    ], async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { key, value, partialUpdate } = req.body;
        const tenantKey = req.tenantId + key;

        try {
            if (partialUpdate) {
                await hpkvIoctl(HPKV_IOCTL_PARTIAL_UPDATE, tenantKey, value);
            } else {
                await fs.writeFile('/dev/hpkv', `${tenantKey}:${value}`);
            }
            res.status(200).json({ message: 'Record inserted/updated successfully' });
        } catch (error) {
            console.error('Error in POST /record:', error);
            res.status(500).json({ error: 'Failed to insert/update record' });
        }
    });

    // Get Record
    app.get('/record/:key', [
        param('key').isString().isLength({ min: 1, max: MAX_KEY_SIZE - 4 }).trim().escape()
    ], async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { key } = req.params;
        const tenantKey = req.tenantId + key;

        try {
            const value = await hpkvIoctl(HPKV_IOCTL_GET, tenantKey);
            // Remove the tenant ID (first 4 characters) from the key in the response
            res.status(200).json({ key: key, value });
        } catch (error) {
            if (error.message.includes('ENOENT')) {
                res.status(404).json({ error: 'Record not found' });
            } else {
                console.error('Error in GET /record/:key:', error);
                console.error('Tenant Key:', tenantKey);
                console.error('Error Stack:', error.stack);
                res.status(500).json({ error: 'Failed to retrieve record' });
            }
        }
    });

    // Delete Record
    app.delete('/record/:key', [
        param('key').isString().isLength({ min: 1, max: MAX_KEY_SIZE - 4 }).trim().escape()
    ], async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { key } = req.params;
        const tenantKey = req.tenantId + key;

        try {
            await hpkvIoctl(HPKV_IOCTL_DELETE, tenantKey);
            res.status(200).json({ message: 'Record deleted successfully' });
        } catch (error) {
            console.error('Error in DELETE /record/:key:', error);
            res.status(500).json({ error: 'Failed to delete record' });
        }
    });

    // Get Statistics
    app.get('/stats', (req, res) => {
        try {
            const stats = fs.readFileSync('/proc/hpkv_stats', 'utf8');
            res.status(200).json({ stats });
        } catch (error) {
            res.status(500).json({ error: 'Failed to get statistics' });
        }
    });

    // Ping endpoint to check if the server is running
    app.get('/ping', (req, res) => {
        res.status(200).send('pong');
    });

    app.listen(PORT, '0.0.0.0', () => {
        console.log(`Worker ${process.pid} is running on port ${PORT}`);
    });
}