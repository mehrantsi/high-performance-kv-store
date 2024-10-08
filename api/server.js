require('dotenv').config(); // Load environment variables from .env file
const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs').promises;
const ioctl = require('ioctl');
const { body, param, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const cluster = require('cluster');
const os = require('os');
const fsSync = require('fs');

const numCPUs = os.cpus().length;
const PORT = process.env.PORT || 3000;

// Define ioctl commands
const HPKV_IOCTL_GET = 0;
const HPKV_IOCTL_DELETE = 1;
const HPKV_IOCTL_PARTIAL_UPDATE = 5;
const HPKV_IOCTL_PURGE = 3;

const MAX_KEY_SIZE = 512;
const MAX_VALUE_SIZE = 102400;  // 100 KB
const UINT16_SIZE = 2; // 2 bytes for uint16
const SIZE_T_SIZE = 8; // 8 bytes for 64-bit systems

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

    // Load configuration file
    let config;
    try {
        config = require('./config.local');
        console.log('Loaded configuration from config.local.json');
    } catch (error) {
        if (error.code === 'MODULE_NOT_FOUND') {
            try {
                config = require('./config');
                console.log('Loaded configuration from config.json');
            } catch (innerError) {
                console.error('Error loading configuration:', innerError);
                process.exit(1);
            }
        } else {
            console.error('Error loading configuration:', error);
            process.exit(1);
        }
    }

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
    async function hpkvIoctl(cmd, key, value = '', timeout = 5000) {
        return new Promise(async (resolve, reject) => {
            const timer = setTimeout(() => {
                reject(new Error('Operation timed out'));
            }, timeout);

            let fd = null;
            let buffer = null;
            try {
                fd = await fs.open('/dev/hpkv', 'r+');

                const keyLength = Buffer.isBuffer(key) ? key.length : Buffer.byteLength(key);
                const valueLength = Buffer.isBuffer(value) ? value.length : Buffer.byteLength(value);

                switch (cmd) {
                    case HPKV_IOCTL_GET:
                        buffer = Buffer.alloc(UINT16_SIZE + SIZE_T_SIZE + keyLength + MAX_VALUE_SIZE);
                        buffer.writeUInt16LE(keyLength, 0);
                        if (Buffer.isBuffer(key)) {
                            key.copy(buffer, UINT16_SIZE);
                        } else {
                            buffer.write(key, UINT16_SIZE);
                        }
                        break;
                    case HPKV_IOCTL_DELETE:
                        buffer = Buffer.alloc(UINT16_SIZE + keyLength);
                        buffer.writeUInt16LE(keyLength, 0);
                        if (Buffer.isBuffer(key)) {
                            key.copy(buffer, UINT16_SIZE);
                        } else {
                            buffer.write(key, UINT16_SIZE);
                        }
                        break;
                    case HPKV_IOCTL_PARTIAL_UPDATE:
                        buffer = Buffer.alloc(UINT16_SIZE + SIZE_T_SIZE + keyLength + valueLength);
                        buffer.writeUInt16LE(keyLength, 0);
                        buffer.writeBigUInt64LE(BigInt(valueLength), UINT16_SIZE);
                        if (Buffer.isBuffer(key)) {
                            key.copy(buffer, UINT16_SIZE + SIZE_T_SIZE);
                        } else {
                            buffer.write(key, UINT16_SIZE + SIZE_T_SIZE);
                        }
                        if (Buffer.isBuffer(value)) {
                            value.copy(buffer, UINT16_SIZE + SIZE_T_SIZE + keyLength);
                        } else {
                            buffer.write(value, UINT16_SIZE + SIZE_T_SIZE + keyLength);
                        }
                        break;
                    case HPKV_IOCTL_PURGE:
                        buffer = Buffer.alloc(0);
                        break;
                    default:
                        throw new Error('Invalid ioctl command');
                }

                ioctl(fd.fd, cmd, buffer);
                resolve(buffer);
            } catch (err) {
                reject(err);
            } finally {
                clearTimeout(timer);
                if (fd) await fd.close();
            }
        });
    }

    // Insert/Update Record
    app.post('/record', [
        body('key').isString().isLength({ min: 1, max: MAX_KEY_SIZE }).trim().escape(),
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
            console.log(`Received request - Key: ${tenantKey}, Value: ${value}, Partial Update: ${partialUpdate}`);
            
            if (partialUpdate) {
                await hpkvIoctl(HPKV_IOCTL_PARTIAL_UPDATE, tenantKey, value);
            } else {
                await fs.writeFile('/dev/hpkv', `${tenantKey}:${value}`);
            }
            res.status(200).json({ success: true, message: 'Record inserted/updated successfully' });
        } catch (error) {
            console.error('Error in POST /record:', error);
            res.status(500).json({ error: 'Failed to insert/update record' });
        }
    });

    // Get Record
    app.get('/record/:key', [
        param('key').isString().isLength({ min: 1, max: MAX_KEY_SIZE }).trim().escape()
    ], async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { key } = req.params;
        const tenantKey = req.tenantId + key;

        let buffer = null;
        try {
            const keyBuffer = Buffer.from(tenantKey);
            buffer = await hpkvIoctl(HPKV_IOCTL_GET, keyBuffer);
            
            const valueLength = buffer.readBigUInt64LE(UINT16_SIZE);
            
            if (valueLength > 0n) {
                const value = buffer.toString('utf8', UINT16_SIZE + SIZE_T_SIZE, UINT16_SIZE + SIZE_T_SIZE + Number(valueLength));
                res.status(200).json({ key: key, value: value.trim() });
            } else {
                res.status(404).json({ error: 'Record not found' });
            }
        } catch (error) {
            if (error.code === 'ENOENT') {
                res.status(404).json({ error: 'Record not found' });
            } else {
                console.error('Error in GET /record/:key:', error);
                console.error('Tenant Key:', tenantKey);
                console.error('Error Stack:', error.stack);
                res.status(500).json({ error: 'Failed to retrieve record' });
            }
        } finally {
            if (buffer) {
                buffer.fill(0);
                buffer = null;
            }
        }
    });

    // Delete Record
    app.delete('/record/:key', [
        param('key').isString().isLength({ min: 1, max: MAX_KEY_SIZE }).trim().escape()
    ], async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { key } = req.params;
        const tenantKey = req.tenantId + key;

        try {
            await hpkvIoctl(HPKV_IOCTL_DELETE, tenantKey);
            res.status(200).json({ success: true, message: 'Record deleted successfully' });
        } catch (error) {
            console.error('Error in DELETE /record/:key:', error);
            res.status(500).json({ error: 'Failed to delete record' });
        }
    });

    // Get Statistics
    app.get('/stats', (req, res) => {
        try {
            const stats = fsSync.readFileSync('/proc/hpkv_stats', 'utf8');
            const parsedStats = {};
            stats.split('\n').forEach(line => {
                const [key, value] = line.split(':');
                if (key && value) {
                    parsedStats[key.trim()] = value.trim();
                }
            });
            res.status(200).json(parsedStats);
        } catch (error) {
            console.error('Error in GET /stats:', error);
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