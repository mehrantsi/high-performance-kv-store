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
                    const buffer = Buffer.from(`${cmd} ${key} ${value}`);
                    try {
                        const result = ioctl(fd.fd, cmd, buffer);
                        clearTimeout(timer);
                        fd.close().then(() => {
                            resolve(result.toString().trim());
                        }).catch(closeError => {
                            console.error('Error closing file:', closeError);
                            resolve(result.toString().trim());
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
        body('key').isString().isLength({ min: 1, max: 252 }).trim().escape(),
        body('value').isString().isLength({ min: 1, max: 1000 }).trim().escape(),
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
        param('key').isString().isLength({ min: 1, max: 252 }).trim().escape() // Adjusted length for tenant ID
    ], async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { key } = req.params;
        const tenantKey = req.tenantId + key;

        try {
            const value = await hpkvIoctl(HPKV_IOCTL_GET, tenantKey);
            res.status(200).json({ key, value });
        } catch (error) {
            res.status(404).json({ error: 'Record not found' });
        }
    });

    // Delete Record
    app.delete('/record/:key', [
        param('key').isString().isLength({ min: 1, max: 252 }).trim().escape() // Adjusted length for tenant ID
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