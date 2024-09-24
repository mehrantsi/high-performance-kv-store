require('dotenv').config(); // Load environment variables from .env file
const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const { execSync } = require('child_process');
const { body, param, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const config = require('./config.json'); // Load configuration file
const cluster = require('cluster');
const os = require('os');

const numCPUs = os.cpus().length;
const PORT = process.env.PORT || 3000;

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
        max: 100, // limit each IP to 100 requests per windowMs
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

    // Insert/Update Record
    app.post('/record', [
        body('key').isString().isLength({ min: 1, max: 252 }).trim().escape(), // Adjusted length for tenant ID
        body('value').isString().isLength({ min: 1, max: 1000 }).trim().escape(),
        body('partialUpdate').optional().isBoolean()
    ], (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { key, value, partialUpdate } = req.body;
        const tenantKey = req.tenantId + key;

        try {
            const cmd = `ioctl /dev/hpkv 2 ${tenantKey} ${value}`;
            execSync(cmd);
            res.status(200).json({ message: 'Record inserted/updated successfully' });
        } catch (error) {
            res.status(500).json({ error: 'Failed to insert/update record' });
        }
    });

    // Get Record
    app.get('/record/:key', [
        param('key').isString().isLength({ min: 1, max: 252 }).trim().escape() // Adjusted length for tenant ID
    ], (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { key } = req.params;
        const tenantKey = req.tenantId + key;

        try {
            const cmd = `ioctl /dev/hpkv 0 ${tenantKey}`;
            const value = execSync(cmd).toString();
            res.status(200).json({ key, value });
        } catch (error) {
            res.status(404).json({ error: 'Record not found' });
        }
    });

    // Delete Record
    app.delete('/record/:key', [
        param('key').isString().isLength({ min: 1, max: 252 }).trim().escape() // Adjusted length for tenant ID
    ], (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { key } = req.params;
        const tenantKey = req.tenantId + key;

        try {
            const cmd = `ioctl /dev/hpkv 1 ${tenantKey}`;
            execSync(cmd);
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

    app.listen(PORT, () => {
        console.log(`Worker ${process.pid} is running on port ${PORT}`);
    });
}