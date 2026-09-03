// Inspired by CVE-2020-27844 (StarIotLink) - command injection in device ping
// Real pattern: host from user input passed to child_process.exec
const express = require('express');
const { exec } = require('child_process');
const app = express();

app.use(express.json());

app.post('/api/device/ping', (req, res) => {
    const host = req.body.host;
    if (!host) {
        return res.status(400).json({ error: 'host required' });
    }
    // Vulnerable: host from user input directly concatenated into shell command
    exec(`ping -c 4 ${host}`, (error, stdout, stderr) => {
        if (error) {
            return res.status(500).json({ error: stderr });
        }
        res.json({
            host: host,
            output: stdout,
            alive: stdout.includes('bytes from')
        });
    });
});

app.listen(8080, () => console.log('IoT device manager running on :8080'));
