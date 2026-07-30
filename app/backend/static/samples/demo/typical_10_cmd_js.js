const express = require("express");
const { exec } = require("child_process");
const app = express();

app.get("/compress", (req, res) => {
    const file = req.query.file;
    exec(`gzip ${file}`, (err, stdout, stderr) => {
        if (err) return res.status(500).send(stderr);
        res.send(stdout);
    });
});

app.listen(3000);
