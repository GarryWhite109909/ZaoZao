const express = require('express');
const app = express();
app.use(express.json());

function merge(target, src) {
    for (const key in src) {
        if (typeof src[key] === 'object' && src[key] !== null) {
            if (!target[key]) target[key] = {};
            merge(target[key], src[key]);
        } else {
            target[key] = src[key];
        }
    }
    return target;
}

app.post('/update_config', (req, res) => {
    const userConfig = {};
    merge(userConfig, req.body);
    res.send('Updated');
});

app.listen(3000);
