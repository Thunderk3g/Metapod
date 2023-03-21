const express = require('express');
const crypto = require('crypto');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());

let salt;

app.post('/generate-parent-hash', (req, res) => {
    salt = crypto.randomBytes(16).toString('hex');

    const parentHash = crypto.createHmac('sha256', salt)
        .update(req.body.clientId + req.body.clientSecret)
        .digest('hex');

    res.status(200).json({ parentHash, salt });
});

app.post('/generate-child-hash', (req, res) => {
    const childHash = crypto.createHmac('sha256', salt)
        .update(req.body.parentHash)
        .digest('hex');

    res.status(200).json({ childHash });
});

app.post('/check-authenticity', (req, res) => {
    const verifyHash = crypto.createHmac('sha256', salt)
        .update(req.body.parentHash)
        .digest('hex');

    if (verifyHash === req.body.childHash) {
        res.status(200).json({ message: 'Child hash belongs to the same series' });
    } else {
        res.status(400).json({ message: 'Child hash does not belong to the same series' });
    }
});

app.listen(3000, () => {
    console.log('Server listening on port 3000');
});