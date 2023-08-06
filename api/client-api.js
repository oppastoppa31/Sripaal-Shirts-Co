
import https from 'node:https';
import crypto from 'node:crypto';
import fs from 'node:fs';

const ip = await new Promise((resolve, _) => {
    const options = {
        host: 'ifconfig.me',
        port: 443,
        path: '/ip',
        method: 'GET'
    };
    const request = https.request(options, d => {
        let data = '';
        d.on('data', chunk => {
            data += chunk;
        });
        d.on('end', () => {
            resolve(data);
        });
    });
    request.end();
});

(() => {
    const signer = crypto.createSign('sha3-512');
    const privateKey = fs.readFileSync('./keys/private.pem', 'utf8');

    const options = {
        host: 'sripaalshirts.com',
        port: 443,
        path: '/api/vpn',
        method: 'POST'
    };
    signer.write(ip);
    signer.end();
    const signature = signer.sign(privateKey, 'hex');

    const postData = JSON.stringify({ ip: ip, signature: signature });
    const request = https.request(options, _ => { });
    request.write(postData);
    request.end();
})();
