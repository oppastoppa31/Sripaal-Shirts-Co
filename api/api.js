
import 'dotenv/config';

import crypto from 'node:crypto';
import express from 'express';
import fs from 'node:fs';
import helmet from 'helmet';
import https from 'node:https';
import multer from 'multer';
import nodemailer from 'nodemailer';
import rateLimit from 'express-rate-limit';
import sqlite3 from 'sqlite3';

const TOKEN_LENGTH = 16;
const PORT = 8080;
const FILE_LIMIT = 16000000;

const emailRegex =
  /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|.(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;

const app = express();
const limiter = rateLimit({});
const db = new sqlite3.Database('./db/emails.db');
const email = nodemailer.createTransport({
  host: 'localhost',
  port: 25,
  tls: { rejectUnauthorized: false },
  auth: { user: process.env.EMAIL_ADDRESS, pass: process.env.EMAIL_PASSWORD }
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(helmet());
app.use(limiter);
app.set('trust proxy', 1);

db.run(
  'CREATE TABLE IF NOT EXISTS emails(email TEXT UNIQUE NOT NULL,verified BOOLEAN DEFAULT 0,token TEXT UNIQUE NOT NULL,unsubscribed BOOLEAN DEFAULT 0)');

const token = () => crypto.randomBytes(TOKEN_LENGTH).toString('hex');

// /api/verify?email=EMAIL&token=TOKEN
app.get('/api/verify', (req, res) => {
  const errorPage = './email-error.html';
  const successPage = './email-verified.html';

  if (!req.query?.email || !req.query?.token) {
    res.sendFile(errorPage);
    return;
  }
  if (!RegExp(emailRegex).exec(String(req.query.email).toLowerCase()) ||
    !RegExp(/^([A-F0-9]{32})$/).exec(String(req.query.token).toUpperCase())) {
    res.sendFile(errorPage);
    return;
  }
  db.serialize(() => {
    db.run(
      'UPDATE emails SET verified = ? WHERE email = ? AND token = ?',
      [1, req.query.email, req.query.token], err => {
        res.sendFile(err ? errorPage : successPage);
      });
  });
});

// /api/subscribe
// {subscriber_email: EMAIL}
app.post('/api/subscribe', (req, res) => {
  if (!req.body?.subscriber_email) {
    res.json({ message: 'error' });
    return;
  }
  if (!RegExp(emailRegex)
    .exec(String(req.body.subscriber_email).toLowerCase())) {
    res.json({ message: 'error' });
    return;
  }
  email.sendMail({
    from: process.env.EMAIL_ADDRESS,
    to: process.env.TO_ADDRESS,
    subject: 'New Subscriber',
    text: req.body.subscriber_email
  });
  db.serialize(() => {
    db.run(
      'INSERT INTO emails(email,verified,token,unsubscribed) VALUES(?,?,?,?)',
      [req.body.subscriber_email, 0, token(), 0], err => {
        res.json({ message: err ? 'error' : 'success' });
      });
  });
});

// /api/unsubscribe?email=EMAIL&token=TOKEN
app.get('/api/unsubscribe', (req, res) => {
  const errorPage = './email-error.html';
  const successPage = './email-unsubscribed.html';

  if (!req.query?.email || !req.query?.token) {
    res.sendFile(errorPage);
    return;
  }
  if (!RegExp().exec(String(req.query.email).toLowerCase()) ||
    !RegExp(/^([A-F0-9]{32})$/).exec(String(req.query.token).toUpperCase())) {
    res.sendFile(errorPage);
    return;
  }
  db.serialize(() => {
    db.run(
      'UPDATE emails SET unsubscribed = ? WHERE email = ? AND token = ?',
      [1, req.query.email, req.query.token], err => {
        res.sendFile(err ? errorPage : successPage);
      });
  });
});

// /api/contact
// {name: "Name", email: "Email", message: "Message"}
app.post('/api/contact', multer().single('image'), (req, res) => {
  if (!req.body?.name || !req.body?.email || !req.body?.message) {
    res.json({ message: 'error' });
    return;
  }

  if (!RegExp(emailRegex).exec(String(req.body.email).toLowerCase())) {
    res.json({ message: 'error' });
    return;
  }
  if (req.file?.size > FILE_LIMIT || !req.file?.mimetype?.startsWith('image')) {
    res.json({ message: 'error' });
    return;
  }
  email.sendMail({
    from: process.env.EMAIL_ADDRESS,
    to: process.env.TO_ADDRESS,
    subject: `New Message from ${req.body.email}`,
    text: `${req.body.name} (${req.body.email}) sent you a message: ${req.body.message}`,
    attachments: req.file ?
      [{ filename: req.file.originalname, content: req.file.buffer }] :
      []
  });
  res.json({ message: 'success' });
});

//This is a secure endpoint that is used to dynamically update the IP address of the VPN server
// /api/vpn
// {ip: "IP", signature: "Signature"}
app.post('/api/vpn', async (req, res) => {
  const signer = crypto.createVerify('sha3-512');
  const publicKey = fs.readFileSync('./keys/public.pem', 'utf8');

  if (!req.body?.ip || !req.body?.signature) {
    res.json({ message: 'error' });
    return;
  }
  if (!RegExp(/^([0-9]{1,3}\.){3}[0-9]{1,3}$/)
    .exec(String(req.body.ip).toLowerCase()) ||
    !RegExp(/^([A-F0-9]{140,144})$/).exec(String(req.body.signature).toUpperCase())) {
    res.json({ message: 'error' });
    return;
  }

  signer.write(req.body.ip);
  signer.end();
  if (!signer.verify(publicKey, req.body.signature, 'hex')) {
    res.json({ message: 'error' });
    return;
  }

  // Get the ID of the record
  const id = await new Promise((resolve, _) => {
    const options = {
      hostname: 'api.digitalocean.com',
      port: 443,
      path: '/v2/domains/sripaalshirts.com/records/',
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${process.env.DO_TOKEN}`
      }
    };
    const request = https.request(options, d => {
      let data = '';
      d.on('data', chunk => {
        data += chunk;
      });
      d.on('end', () => {
        data = JSON.parse(data);
        for (const record in data.domain_records) {
          if (record.name === 'vpn') {
            resolve(record.id);
          }
        }
        resolve(0);
      });
    });
    request.on('error', _ => {
      res.json({ message: 'error' });
    });
    request.end();
  });

  // Update the record
  if (id !== 0) {
    // Check if the IP address has changed
    const needsUpdate = await new Promise((resolve, _) => {
      const options = {
        hostname: 'api.digitalocean.com',
        port: 443,
        path: `/v2/domains/sripaalshirts.com/records/${id}`,
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${process.env.DO_TOKEN}`
        }
      };
      const request = https.request(options, d => {
        let data = '';
        d.on('data', chunk => {
          data += chunk;
        });
        d.on('end', () => {
          data = JSON.parse(data);
          resolve(data.domain_record.data === req.body.ip);
        });
      });
      request.on('error', _ => {
        res.json({ message: 'error' });
      });
      request.end();
    });

    // Update the record
    if (needsUpdate) {
      const options = {
        hostname: 'api.digitalocean.com',
        port: 443,
        path: `/v2/domains/sripaalshirts.com/records/${id}`,
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${process.env.DO_TOKEN}`
        }
      };
      const patchData = JSON.stringify({
        type: 'A',
        data: req.body.ip
      });
      const request = https.request(options, _ => { });
      request.on('error', _ => {
        res.json({ message: 'error' });
      });
      request.write(patchData);
      request.end();
    }
  }

  else {
    // Create the record
    const options = {
      hostname: 'api.digitalocean.com',
      port: 443,
      path: '/v2/domains/sripaalshirts.com/records',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${process.env.DO_TOKEN}`
      }
    };
    const postData = JSON.stringify({
      type: 'A',
      name: 'vpn',
      data: req.body.ip,
      priority: null,
      port: null,
      ttl: 1800,
      weight: null,
      flags: null,
      tag: null
    });
    const request = https.request(options, _ => { });
    request.on('error', _ => {
      res.json({ message: 'error' });
    });
    request.write(postData);
    request.end();
  }
  res.json({ message: 'success' });
});

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
