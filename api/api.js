
import 'dotenv/config';

import crypto from 'crypto';
import express from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import multer from 'multer';
import nodemailer from 'nodemailer';
import sqlite3 from 'sqlite3';

const TOKEN_LENGTH = 16;
const PORT = 8080;
const FILE_LIMIT = 16000000;

const emailRegex =
    /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|.(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
const imageRegex =
    /^(?:R0lG|iVBORw0KGg|Qk[0-3]|UklGR.{6}XRUJQ)(?:[A-Za-z0-9]|[+/])+={0,2}/;
const app = express();
const limiter = rateLimit({});
const db = new sqlite3.Database('./db/emails.db');
const email = nodemailer.createTransport({
  host: 'localhost',
  port: 25,
  tls: {rejectUnauthorized: false},
  auth: {user: process.env.EMAIL_ADDRESS, pass: process.env.EMAIL_PASSWORD}
});

app.use(express.json());
app.use(express.urlencoded({extended: true}));
app.use(helmet());
app.use(limiter);
app.set('trust proxy', 1);

db.run(
    'CREATE TABLE IF NOT EXISTS emails(email TEXT UNIQUE NOT NULL,verified BOOLEAN DEFAULT 0,token TEXT UNIQUE NOT NULL,unsubscribed BOOLEAN DEFAULT 0)');

const id = function() {
  return crypto.randomBytes(TOKEN_LENGTH).toString('hex');
};

// /api/verify?email=EMAIL&token=TOKEN
app.get('/api/verify', function(req, res) {
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
        [1, req.query.email, req.query.token], function(err) {
          res.sendFile(err ? errorPage : successPage);
        });
  });
});

// /api/subscribe
// {subscriber_email: EMAIL}
app.post('/api/subscribe', function(req, res) {
  if (!req.body?.subscriber_email) {
    res.json({message: 'error'});
    return;
  }
  if (!RegExp(emailRegex)
           .exec(String(req.body.subscriber_email).toLowerCase())) {
    res.json({message: 'error'});
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
        [req.body.subscriber_email, 0, id(), 0], function(err) {
          res.json({message: err ? 'error' : 'success'});
        });
  });
});

// /api/unsubscribe?email=EMAIL&token=TOKEN
app.get('/api/unsubscribe', function(req, res) {
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
        [1, req.query.email, req.query.token], function(err) {
          res.sendFile(err ? errorPage : successPage);
        });
  });
});

// /api/contact
// {name: "Name", email: "Email", message: "Message"}
app.post('/api/contact', multer().single('image'), function(req, res) {
  if (!req.body?.name || !req.body?.email || !req.body?.message) {
    res.json({message: 'error'});
    return;
  }

  if (!RegExp(emailRegex).exec(String(req.body.email).toLowerCase())) {
    res.json({message: 'error'});
    return;
  }
  if (req.file?.size > FILE_LIMIT ||
      !RegExp(imageRegex).exec(String(req.file?.buffer.toString('base64')))) {
    res.json({message: 'error'});
    return;
  }
  email.sendMail({
    from: process.env.EMAIL_ADDRESS,
    to: process.env.TO_ADDRESS,
    subject: `New Message from ${req.body.email}`,
    text: `${req.body.name} (${req.body.email}) sent you a message: ${
        req.body.message}`,
    attachments: req.file ?
        [{filename: req.file.originalname, content: req.file.buffer}] :
        []
  });
});
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
