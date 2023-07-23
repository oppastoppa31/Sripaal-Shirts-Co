
import crypto from 'crypto';
import express from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import sqlite3 from 'sqlite3';

const TOKEN_LENGTH = 16;
const PORT = 8080;

const app = express();
const limiter = rateLimit({});
const db = new sqlite3.Database('./db/emails.db');

app.use(express.json());
app.use(express.urlencoded({extended: true}));
app.use(helmet());
app.use(limiter);
app.set('trust proxy', 1);

db.run(
    'CREATE TABLE IF NOT EXISTS emails(email TEXT UNIQUE NOT NULL,verified BOOLEAN DEFAULT 0,token TEXT UNIQUE NOT NULL)');

const id = function() {
  return crypto.randomBytes(TOKEN_LENGTH).toString('hex');
};

// /api/verify?email=EMAIL&token=TOKEN
app.get('/api/verify', function(req, res) {
  const errorPage = './email-error.html';
  console.log(req.query);
  if (!req.query) {
    console.log('No body provided');
    res.sendFile(errorPage);
    return;
  }
  if (!req.query.email || !req.query.token) {
    console.log('No email or token provided');
    res.sendFile(errorPage);
    return;
  }
  if (!RegExp(
           /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|.(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/)
           .exec(String(req.query.email).toLowerCase()) ||
      !RegExp(/^([A-F0-9]{32})$/).exec(String(req.query.token).toUpperCase())) {
    console.log('Invalid email address or token');
    res.sendFile(errorPage);
    return;
  }
  db.serialize(() => {
    db.run(
        'UPDATE emails SET verified = ? WHERE email = ? AND token = ?',
        [1, req.query.email, req.query.token], function(err) {
          if (err) {
            console.log(err.message);
            res.sendFile(errorPage);
          } else {
            console.log(
                `Email "${req.query.email}" has been verified successfully.'`);
            res.sendFile('./email-verified.html');
          }
        });
  });
});
app.post('/api/email', function(req, res) {
  console.log(req.body);
  if (!req.body) {
    console.log('No body provided');
    res.json({message: 'error'});
    return;
  }
  if (!req.body.subscriber_email) {
    console.log('No email provided');
    res.json({message: 'error'});
    return;
  }
  if (!RegExp(
           /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|.(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/)
           .exec(String(req.body.subscriber_email).toLowerCase())) {
    console.log('Invalid email address');
    res.json({message: 'error'});
    return;
  }
  db.serialize(() => {
    db.run(
        'INSERT INTO emails(email,verified,token) VALUES(?,?,?)',
        [req.body.subscriber_email, 0, id()], function(err) {
          if (err) {
            console.log(err.message);
            res.json({message: 'error'});
          } else {
            console.log(`New email has been added "${
                req.body.subscriber_email}" into the database.'`);
            res.json({message: 'success'});
          }
        });
  });
});
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
