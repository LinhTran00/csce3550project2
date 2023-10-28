const express = require('express');
const jwt = require('jsonwebtoken');
const jose = require('node-jose');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const port = 8080;

let keyPair;
let expiredKeyPair;
let token;
let expiredToken;

const path = require('path');

// Specify the path to your SQLite database file 
// change path as needed
const dbPath = path.join('C:', 'Users', 'heoch', 'Downloads', 'CSCE3550_Windows_x86_64', 'totally_not_my_privateKeys.db');

// Create a new SQLite database connection
const db = new sqlite3.Database(dbPath);

// Function to generate RSA key pairs
async function generateKeyPairs() {
  keyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
  expiredKeyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });

  // Convert key pairs to PKCS1 PEM format
  const keyPairtoPem = keyPair.toPEM(true);
  const expiredKeyPairtoPem = expiredKeyPair.toPEM(true);

  // Create a keys table in the SQLite database if it doesn't exist
  db.serialize(() => {
    db.run(
      'CREATE TABLE IF NOT EXISTS keys ('
      + 'kid INTEGER PRIMARY KEY AUTOINCREMENT,'
      + 'key TEXT NOT NULL,'
      + 'exp INTEGER NOT NULL'
      + ');',
    );
  });

  // Insert the key pairs into the keys table
  const insertKey = db.prepare('INSERT INTO keys (key, exp) VALUES (?, ?)');
  insertKey.run(keyPairtoPem, Math.floor(Date.now() / 1000) + 3600);
  insertKey.run(expiredKeyPairtoPem, Math.floor(Date.now() / 1000) - 3600);
  insertKey.finalize();
}

// Function to generate a JWT token
function generateToken() {
  const payload = {
    user: 'sampleUser',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
  };
  const options = {
    algorithm: 'RS256',
    header: {
      typ: 'JWT',
      alg: 'RS256',
      kid: keyPair.kid,
    },
  };

  token = jwt.sign(payload, keyPair.toPEM(true), options);
}

// Function to generate an expired JWT
function generateExpiredJWT() {
  const payload = {
    user: 'sampleUser',
    iat: Math.floor(Date.now() / 1000) - 30000,
    exp: Math.floor(Date.now() / 1000) - 3600,
  };
  const options = {
    algorithm: 'RS256',
    header: {
      typ: 'JWT',
      alg: 'RS256',
      kid: expiredKeyPair.kid,
    },
  };

  expiredToken = jwt.sign(payload, expiredKeyPair.toPEM(true), options);
}

// Middleware to handle /auth route for POST requests
app.all('/auth', (req, res, next) => {
  if (req.method !== 'POST') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

// Middleware to ensure only GET requests are allowed for /jwks
app.all('/.well-known/jwks.json', (req, res, next) => {
  if (req.method !== 'GET') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

// Route to handle GET requests for /.well-known/jwks.json
app.get('/.well-known/jwks.json', (req, res) => {
  // Filter out expired keys from the validKeys array
  const validKeys = [keyPair].filter((key) => !key.expired);
  res.setHeader('Content-Type', 'application/json');
  res.json({ keys: validKeys.map((key) => key.toJSON()) });
});

// Route to handle POST requests for /auth
app.post('/auth', (req, res) => {
  if (req.query.expired === 'true') {
    return res.send(expiredToken);
  }
  res.send(token);
});

// Generate key pairs and start the server
generateKeyPairs().then(async () => {
  generateToken();
  generateExpiredJWT();
  app.listen(port, () => {
    console.log(`Server started on http://localhost:${port}`);
  });
});

module.exports = app; // Export the Express app
