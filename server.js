// Votifier relay — bridges the website (static, no backend) to your Minecraft
// server's Votifier port using the real Votifier v1 protocol (RSA-encrypted).
//
// Why this exists: GitHub Pages / any static site cannot open a raw TCP socket
// to your Minecraft server. This tiny server can (it must be hosted somewhere
// that runs real Node.js — Render, Railway, a VPS, your own PC, etc. — NOT
// GitHub Pages). The website calls this relay's /vote endpoint after a player
// votes; this relay then does the actual Votifier handshake your VotingPlugin
// is listening for.
//
// Supports classic Votifier v1 (RSA). Most builds of VotingPlugin still accept
// v1. If your server only has NuVotifier v2 (token-based) enabled, say so and
// this can be extended — v2 uses a different (AES+HMAC) payload format.

const express = require('express');
const net = require('net');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors()); // allow requests from your GitHub Pages site's origin

// Simple shared-secret check so randoms on the internet can't spam fake votes
// at your Minecraft server through this relay. Set this in your hosting
// platform's environment variables, and put the same value in the website's
// voteForServer() fetch call.
const RELAY_SECRET = process.env.RELAY_SECRET || 'change-me';

app.post('/vote', (req, res) => {
  try {
    const { secret, ip, port, publicKey, username, serviceName } = req.body || {};

    if (secret !== RELAY_SECRET) {
      return res.status(403).json({ ok: false, error: 'Bad secret' });
    }
    if (!ip || !port || !publicKey || !username) {
      return res.status(400).json({ ok: false, error: 'Missing ip, port, publicKey, or username' });
    }

    sendVotifierV1({
      host: ip,
      port: parseInt(port, 10),
      publicKeyPem: publicKey,
      username,
      serviceName: serviceName || 'Website',
      address: req.ip || '0.0.0.0'
    })
      .then(() => res.json({ ok: true }))
      .catch((err) => {
        console.error('Votifier send failed:', err.message);
        res.status(502).json({ ok: false, error: err.message });
      });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: 'Internal error' });
  }
});

app.get('/', (req, res) => res.send('Votifier relay is running.'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Votifier relay listening on ${PORT}`));

/**
 * Sends one vote using the classic Votifier v1 protocol:
 * 1. Connect via TCP.
 * 2. Read the server's greeting line (contains "VOTIFIER").
 * 3. Build the vote block: "VOTE\nserviceName\nusername\naddress\ntimestamp\n"
 * 4. RSA-encrypt (PKCS#1 v1.5) the block with the server's public key.
 * 5. Write the encrypted bytes to the socket and close.
 */
function sendVotifierV1({ host, port, publicKeyPem, username, serviceName, address }) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host, port, timeout: 8000 });
    let handled = false;

    socket.on('timeout', () => {
      socket.destroy();
      if (!handled) { handled = true; reject(new Error('Connection to Votifier timed out')); }
    });

    socket.on('error', (err) => {
      if (!handled) { handled = true; reject(err); }
    });

    socket.once('data', () => {
      // First data from the server is the greeting ("VOTIFIER 1.9" etc.) —
      // once we see it, the connection is ready for the encrypted payload.
      try {
        const voteBlock =
          `VOTE\n${serviceName}\n${username}\n${address}\n${Date.now()}\n`;

        const key = normalizePublicKey(publicKeyPem);
        const encrypted = crypto.publicEncrypt(
          { key, padding: crypto.constants.RSA_PKCS1_PADDING },
          Buffer.from(voteBlock, 'utf8')
        );

        socket.write(encrypted, (err) => {
          if (err) { if (!handled) { handled = true; reject(err); } return; }
          socket.end();
          if (!handled) { handled = true; resolve(); }
        });
      } catch (err) {
        socket.destroy();
        if (!handled) { handled = true; reject(err); }
      }
    });
  });
}

// Accepts a PEM key with or without the standard header/footer/newlines
// (handy since the admin panel just pastes the key into a text box).
function normalizePublicKey(raw) {
  let key = raw.trim();
  if (!key.includes('BEGIN PUBLIC KEY') && !key.includes('BEGIN RSA PUBLIC KEY')) {
    // Assume it's raw base64 with no PEM wrapper — wrap it ourselves.
    const body = key.match(/.{1,64}/g).join('\n');
    key = `-----BEGIN PUBLIC KEY-----\n${body}\n-----END PUBLIC KEY-----`;
  }
  return key;
}
