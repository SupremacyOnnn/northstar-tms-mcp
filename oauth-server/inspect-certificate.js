
require("dotenv").config();

const net = require("node:net");
const tls = require("node:tls");

const url = new URL(process.env.DATABASE_URL);
const host = url.hostname;
const port = Number(url.port || 5432);

const socket = net.connect({ host, port });
socket.setTimeout(10000);

socket.once("connect", () => {
  // PostgreSQL SSLRequest: length 8, code 80877103
  const request = Buffer.alloc(8);
  request.writeInt32BE(8, 0);
  request.writeInt32BE(80877103, 4);
  socket.write(request);
});

socket.once("data", (response) => {
  if (response[0] !== 83) {
    console.error("PostgreSQL did not accept SSL negotiation");
    socket.destroy();
    return;
  }

  socket.removeAllListeners("timeout");

  const secureSocket = tls.connect({
    socket,
    servername: host,
    rejectUnauthorized: false
  });

  secureSocket.once("secureConnect", () => {
    console.log("Certificate trusted:", secureSocket.authorized);
    console.log("Verification error:", secureSocket.authorizationError);

    let cert = secureSocket.getPeerCertificate(true);
    let depth = 0;
    const seen = new Set();

    while (cert && cert.raw && !seen.has(cert.fingerprint256)) {
      seen.add(cert.fingerprint256);

      console.log(`\nCertificate ${depth}`);
      console.log("Subject:", cert.subject);
      console.log("Issuer:", cert.issuer);
      console.log("Valid until:", cert.valid_to);

      if (!cert.issuerCertificate ||
          cert.issuerCertificate === cert) break;

      cert = cert.issuerCertificate;
      depth++;
    }

    secureSocket.end();
  });

  secureSocket.on("error", (error) => {
    console.error("TLS error:", error.message);
    secureSocket.destroy();
  });
});

socket.on("timeout", () => {
  console.error("Connection timed out");
  socket.destroy();
});

socket.on("error", (error) => {
  console.error("Connection error:", error.message);
});
