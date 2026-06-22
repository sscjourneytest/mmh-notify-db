/**
 * Minimal Web Push (RFC 8291 + VAPID) implementation built on the
 * Web Crypto API (SubtleCrypto), so it runs natively in Cloudflare Workers
 * without any Node.js "crypto" module dependency.
 *
 * This avoids needing the npm "web-push" package, which assumes Node.
 */

// ---- base64url helpers --------------------------------------------------

function base64UrlToUint8Array(base64Url) {
  const padding = "=".repeat((4 - (base64Url.length % 4)) % 4);
  const base64 = (base64Url + padding).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(base64);
  const arr = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
  return arr;
}

function uint8ArrayToBase64Url(bytes) {
  let str = "";
  for (let i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function concatUint8Arrays(...arrays) {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

// ---- VAPID JWT (ES256) ---------------------------------------------------

/**
 * VAPID keys must be supplied as a JWK private key (P-256) for this to work
 * cleanly with SubtleCrypto. Generate them once (see scripts/generate-vapid-keys.js)
 * and store:
 *   VAPID_PUBLIC  = the uncompressed public key, base64url (used in JWT + frontend applicationServerKey)
 *   VAPID_PRIVATE = the JWK-encoded private key as a JSON string
 */
async function getVapidSigningKey(vapidPrivateJwkString) {
  const jwk = JSON.parse(vapidPrivateJwkString);
  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );
}

async function buildVapidJwt({ audience, subject, publicKeyB64Url, privateKeyJwkString }) {
  const header = { typ: "JWT", alg: "ES256" };
  const exp = Math.floor(Date.now() / 1000) + 12 * 60 * 60; // 12 hours
  const payload = { aud: audience, exp, sub: subject };

  const encodedHeader = uint8ArrayToBase64Url(new TextEncoder().encode(JSON.stringify(header)));
  const encodedPayload = uint8ArrayToBase64Url(new TextEncoder().encode(JSON.stringify(payload)));
  const unsignedToken = `${encodedHeader}.${encodedPayload}`;

  const signingKey = await getVapidSigningKey(privateKeyJwkString);
  const signatureBuffer = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    signingKey,
    new TextEncoder().encode(unsignedToken)
  );

  const signatureB64Url = uint8ArrayToBase64Url(new Uint8Array(signatureBuffer));
  return `${unsignedToken}.${signatureB64Url}`;
}

// ---- RFC 8291 message encryption (aes128gcm) ------------------------------

async function encryptPayload(payload, p256dhB64Url, authB64Url) {
  const payloadBytes = new TextEncoder().encode(payload);
  const clientPublicKeyBytes = base64UrlToUint8Array(p256dhB64Url);
  const authSecret = base64UrlToUint8Array(authB64Url);

  // Generate an ephemeral local EC key pair for this message.
  const localKeyPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );
  const localPublicKeyRaw = new Uint8Array(
    await crypto.subtle.exportKey("raw", localKeyPair.publicKey)
  );

  const clientPublicKey = await crypto.subtle.importKey(
    "raw",
    clientPublicKeyBytes,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );

  const sharedSecretBuffer = await crypto.subtle.deriveBits(
    { name: "ECDH", public: clientPublicKey },
    localKeyPair.privateKey,
    256
  );
  const sharedSecret = new Uint8Array(sharedSecretBuffer);

  const salt = crypto.getRandomValues(new Uint8Array(16));

  // Step 1 (RFC 8291 §3.4): derive the pseudo-random key (IKM) for this message.
  // IKM = HKDF(salt = authSecret, ikm = sharedSecret, info = "WebPush: info\0" || clientPubKey || localPubKey, len=32)
  const keyInfo = concatUint8Arrays(
    new TextEncoder().encode("WebPush: info\0"),
    clientPublicKeyBytes,
    localPublicKeyRaw
  );

  const sharedSecretKey = await crypto.subtle.importKey("raw", sharedSecret, { name: "HKDF" }, false, [
    "deriveBits",
  ]);
  const ikm = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: authSecret, info: keyInfo },
      sharedSecretKey,
      256
    )
  );

  // Step 2: derive Content Encryption Key (CEK) and Nonce from IKM, using the random per-message `salt`.
  const cekInfo = new TextEncoder().encode("Content-Encoding: aes128gcm\0");
  const nonceInfo = new TextEncoder().encode("Content-Encoding: nonce\0");

  const cekHkdfKey = await crypto.subtle.importKey("raw", ikm, { name: "HKDF" }, false, [
    "deriveBits",
  ]);
  const cek = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt, info: cekInfo },
      cekHkdfKey,
      128
    )
  );
  const nonce = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt, info: nonceInfo },
      cekHkdfKey,
      96
    )
  );

  // Padding: RFC8291 requires a delimiter byte (0x02) then content. Minimal padding = none extra.
  const paddedPayload = concatUint8Arrays(payloadBytes, new Uint8Array([0x02]));

  const aesKey = await crypto.subtle.importKey("raw", cek, { name: "AES-GCM" }, false, ["encrypt"]);
  const encryptedBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce },
    aesKey,
    paddedPayload
  );
  const ciphertext = new Uint8Array(encryptedBuffer);

  // Build the aes128gcm header: salt(16) + record size(4, big-endian) + keyid length(1) + keyid(localPublicKeyRaw)
  const recordSize = ciphertext.length + 16; // not strictly required to be exact max, but must be >= total length
  const header = new Uint8Array(16 + 4 + 1 + localPublicKeyRaw.length);
  header.set(salt, 0);
  new DataView(header.buffer).setUint32(16, recordSize, false);
  header[20] = localPublicKeyRaw.length;
  header.set(localPublicKeyRaw, 21);

  const body = concatUint8Arrays(header, ciphertext);
  return body;
}

// ---- Public entry point ---------------------------------------------------

export async function sendWebPush(subscription, payloadString, vapid) {
  const endpointUrl = new URL(subscription.endpoint);
  const audience = `${endpointUrl.protocol}//${endpointUrl.host}`;

  const jwt = await buildVapidJwt({
    audience,
    subject: vapid.subject,
    publicKeyB64Url: vapid.publicKey,
    privateKeyJwkString: vapid.privateKey,
  });

  const encryptedBody = await encryptPayload(
    payloadString,
    subscription.keys.p256dh,
    subscription.keys.auth
  );

  const response = await fetch(subscription.endpoint, {
    method: "POST",
    headers: {
      TTL: "86400",
      "Content-Type": "application/octet-stream",
      "Content-Encoding": "aes128gcm",
      Authorization: `vapid t=${jwt}, k=${vapid.publicKey}`,
    },
    body: encryptedBody,
  });

  return response;
}
