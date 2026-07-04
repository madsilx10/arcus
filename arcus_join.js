/**
 * Arcus Waitlist Automation (Node.js / ethers.js)
 * Flow per akun:
 *   1. Wallet: sign message -> createapikey -> registeraffiliate (referral: TENX)
 *   2. X OAuth (PKCE): authorize (GET) -> authorize (POST approval) -> Privy authenticate -> Privy-Id-Token
 *   3. joinWithAddress (waitlist.vee-cinco-prod.com)
 *   4. Auto follow @arcus_xyz via X API (friendships/create.json)
 *
 * Input:
 *   wallets.txt  -> private key per baris
 *   cookies.txt  -> auth_token & ct0 selang-seling per baris
 *                   (baris 1 = auth_token akun1, baris 2 = ct0 akun1, baris 3 = auth_token akun2, ...)
 *
 * Jalankan: npm install && npm start
 */

import fs from "fs";
import readline from "readline";
import crypto from "crypto";
import axios from "axios";
import { ethers } from "ethers";

// ================== CONFIG ==================
const REFERRAL_CODE = "TENX";
const FOLLOW_TARGET_SCREEN_NAME = "arcus_xyz";

const ARCUS_API = "https://api.arcus.xyz/v1";
const WAITLIST_API = "https://waitlist.vee-cinco-prod.com/v1/waitlist";
const PRIVY_API = "https://auth.privy.io/api/v1";
const X_API = "https://x.com/i/api";

const PRIVY_APP_ID = "cmobo450d00ug0cjy8hcx1645";
const PRIVY_CA_ID = "808a180c-a519-4696-a84e-1754a7f2035f";

const X_OAUTH_CLIENT_ID = "cWxnOTJXTFpJU3JHMXdESUhtTXc6MTpjaQ";
const X_BEARER =
  "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Dz7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA";

const ORIGIN = "https://waitlist.arcus.xyz";
const UA =
  "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";

const WALLETS_FILE = "wallets.txt";
const COOKIES_FILE = "cookies.txt";

// ================== HELPERS ==================

function log(msg) {
  console.log(msg);
}

function b64url(buf) {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function genCodeVerifier() {
  return b64url(crypto.randomBytes(32));
}

function genCodeChallenge(verifier) {
  const digest = crypto.createHash("sha256").update(verifier).digest();
  return b64url(digest);
}

function genState() {
  return b64url(crypto.randomBytes(24));
}

function loadWallets(path) {
  if (!fs.existsSync(path)) return [];
  return fs
    .readFileSync(path, "utf-8")
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);
}

function loadCookies(path) {
  if (!fs.existsSync(path)) return [];
  const raw = fs.readFileSync(path, "utf-8");
  // Split per blok (dipisah baris kosong), tiap blok = 1 akun
  const blocks = raw.split(/\n\s*\n/).map((b) => b.trim()).filter(Boolean);
  const pairs = [];
  for (const block of blocks) {
    const lines = block.split("\n").map((l) => l.trim()).filter(Boolean);
    if (lines.length >= 2) {
      pairs.push({ auth_token: lines[0], ct0: lines[1] });
    }
  }
  return pairs;
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function ask(question) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  return new Promise((resolve) =>
    rl.question(question, (ans) => {
      rl.close();
      resolve(ans.trim());
    })
  );
}

// ================== STEP 1: WALLET ==================

async function walletFlow(privateKey) {
  const wallet = new ethers.Wallet(privateKey);
  const address = wallet.address;
  log(`[WALLET] address: ${address}`);

  const validUntil = Date.now() + 15_000_000_000;

  // Generate Ed25519 keypair — sama persis dengan CA.utils.randomSecretKey() + CA.getPublicKey()
  const secretKeySeed = crypto.randomBytes(32); // raw bytes
  const edPrivKey = crypto.createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), secretKeySeed]),
    format: "der",
    type: "pkcs8",
  });
  const edPubKey = crypto.createPublicKey(edPrivKey);
  const pubKeyBytes = edPubKey.export({ type: "spki", format: "der" }).slice(-32);

  // AA(r) = base64 encode
  const publicKeyHex = pubKeyBytes.toString("hex");      // hex untuk X-Api-Key header
  const publicKeyB64 = pubKeyBytes.toString("base64");   // base64 untuk createapikey body

  // Message pakai base64 public key (sesuai source JS: AA(r))
  const messageObj = {
    apiWalletName: "arcus-referrals",
    apiWalletPublicKey: publicKeyB64,
    validUntil,
  };
  const messageStr = JSON.stringify(messageObj);
  log(`[WALLET] signing message: ${messageStr}`);

  const flatSig = await wallet.signMessage(messageStr);
  const sig = ethers.Signature.from(flatSig);

  const body = {
    address,
    publicKey: publicKeyB64,   // base64 sesuai source JS
    apiWalletName: "arcus-referrals",
    keyName: "Arcus Referrals",
    validUntil,
    signature: {
      r: sig.r.slice(2),
      s: sig.s.slice(2),
      v: sig.v.toString(16),
    },
  };

  const headers = {
    "Content-Type": "application/json",
    Origin: ORIGIN,
    Referer: ORIGIN + "/",
    "User-Agent": UA,
  };

  log(`[WALLET] createapikey body: ${JSON.stringify(body, null, 2)}`);
  let apiKey = null;
  try {
    const resp = await axios.post(`${ARCUS_API}/createapikey`, body, {
      headers,
      validateStatus: () => true,
    });
    log(`[WALLET] createapikey -> ${resp.status}`);
    if (resp.status !== 200) {
      log(`[WALLET] createapikey FAILED: ${JSON.stringify(resp.data).slice(0, 300)}`);
      return { apiKey: null, address };
    }
    apiKey = resp.data.apiKey;
    log(`[WALLET] apiKey diterima`);
  } catch (err) {
    log(`[WALLET] createapikey ERROR: ${err.message}`);
    return { apiKey: null, address };
  }

  // ---- ambil server timestamp ----
  let timeNs;
  try {
    const tr = await axios.get(`${ARCUS_API}/time`, { headers, validateStatus: () => true });
    timeNs = String(tr.data.timeNs);
    log(`[WALLET] server timeNs: ${timeNs}`);
  } catch (e) {
    timeNs = String(BigInt(Date.now()) * 1_000_000n);
    log(`[WALLET] fallback timeNs: ${timeNs}`);
  }

  // ---- registeraffiliate ----
  const affPath = "/v1/affiliate/registeraffiliate";
  const affBody = { address: address.toLowerCase(), code: REFERRAL_CODE };
  const affBodyStr = JSON.stringify(affBody);

  // Payload = timestamp + path + body, di-encode ke Uint8Array
  const sigPayload = Buffer.from(`${timeNs}${affPath}${affBodyStr}`);
  log(`[WALLET] sig payload: ${timeNs}${affPath}${affBodyStr}`);
  const xSignature = crypto.sign(null, sigPayload, edPrivKey).toString("base64url");

  const affHeaders = {
    ...headers,
    "X-Api-Key": publicKeyHex,
    "X-Signature": xSignature,
    "X-Timestamp": timeNs,
  };

  try {
    const resp2 = await axios.post(
      `${ARCUS_API}/affiliate/registeraffiliate`,
      affBody,
      { headers: affHeaders, validateStatus: () => true }
    );
    log(
      `[WALLET] registeraffiliate -> ${resp2.status} | ${JSON.stringify(
        resp2.data
      ).slice(0, 200)}`
    );
  } catch (err) {
    log(`[WALLET] registeraffiliate ERROR: ${err.message}`);
  }

  return { apiKey, address, signature: flatSig, publicKeyHex };
}

// ================== STEP 2: X OAUTH (PKCE) ==================

async function getGuestId() {
  // Coba endpoint utama dulu
  const endpoints = [
    { url: `${X_API}/1.1/guest/activate.json`, method: "post" },
    { url: `https://api.x.com/1.1/guest/activate.json`, method: "post" },
  ];

  for (const ep of endpoints) {
    try {
      const r = await axios({
        method: ep.method,
        url: ep.url,
        headers: {
          Authorization: `Bearer ${X_BEARER}`,
          "User-Agent": UA,
          "Accept": "*/*",
          "Accept-Language": "en-US,en;q=0.9",
          "Content-Type": "application/x-www-form-urlencoded",
          "Origin": "https://x.com",
          "Referer": "https://x.com/",
          "x-twitter-active-user": "yes",
          "x-twitter-client-language": "en",
        },
        validateStatus: () => true,
      });
      if (r.status === 200 && r.data?.guest_token) {
        log(`[X-OAUTH] guest_token diperoleh: ${r.data.guest_token}`);
        return r.data.guest_token;
      }
      log(`[X-OAUTH] ${ep.url} -> ${r.status}`);
    } catch (err) {
      log(`[X-OAUTH] guest_token ERROR: ${err.message}`);
    }
  }
  return null;
}

async function xOauthFlow(authToken, ct0) {
  const codeVerifier = genCodeVerifier();
  const codeChallenge = genCodeChallenge(codeVerifier);
  const state = genState();

  const guestToken = await getGuestId();
  const guestId = guestToken ? `v1%3A${guestToken}` : null;

  let cookieHeader = `auth_token=${authToken}; ct0=${ct0}`;
  if (guestId) {
    cookieHeader += `; guest_id=${guestId}; guest_id_ads=${guestId}; guest_id_marketing=${guestId}`;
  }

  const authorizeParams = new URLSearchParams({
    client_id: X_OAUTH_CLIENT_ID,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    redirect_uri: `${PRIVY_API}/oauth/callback`,
    response_type: "code",
    scope: "users.read tweet.read",
    state,
  });

  const headersX = {
    Authorization: `Bearer ${X_BEARER}`,
    "User-Agent": UA,
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    Referer: `https://x.com/i/oauth2/authorize`,
    Cookie: cookieHeader,
    "X-Csrf-Token": ct0,
    "X-Twitter-Active-User": "yes",
    "X-Twitter-Auth-Type": "OAuth2Session",
    "X-Twitter-Client-Language": "en",
    ...(guestToken && { "X-Guest-Token": guestToken }),
  };

  let authCode = null;
  try {
    let r1 = await axios.get(
      `${X_API}/2/oauth2/authorize?${authorizeParams.toString()}`,
      { headers: headersX, validateStatus: () => true }
    );
    log(`[X-OAUTH] step1 authorize GET -> ${r1.status}`);
    log(`[X-OAUTH] step1 response: ${JSON.stringify(r1.data).slice(0, 500)}`);

    // Kalau 401, coba tanpa Authorization Bearer (pure cookie auth)
    if (r1.status === 401) {
      log(`[X-OAUTH] step1 retry tanpa Bearer...`);
      const headersNoBear = { ...headersX };
      delete headersNoBear.Authorization;
      r1 = await axios.get(
        `${X_API}/2/oauth2/authorize?${authorizeParams.toString()}`,
        { headers: headersNoBear, validateStatus: () => true }
      );
      log(`[X-OAUTH] step1 retry -> ${r1.status} | ${JSON.stringify(r1.data).slice(0, 300)}`);
    }

    if (r1.status !== 200) {
      log(`[X-OAUTH] FAILED step1: ${JSON.stringify(r1.data).slice(0, 300)}`);
      return null;
    }
    authCode = r1.data?.auth_code;
    if (!authCode) {
      log(`[X-OAUTH] auth_code tidak ditemukan: ${JSON.stringify(r1.data).slice(0, 300)}`);
      return null;
    }
  } catch (err) {
    log(`[X-OAUTH] step1 ERROR: ${err.message}`);
    return null;
  }

  // ---- step 2: approve ----
  const approveHeaders = {
    ...headersX,
    "Content-Type": "application/x-www-form-urlencoded",
    Referer: `https://x.com/i/oauth2/authorize?${authorizeParams.toString()}`,
  };

  let authorizationCode = null;
  try {
    const r2 = await axios.post(
      `${X_API}/2/oauth2/authorize`,
      new URLSearchParams({ approval: "true", code: authCode }).toString(),
      {
        headers: approveHeaders,
        validateStatus: () => true,
        maxRedirects: 0,
      }
    );
    log(`[X-OAUTH] step2 approve POST -> ${r2.status}`);

    const location = r2.headers?.location;
    if (location) {
      const m = location.match(/[?&]code=([^&]+)/);
      if (m) authorizationCode = decodeURIComponent(m[1]);
    }
    if (!authorizationCode && r2.data) {
      authorizationCode = r2.data.code || null;
    }
    if (!authorizationCode) {
      log(`[X-OAUTH] gagal dapat authorization_code. body: ${JSON.stringify(r2.data).slice(0, 300)}`);
      return null;
    }
  } catch (err) {
    log(`[X-OAUTH] step2 ERROR: ${err.message}`);
    return null;
  }

  // ---- step 3: privy authenticate ----
  const privyHeaders = {
    "Content-Type": "application/json",
    Origin: ORIGIN,
    Referer: ORIGIN + "/",
    "Privy-App-Id": PRIVY_APP_ID,
    "Privy-Ca-Id": PRIVY_CA_ID,
    "Privy-Client": "react-auth:3.18.0",
    "Privy-Client-Id": "client-WY6Ye8SLfT4zfcSrZ7tJnyeQAvdWiXbpptjM9EzLND3vV",
    "User-Agent": UA,
  };
  const authBody = {
    authorization_code: authorizationCode,
    code_verifier: codeVerifier,
    mode: "login-or-sign-up",
    state_code: state,
  };

  try {
    const r3 = await axios.post(`${PRIVY_API}/oauth/authenticate`, authBody, {
      headers: privyHeaders,
      validateStatus: () => true,
    });
    log(`[X-OAUTH] step3 privy authenticate -> ${r3.status}`);
    if (r3.status !== 200) {
      log(`[X-OAUTH] FAILED step3: ${JSON.stringify(r3.data).slice(0, 300)}`);
      return null;
    }

    const privyToken = r3.data.identity_token || r3.data.token;
    const linked = r3.data?.user?.linked_accounts || [];
    const xHandle = linked.find((a) => a.type === "twitter_oauth")?.username;

    log(`[X-OAUTH] sukses, handle: @${xHandle}`);
    return { privyToken, xHandle };
  } catch (err) {
    log(`[X-OAUTH] step3 ERROR: ${err.message}`);
    return null;
  }
}

// ================== STEP 3: JOIN WAITLIST ==================

async function joinWaitlist(address, signature) {
  const headers = {
    "Content-Type": "application/json",
    "ngrok-skip-browser-warning": "1",
    Origin: ORIGIN,
    Referer: ORIGIN + "/",
    "User-Agent": UA,
  };
  const body = { ethereumAddress: address, signature };

  try {
    const r = await axios.post(`${WAITLIST_API}/joinWithAddress`, body, {
      headers,
      validateStatus: () => true,
    });
    log(`[JOIN] joinWithAddress -> ${r.status} | ${JSON.stringify(r.data).slice(0, 200)}`);
    return r.status === 200;
  } catch (err) {
    log(`[JOIN] ERROR: ${err.message}`);
    return false;
  }
}

// ================== STEP 4: AUTO FOLLOW ==================

async function autoFollow(authToken, ct0, target) {
  const cookieHeader = `auth_token=${authToken}; ct0=${ct0}`;
  const headers = {
    Authorization: `Bearer ${X_BEARER}`,
    "User-Agent": UA,
    Cookie: cookieHeader,
    "X-Csrf-Token": ct0,
    "X-Twitter-Active-User": "yes",
    "X-Twitter-Auth-Type": "OAuth2Session",
    "X-Twitter-Client-Language": "id",
    "Content-Type": "application/x-www-form-urlencoded",
    Referer: "https://x.com/",
  };
  const data = new URLSearchParams({
    include_profile_interstitial_type: "1",
    include_blocking: "1",
    include_blocked_by: "1",
    include_followed_by: "1",
    include_want_retweets: "1",
    include_mute_edge: "1",
    include_can_dm: "1",
    screen_name: target,
  }).toString();

  try {
    const r = await axios.post(`${X_API}/1.1/friendships/create.json`, data, {
      headers,
      validateStatus: () => true,
    });
    log(`[FOLLOW] follow @${target} -> ${r.status}`);
    return r.status === 200;
  } catch (err) {
    log(`[FOLLOW] ERROR: ${err.message}`);
    return false;
  }
}

// ================== MAIN RUNNER ==================

async function processAccount(idx, privateKey, cookiePair) {
  log(`\n===== AKUN #${idx + 1} =====`);

  const { apiKey, address, signature } = await walletFlow(privateKey);
  if (!address) {
    log("[SKIP] wallet flow gagal total");
    return;
  }

  await joinWaitlist(address, signature);
  await autoFollow(cookiePair.auth_token, cookiePair.ct0, FOLLOW_TARGET_SCREEN_NAME);
}

async function main() {
  const wallets = loadWallets(WALLETS_FILE);
  const cookies = loadCookies(COOKIES_FILE);

  if (!wallets.length || !cookies.length) {
    console.log(
      `File belum lengkap. wallets: ${wallets.length}, cookies (pair): ${cookies.length}`
    );
    return;
  }

  const total = Math.min(wallets.length, cookies.length);
  console.log(`Total akun terdeteksi: ${total}`);
  console.log("\nPilih mode:");
  console.log("1. Jalankan 1 akun (pilih nomor)");
  console.log("2. Jalankan semua akun");
  console.log("3. Jalankan dari X sampai akhir");
  const choice = await ask("Pilihan (1/2/3): ");

  let indices = [];
  if (choice === "1") {
    const num = parseInt(await ask(`Nomor akun (1-${total}): `), 10) - 1;
    indices = [num];
  } else if (choice === "2") {
    indices = Array.from({ length: total }, (_, i) => i);
  } else if (choice === "3") {
    const start =
      parseInt(await ask(`Mulai dari akun ke berapa (1-${total}): `), 10) - 1;
    indices = Array.from({ length: total - start }, (_, i) => start + i);
  } else {
    console.log("Pilihan tidak valid.");
    return;
  }

  for (const i of indices) {
    if (i < 0 || i >= total) {
      log(`[SKIP] index ${i + 1} di luar range`);
      continue;
    }
    await processAccount(i, wallets[i], cookies[i]);
    await sleep(3000 + Math.random() * 4000);
  }

  console.log("\nSelesai. Cek log di atas untuk hasil tiap akun.");
}

main();
