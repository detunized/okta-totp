const CLIENT_INSTANCE_KEY = {
  alg: "RS256",
  e: "AQAB\n",
  "okta:isFipsCompliant": false,
  "okta:kpr": "SOFTWARE",
  kty: "RSA",
  use: "sig",
  kid: "OpSRC6wLx4oPnqGBUuLz-WL7_knbK_UhClzjvt1cpOw",
  n: "u0Y1ygDJ61AghDiEqeGW7lCv4iW2gLOON0Aw-Tm53xQW7qB94MUNVjua8KuYyxS-1pxf58u0pCpVhQxSgZJGht5Z7Gmc0geVuxRza3B_TFLd90SFlEdE3te6IkH28MqDu2rQtonYowVedHXZpOii6QBLPjqP6Zm3zx9r7WokpSvY9fnp8zjixuAUuA0XYhv6EwedfvSiz3t84N-nV0R1cN5Ni8os6sG4K6F8ZSr7E4aXTzvOfJIWa9MC1Lx_J4M7HIUuUH7LV7PN_h5yYk8b-2fW4g3_3h13mQ-blx2qMXclr6uuBc13tLLks7LzY3S34y2K060gHMMWCM4MQ77Mrw"
};

const USER_AGENT = "D2DD7D3915.com.okta.android.auth/6.8.1 DeviceSDK/0.19.0 Android/7.1.1 unknown/Google";

export default {
  async fetch(req) {
    const url = new URL(req.url);
    if (url.pathname === "/api/register") {
      if (req.method !== "POST") return json({ error: "Use POST" }, 405);
      return handleRegister(req);
    }
    return new Response("Not found", { status: 404 });
  }
};

async function handleRegister(req) {
  let payload;
  try {
    payload = await req.json();
  } catch {
    return json({ error: "Invalid JSON body" }, 400);
  }

  const { oktaUrl, deviceName } = payload;
  if (typeof oktaUrl !== "string" || !oktaUrl.startsWith("oktaverify://")) {
    return json({ error: "oktaUrl must start with oktaverify://" }, 400);
  }

  const displayName = typeof deviceName === "string" ? deviceName.trim() : "";
  if (!displayName) {
    return json({ error: "deviceName must not be empty" }, 400);
  }

  let parsed;
  try {
    parsed = new URL(oktaUrl);
  } catch (err) {
    return json({ error: `Failed to parse oktaUrl: ${err.message}` }, 400);
  }

  const t = parsed.searchParams.get("t");
  const f = parsed.searchParams.get("f");
  const s = parsed.searchParams.get("s");

  if (!t || !f || !s) {
    return json({ error: "URL is missing required params t, f, or s" }, 400);
  }

  let serverUrl;
  try {
    serverUrl = new URL("/idp/authenticators", s);
  } catch (err) {
    return json({ error: `Invalid server URL s=${s}: ${err.message}` }, 400);
  }
  if (serverUrl.protocol !== "https:") {
    return json({ error: `Server URL must use https: s=${s}` }, 400);
  }

  const body = {
    authenticatorId: f,
    device: {
      clientInstanceBundleId: "com.okta.android.auth",
      clientInstanceDeviceSdkVersion: "DeviceSDK 0.19.0",
      clientInstanceVersion: "6.8.1",
      clientInstanceKey: CLIENT_INSTANCE_KEY,
      deviceAttestation: {},
      displayName,
      fullDiskEncryption: false,
      isHardwareProtectionEnabled: false,
      manufacturer: "unknown",
      model: "Google",
      osVersion: "25",
      platform: "ANDROID",
      rootPrivileges: true,
      screenLock: false,
      secureHardwarePresent: false
    },
    key: "okta_verify",
    methods: [
      {
        isFipsCompliant: false,
        supportUserVerification: false,
        type: "totp"
      }
    ]
  };

  let resp;
  try {
    resp = await fetch(serverUrl, {
      method: "POST",
      headers: {
        "Accept": "application/json; charset=UTF-8",
        "Authorization": `OTDT ${t}`,
        "Content-Type": "application/json; charset=UTF-8",
        "User-Agent": USER_AGENT
      },
      body: JSON.stringify(body)
    });
  } catch (err) {
    return json({ error: `Network error calling Okta: ${err.message}` }, 502);
  }

  const text = await resp.text();
  let data = null;
  try { data = JSON.parse(text); } catch { /* non-JSON response */ }

  if (!resp.ok) {
    return json({
      error: "Okta request failed",
      status: resp.status,
      response: data ?? text
    }, 502);
  }

  const sharedSecret = findSharedSecret(data);
  return json({ sharedSecret, raw: data });
}

function findSharedSecret(obj) {
  if (!obj || typeof obj !== "object") return null;
  if (typeof obj.sharedSecret === "string") return obj.sharedSecret;
  for (const key of Object.keys(obj)) {
    const found = findSharedSecret(obj[key]);
    if (found) return found;
  }
  return null;
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" }
  });
}
