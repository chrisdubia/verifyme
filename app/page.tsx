"use client";

import React, { useEffect, useState } from "react";
import {
  startRegistration,
  startAuthentication,
} from "@simplewebauthn/browser";

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function base64FromBytes(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

async function sha256(file: File): Promise<string> {
  const buf = await file.arrayBuffer();
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return bytesToHex(new Uint8Array(digest));
}

// IndexedDB minimal wrapper for a single private CryptoKey
async function idbSetKey(name: string, key: CryptoKey): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const req = indexedDB.open("tl_keys", 1);
    req.onupgradeneeded = () => {
      req.result.createObjectStore("keys");
    };
    req.onsuccess = () => {
      const db = req.result;
      const tx = db.transaction("keys", "readwrite");
      tx.objectStore("keys").put(key, name);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    };
    req.onerror = () => reject(req.error);
  });
}

async function idbGetKey(name: string): Promise<CryptoKey | null> {
  return await new Promise((resolve, reject) => {
    const req = indexedDB.open("tl_keys", 1);
    req.onupgradeneeded = () => {
      req.result.createObjectStore("keys");
    };
    req.onsuccess = () => {
      const db = req.result;
      const tx = db.transaction("keys", "readonly");
      const getReq = tx.objectStore("keys").get(name);
      getReq.onsuccess = () => resolve(getReq.result ?? null);
      getReq.onerror = () => reject(getReq.error);
    };
    req.onerror = () => reject(req.error);
  });
}

async function startPasskeyRegistration(userName: string) {
  const res = await fetch("/api/webauthn/register/options", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ userName }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error ?? "Registration options failed");

  const { userId, options } = data;

  const attResp = await startRegistration(options);

  const verify = await fetch("/api/webauthn/register/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ userId, response: attResp }),
  });

  const verifyData = await verify.json();
  if (!verify.ok) throw new Error(verifyData.error ?? "Registration verify failed");

  return userId as string;
}

async function devLogin(label: string) {
  const res = await fetch("/api/dev/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ label }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error ?? "Dev login failed");
}

async function enrollDeviceKey(name: string) {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );

  await idbSetKey("device_private", keyPair.privateKey);

  const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);

  const res = await fetch("/api/device/enroll", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, publicJwk }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error ?? "Enroll failed");

  return data.deviceKeyId as string;
}

async function signHashHexWithDeviceKey(hashHex: string): Promise<string> {
  const priv = await idbGetKey("device_private");
  if (!priv) throw new Error("No device private key. Enroll device key first.");

  const msg = new Uint8Array(hashHex.match(/.{1,2}/g)!.map((x) => parseInt(x, 16)));
  const sigBuf = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, priv, msg);
  return base64FromBytes(new Uint8Array(sigBuf));
}

export default function Page() {
  const [me, setMe] = useState<any>(null);
  const [userName, setUserName] = useState("Chris");
  const [deviceKeyId, setDeviceKeyId] = useState<string | null>(null);

  const [file, setFile] = useState<File | null>(null);
  const [hashHex, setHashHex] = useState<string>("");
  const [recordId, setRecordId] = useState<string>("");
  const [receiptJson, setReceiptJson] = useState<string>("");
  const [verifyResult, setVerifyResult] = useState<any>(null);
  const [error, setError] = useState<string>("");

  async function refreshMe() {
    const res = await fetch("/api/session/me");
    const data = await res.json();
    setMe(data.user);
    if (data.user?.deviceKeys?.length) {
      setDeviceKeyId(data.user.deviceKeys[0].id);
    }
  }

  useEffect(() => {
    refreshMe().catch(() => {});
  }, []);

  async function onRegister() {
    setError("");
    try {
      await startPasskeyRegistration(userName);
      await refreshMe();
    } catch (e: any) {
      setError(e?.message ?? "Passkey registration failed. Try Dev Login on older Macs.");
    }
  }

  async function onDevLogin() {
    setError("");
    try {
      await devLogin(userName || "Dev User");
      await refreshMe();
    } catch (e: any) {
      setError(e?.message ?? "Dev login failed");
    }
  }

  async function onEnrollDeviceKey() {
    setError("");
    try {
      const id = await enrollDeviceKey("Primary device key");
      setDeviceKeyId(id);
      await refreshMe();
    } catch (e: any) {
      setError(e?.message ?? "Enroll failed");
    }
  }

  async function onComputeHash() {
    setError("");
    try {
      if (!file) return;
      const h = await sha256(file);
      setHashHex(h);
    } catch (e: any) {
      setError(e?.message ?? "Hash failed");
    }
  }

  function downloadText(filename: string, text: string) {
    const blob = new Blob([text], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  async function onSignProvenance() {
    setError("");
    try {
      if (!file || !hashHex || !deviceKeyId) return;

      const signatureB64 = await signHashHexWithDeviceKey(hashHex);

      const res = await fetch("/api/provenance/sign", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          deviceKeyId,
          fileName: file.name,
          mimeType: file.type || "application/octet-stream",
          sha256Hex: hashHex,
          signatureB64,
          metadata: {
            note: "MVP demo receipt. Verifies integrity since signing.",
            signedOn: new Date().toISOString(),
          },
        }),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "Sign failed");
      setRecordId(data.recordId);

      const receipt = {
        receipt_id: data.recordId,
        file_hash_sha256_hex: hashHex,
        signature_base64: signatureB64,
        device_key_id: deviceKeyId,
        signed_at_iso: new Date().toISOString(),
        file_name: file.name,
        mime_type: file.type || "application/octet-stream",
      };
      const receiptText = JSON.stringify(receipt, null, 2);
      setReceiptJson(receiptText);
      downloadText(`${file.name}.verifyme.receipt.json`, receiptText);
    } catch (e: any) {
      setError(e?.message ?? "Sign failed");
    }
  }

  async function onVerify() {
    setError("");
    try {
      if (!recordId) return;

      const res = await fetch("/api/provenance/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ recordId, sha256Hex: hashHex || undefined }),
      });
      const data = await res.json();
      setVerifyResult(data);
    } catch (e: any) {
      setError(e?.message ?? "Verify failed");
    }
  }

  return (
    <main style={{ maxWidth: 920, margin: "36px auto", fontFamily: "system-ui", padding: 16, lineHeight: 1.35 }}>
      <h1 style={{ marginBottom: 8 }}>Verify Me - Media Authenticity MVP</h1>
      <div style={{ opacity: 0.8 }}>
        Sign a photo or video hash with a device key, then verify later.  This proves integrity since signing and who signed it.
      </div>

      {error && (
        <div style={{ marginTop: 16, padding: 12, borderRadius: 12, background: "#fff3f3", border: "1px solid #ffd0d0" }}>
          {error}
        </div>
      )}

      <section style={{ padding: 16, border: "1px solid #ddd", borderRadius: 12, marginTop: 16 }}>
        <h2 style={{ marginTop: 0 }}>1) Identity</h2>
        <div>Session: {me ? `Signed in as ${me.label ?? me.id}` : "Not signed in"}</div>

        <div style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap", marginTop: 12 }}>
          <input
            value={userName}
            onChange={(e) => setUserName(e.target.value)}
            style={{ padding: 10, minWidth: 260 }}
            placeholder="Display name"
          />
          <button onClick={onRegister} style={{ padding: "10px 14px" }}>
            Create account + passkey
          </button>
          <button onClick={onDevLogin} style={{ padding: "10px 14px" }}>
            Dev login (if passkeys fail)
          </button>
        </div>

        <div style={{ marginTop: 10, opacity: 0.8 }}>
          On older macOS versions, passkeys may not work.  Dev login lets you test the rest of the system.
        </div>
      </section>

      <section style={{ padding: 16, border: "1px solid #ddd", borderRadius: 12, marginTop: 16 }}>
        <h2 style={{ marginTop: 0 }}>2) Device key (signing)</h2>
        <div>Device key id: {deviceKeyId ?? "None"}</div>
        <button onClick={onEnrollDeviceKey} style={{ padding: "10px 14px", marginTop: 10 }} disabled={!me}>
          Enroll device key
        </button>
        {!me && <div style={{ marginTop: 10, opacity: 0.8 }}>Sign in first.</div>}
      </section>

      <section style={{ padding: 16, border: "1px solid #ddd", borderRadius: 12, marginTop: 16 }}>
        <h2 style={{ marginTop: 0 }}>3) Sign media</h2>

        <input type="file" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />

        <div style={{ marginTop: 12, display: "flex", gap: 12, flexWrap: "wrap" }}>
          <button onClick={onComputeHash} style={{ padding: "10px 14px" }} disabled={!file}>
            Compute SHA 256
          </button>
          <button
            onClick={onSignProvenance}
            style={{ padding: "10px 14px" }}
            disabled={!me || !deviceKeyId || !file || !hashHex}
          >
            Sign + create receipt
          </button>
          <button onClick={onVerify} style={{ padding: "10px 14px" }} disabled={!recordId}>
            Verify record
          </button>
        </div>

        <div style={{ marginTop: 12 }}>
          <div>File: {file ? file.name : "None"}</div>
          <div>Hash: {hashHex ? hashHex.slice(0, 36) + "..." : "None"}</div>
          <div>Record id: {recordId || "None"}</div>
        </div>

        {receiptJson && (
          <div style={{ marginTop: 12 }}>
            <div style={{ opacity: 0.85 }}>Receipt preview:</div>
            <pre style={{ marginTop: 8, padding: 12, background: "#f7f7f7", borderRadius: 12, overflowX: "auto" }}>
{receiptJson}
            </pre>
          </div>
        )}

        {verifyResult && (
          <div style={{ marginTop: 12 }}>
            <div style={{ opacity: 0.85 }}>Verification result:</div>
            <pre style={{ marginTop: 8, padding: 12, background: "#f7f7f7", borderRadius: 12, overflowX: "auto" }}>
{JSON.stringify(verifyResult, null, 2)}
            </pre>
          </div>
        )}
      </section>

      <section style={{ padding: 16, border: "1px solid #ddd", borderRadius: 12, marginTop: 16 }}>
        <h2 style={{ marginTop: 0 }}>What this MVP guarantees</h2>
        <div>
          If verification says ok, the uploaded media matches the hash that was signed, and the signature verifies against the signer’s registered public key.
          That means the file has not changed since it was signed, and you know which identity signed it.
        </div>
      </section>
    </main>
  );
}
