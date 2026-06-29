#!/usr/bin/env node
/*
 * build.mjs — wrap the itinerary in a client-side password gate.
 *
 * The whole site is encrypted with AES-256-GCM using a key derived from the
 * password via PBKDF2 (SHA-256, 250k iterations). The published index.html
 * contains only ciphertext + a small unlock screen; without the password the
 * source reveals nothing. Decryption happens entirely in the browser.
 *
 * Usage (password comes from the SITE_PASSWORD env var, never committed):
 *   SITE_PASSWORD=... node build.mjs encrypt itinerary.plain.html index.html
 *   SITE_PASSWORD=... node build.mjs decrypt index.html itinerary.plain.html
 *
 * Edit workflow: decrypt -> edit the plaintext -> encrypt again.
 */
import { readFileSync, writeFileSync } from "node:fs";
import crypto from "node:crypto";

const ITER = 250000;
const [, , mode, inPath, outPath] = process.argv;
const pw = process.env.SITE_PASSWORD;

if (!mode || !inPath || !outPath) {
  console.error("usage: node build.mjs <encrypt|decrypt> <in> <out>");
  process.exit(1);
}
if (!pw) {
  console.error("error: set SITE_PASSWORD env var");
  process.exit(1);
}

const MARK = "<!--NV-PAYLOAD:"; // marks an encrypted file so decrypt can find the blob

function deriveKey(password, salt) {
  return crypto.pbkdf2Sync(password, salt, ITER, 32, "sha256");
}

function gatePage(salt, iv, ct) {
  const SALT = salt.toString("base64");
  const IV = iv.toString("base64");
  const CT = ct.toString("base64");
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#111828">
<meta name="robots" content="noindex, nofollow">
<title>Bergen &amp; the Fjords</title>
<style>
  :root{color-scheme:dark}
  *{box-sizing:border-box}
  html,body{margin:0;height:100%}
  body{min-height:100%;background:#111828;color:#fff;display:grid;place-items:center;
    font-family:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;padding:24px}
  .gate{width:100%;max-width:360px;text-align:center}
  .drop{width:26px;height:32px;fill:rgba(255,255,255,.85);margin:0 auto 20px;display:block}
  h1{font-size:1.05rem;font-weight:600;letter-spacing:.4px;margin:0 0 6px}
  p{font-size:.85rem;line-height:1.5;color:rgba(255,255,255,.6);margin:0 0 22px}
  form{display:flex;flex-direction:column;gap:12px}
  input[type=password]{appearance:none;width:100%;font:inherit;font-size:1rem;color:#fff;
    background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.18);border-radius:12px;padding:13px 15px;outline:none}
  input[type=password]:focus{border-color:rgba(255,255,255,.5);background:rgba(255,255,255,.10)}
  button{appearance:none;font:inherit;font-weight:600;font-size:1rem;color:#111828;background:#fff;
    border:0;border-radius:12px;padding:13px 15px;cursor:pointer}
  button:disabled{opacity:.6;cursor:default}
  .remember{display:flex;align-items:center;justify-content:center;gap:8px;font-size:.8rem;color:rgba(255,255,255,.6)}
  .remember input{width:16px;height:16px;accent-color:#fff}
  .err{min-height:18px;font-size:.8rem;color:#FCA5A5;margin-top:2px}
  @media (prefers-reduced-motion:no-preference){.shake{animation:sh .35s}}
  @keyframes sh{10%,90%{transform:translateX(-2px)}30%,70%{transform:translateX(4px)}50%{transform:translateX(-6px)}}
</style>
</head>
<body>
  <div class="gate">
    <svg class="drop" viewBox="0 0 24 28"><path d="M12 0C12 0 2 12 2 19a10 10 0 0 0 20 0C22 12 12 0 12 0z"/></svg>
    <h1>Bergen &amp; the Fjords</h1>
    <p>This itinerary is private. Enter the password to continue.</p>
    <form id="f">
      <input id="pw" type="password" placeholder="Password" autocomplete="current-password" autofocus>
      <label class="remember"><input id="rm" type="checkbox"> Remember on this device</label>
      <button id="go" type="submit">Unlock</button>
      <div class="err" id="err" role="alert"></div>
    </form>
  </div>
<script>
"use strict";
var SALT="${SALT}",IV="${IV}",CT="${CT}",ITER=${ITER},STORE="nv-pw";
var b64=function(s){return Uint8Array.from(atob(s),function(c){return c.charCodeAt(0)});};
async function unlock(pw){
  var enc=new TextEncoder();
  var base=await crypto.subtle.importKey("raw",enc.encode(pw),"PBKDF2",false,["deriveKey"]);
  var key=await crypto.subtle.deriveKey({name:"PBKDF2",salt:b64(SALT),iterations:ITER,hash:"SHA-256"},
    base,{name:"AES-GCM",length:256},false,["decrypt"]);
  var pt=await crypto.subtle.decrypt({name:"AES-GCM",iv:b64(IV)},key,b64(CT));
  return new TextDecoder().decode(pt);
}
function render(html){document.open();document.write(html);document.close();}
var f=document.getElementById("f"),pwEl=document.getElementById("pw"),
    errEl=document.getElementById("err"),go=document.getElementById("go"),rm=document.getElementById("rm");
function fail(msg){errEl.textContent=msg;f.classList.remove("shake");void f.offsetWidth;f.classList.add("shake");
  go.disabled=false;go.textContent="Unlock";pwEl.select();}
async function attempt(pw,remember){
  go.disabled=true;go.textContent="Unlocking…";errEl.textContent="";
  var html;
  try{html=await unlock(pw);}catch(e){
    try{localStorage.removeItem(STORE);}catch(_){}
    return fail("Incorrect password. Try again.");}
  if(remember){try{localStorage.setItem(STORE,pw);}catch(_){}}
  render(html);
}
f.addEventListener("submit",function(e){e.preventDefault();
  var pw=pwEl.value;if(!pw)return;attempt(pw,rm.checked);});
// auto-unlock if remembered on this device
(function(){var saved=null;try{saved=localStorage.getItem(STORE);}catch(_){}
  if(saved){rm.checked=true;attempt(saved,true);}})();
</script>
${MARK}${SALT}:${IV}:${CT}-->
</body>
</html>
`;
}

if (mode === "encrypt") {
  const plain = readFileSync(inPath, "utf8");
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = deriveKey(pw, salt);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(plain, "utf8"), cipher.final(), cipher.getAuthTag()]);
  writeFileSync(outPath, gatePage(salt, iv, ct));
  console.log(`encrypted ${plain.length} bytes -> ${outPath}`);
} else if (mode === "decrypt") {
  const gate = readFileSync(inPath, "utf8");
  const i = gate.lastIndexOf(MARK);
  if (i < 0) { console.error("no payload marker found in " + inPath); process.exit(1); }
  const blob = gate.slice(i + MARK.length, gate.indexOf("-->", i)).trim();
  const [s, v, c] = blob.split(":");
  const salt = Buffer.from(s, "base64"), iv = Buffer.from(v, "base64"), full = Buffer.from(c, "base64");
  const key = deriveKey(pw, salt);
  const tag = full.subarray(full.length - 16), ct = full.subarray(0, full.length - 16);
  const d = crypto.createDecipheriv("aes-256-gcm", key, iv);
  d.setAuthTag(tag);
  let pt;
  try { pt = Buffer.concat([d.update(ct), d.final()]).toString("utf8"); }
  catch (e) { console.error("decrypt failed — wrong password?"); process.exit(1); }
  writeFileSync(outPath, pt);
  console.log(`decrypted -> ${outPath}`);
} else {
  console.error("unknown mode: " + mode);
  process.exit(1);
}
