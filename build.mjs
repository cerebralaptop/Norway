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
<link rel="icon" type="image/png" sizes="32x32" href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAK50lEQVR4AZyWCXhU1RXHf+/NkskySRqybxAICSgCQlH2RVBkEYKgUFREP/1aqyhiPwvUBUWqKC4ofoi0CIRNKbQskUVI2Al7CFsCYQkhZCPJhEyWmUkyPfclVCq1X+2dOe+9u51z7ln+5+put9v7/5LD4fA6nc7/ab/L5bpjnRrT+SXN27LY66W0rIzUVWtYsiyVmpoavDLWMnvH69a2n05omsYvUsBLM6uiklI2bf6e5555msmTnmCFKFJbW2so8Z8U0Whuau6npN8aqKioQEzSvPK/PAuvX2fLtu0MHzaUb5avFOHf8sTE8axYvQalxM9t1TQNTdPumNaRserqar59/SVS571vnOKOVS0nL7h2jR07M3hm0pOGsm63C1d9PRazhaefFEu0KHHrUIqP+r71LhO3qe/bSW9saGTlnFmYSguxHNlF2rp1dyih3Hv58hX27DvAU0/8pmW/RlxsrEFqwMfHh8lPPYlyR11dHZqm/Rufczk5rP3tRLZu2KCWG6RpGvrqhV9iyzlGj2ALrSxQsmohp06dMjbf0j4v7yKHjhwhZdRIlJtccnJfXxtBQYEEBQfhdNZQdfMmTd4mJk543AjOGokJWlp5eQV7575JnVirKPULThw/Ycwo/rp7x3rCfExkWCKpConG3NRA5sfvUllZaSw6l5NLVvYpxj82jj1797NRgm/7jgwWL1lGp7s60qZ1PH/fuMk4+aefLcDt9og7JpK6cpUREw2NDXw35y2oKGNMhC/WpkaOffI2VwuuGfx1u0nD2dBEUN8Hqeo2iB5BFkyOMtbOfYesk9kGjXs0hUvigtCwVvTr24eoiAgeHDzQYNDQ0ECP7t156MHBPDpmNNckSJ2Slsodi5csZfkn87DmZZPoa2aLKZxf+fvCzSq2zJ7OTbGa3jPISje7BeeuNEIObSdA1+keaMaam8XSzz+j8z2dDEFHjx2nuKiYE1lZXLx8maLiUg4cPMTRY1lymgJyz1/g9NmzXL1awMHMw6iY0Fz1NO3bSoIIz7P9itChKeR16MXAVj7oJQWsnv0ndN0eSFDPAYzv053BA/th7fsQrex24m0mooou4O/nZyjgdDpxOKpoampCZU2lpG1jYyM1tTVUiLtUMNdILCjXqTVqU1VWJiFmjUQ/M0meKkqzjhCZfxofXeP+YCs+F0+jHym8wdYtP3Bw2xZytmxg28aNpBdW0FoU8Bf3+LUoEBcXS1JSEhaLldjoaJKT2mP1sRIdGUkH+fb19SU6Sr6Tk7DZbEo+Znl2C7TSIPgV76Mx+vpxergr8TR5sZt0kn1N6A2DxhDzyiw8g1K4GhBO/LQ5tJ/+EU6PlxCLjq+fr7CB8vJKVDYEBtpxiO8uXrpCgH8ANwVDzkuW+Np8JBOqOX/hIkoZtSncorHVGsG+IZNZf89w3E2QZk9gv/TXte1HrI+OXlxcTO6FC6h3vaTJOcnXs0JeAZ960dxXTpMtWdCrZw8SEuJRboiJiiI6OspIw/DwMO7qkExYWCiRkRHyDpMUbuLatUJU8xF8sAmPgIAA4QgB9gDDin7+/kjWokfJpg5i2igxpRJ2d8eOKFKbvSaLBImOWIxrhYVERkRiFwY2wQCr1UyQWEP5vlaAR+W9n7jBbvdDxYbJZDIEKuHJSYkktGmDJkz9ZU2S9GPEjWpArz+4kwtLF1B/YCchznLO/WU+pxZ+hJ/4SJyMpml07XIPuefz2LVnL8pKp8+cMfo5Evkq7c7n5VFWVs6Zsznk5OYZWBAl8SDy0IoLyPpuBXmb1xqVz3Uph1PrVnF9z3Y0+elhbicRzhuEe5yEaI2EO8sIqy5D3IdutaHQSjEKDg6WIIsymAcGBhIjAho8DdgD7KigVJEfEOBPTEyUYQG1R9M0+kcHM8R5lRQ/N7a4NgwK8+chHIwOaES3B6GX9x6O5bnp3Og9jFy/UGzPz8T+0iyqJHQ1KTKapqGa2+U2Tq8U8gja1dW7UEI9Hjf1LpehqAIlZSGvONerNgmZI2LQW4WiSxyY4xOxtG6HOa6tUAKmoGD0iopKVJUrF7z2uDxcvVZggImmPCgKCA/jX15eTpEAUaNAqcr7opISPIKClYINatztduOodMiaEsNKHukX1rjIzsyk/uJ5Gq5cpHjvDjLSM0iXcp6esYuyK1fQVeR2kNyNjorG5utDh+RkOnbsYAj1aDrlAjhK4GPjxgjUjqJXz/sYNyaFsSmjBJZ7M2b0SKNI9evTi9GjRsj3CHFDNENHjGbN2QKmnKvgoMNl8MurbeCR1O95/G/pPLp6O7nS12sO7+Zc6iKch9IJqq4gZ8VXZC/5HJuu4xSzn8w+LdB6iG3bd0gQ7mNz2lZ2ivbpu/aQnrGbo2kb2L97D//YlMbhYyc4feYcL778KqUlZSjv2XQTXQWMLomwCzUeqapHDYsbGkmd1/WqG9hvXMVcVUFlbR0BJVfxK84np9ZDYHAwDwzsT/du9xIeHk77xLaEh4YSJGXYYjbT6e676dM+jgcG9DOwoGvnTgLdvjirncqB6JqX7nfdZFNkDpdGTGbColW0aRMv2XKODZvTQMJLHxBsY0CwL0MGD2TIoAEMiGlF/2Af7g2woOJjwcKv+WFHOjVOJ5cv5xv3gbq6elTblJbGjtI6du4/yLYfdvLBhx8z7fXpiPEY1quSb2bn8eaUfManlKHV5xAfH0dC69YoLHGcOoqqxPrJKhf7y+vYczKX3cdPcaC4iuxqj+JPmJz613L6hIQ2tGuXIBZoR2KiULu20m8r/UTGqngQio+PxSWBpzU6eF+Evjy5iLDQRuGjUVFu4kz2TlauWMbqFd9wKeckfiF2ijp2R3f0f4SCgWO50rEn+V0GkN/nEcr7jkT5T5OjqFuOugFFyB1AlWZFXTt3llPqiAV5f+481q5bz/ETWfS9vwNzp+bRpZMTtEZu3NDYlN6bkoZF/Hn2t0wa9zBPjRvGsxPH8PTzk3luxmvoJpOJ1anLOb5uNcuWLuevS5dhMpsMH4KOJDjXCwrY8PrvUTmOtMNHJJBkTOV6cnJ7Ro0cQbUUKB/HO8RGivVk4vDxEC475jBl6gpGPjxECpTNUJiWJ9K8Xk1JgBirzqzEQELkrRkLdIymiXz5cEnFi613oK7jGRLxp+fOgBP7ZEb+IgwxV40EsCX+a9bve5bvd7YmsesyJjw2HpMcUFbJX5hxOzUP6Wp/gauJjAoXZapeqkUt64Sv6uEnSHbMHsd3a9cz79P5uCJiKXKpnUhNuMARuS29/cZMwYkUprz2GebQKfTo1lkk3P5vXt98JPXtFd5esYDXi6vJy/z8ahngX6R84BUNZBqzIGLS0FGkCPhMkvt/8IDhRNzXB1UTkgXE8q/kEx8Xy/wvvkRVRv/AEH6+qdM1zyreel5pOWM7J/FCj7v4XY+OTOjanoty39thDuNKbaOc7pgwrcUk1yjRB10eyqwuASl1/crJPc91gejMQ0dYuGgxmYcOo+kSQ95mIXc+b02IIpqG/tZ77/HeijWMeecDRs58l7eWr2HGrFkkTnqBGXPnMnXKi9zbpQuJ7RJpL5TYTqVhMyXLPWLmH/+Aqu1DBg9i8VdfMnjQQLxSLzRNBHB7+2kfsbaGnn3iOKnTX2Hbgo+5tDcdVdG2r1/H2eVfYbVa8YqdDr3xEp4Ppwq9SsNH0+Q9zXgffHMKJaWlZGYeRGWGurKbBSGbPHU0+xrkw/grPj+O/ajMPwEAAP//X6Lz/AAAAAZJREFUAwCX920jVEqzvgAAAABJRU5ErkJggg==">
<link rel="icon" type="image/png" sizes="16x16" href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAADM0lEQVR4AWSTX2hbVRzHP/ckN2lzs/YujatrtdnWTaydrE7bqQylCA7xTV982PBJ0PrnVYRu6Nhg+iIIvggDmb6IIFMUYa7zHxu+bA/isiZN2qSmS5Mmt2mT3Nx7c5PryZWK4oHfvb/z4/v7nt/5/n5HOI7j/c9sGbNtbzGV8pYyWc+W/g7Glvidfe8vPM9DOvx7eXikM1lKpQ2K60Xyq6v0cD2M0vtI29mL1fQil149RaVclmF8YHopw65olLbbJqSGEEL8Q9JLTF7/BaNS8fHi1wuniXUtrn3wLrJMFlNp2u02G9UKqqridjosr+RwXdcnyd1J8vtH51i4MI9l2YiEZWAkJkkUU3x27gzhcJhKtcrW1rZfjWVZBINBGTO4W1jj+vvzdEcPoNYqfP/heURQH2LGNXAGhtBv/0Z8KEattkWlUqUqzTAMqpKwWjVorxc40qmTaJQ50DUZ/uMGIjP1DLcclfKJk2hCodPtEtU0IpGIb6FQmN26TiAQQHVtbh6eZTt+HzcnZ6mPjCNCpQLRVh0ln0HW6gMdKR6yE4oA27GlJi5dSQwKg7TR6KJ7DhE8RNhuEu44qM0aItTnn261bEyzRbNhyhSFeqNB1+v6+hwzixyKBHhCXvtgn4Jo7pvA2BXHnZzGFQFaUjRdH2B4eA8xqYeuDzK85x76+/r58qcbfHsryUYqSWlskryIIJyFy4Rzd9j84hNMTyGXz9M0TdbW7mIYm+ht0ye98sNVvln4mVVti/zh47gTR2nFRxAPehb7xw/ykGIzEAyQTmfQ+iMMxWKyzxbq3jGuXvuRTPIyH8+v8PKcnJP9ccz6JsViAXFl3zQXizbfjU4RkjOgRfpJ6BqPHX2EaFQjl8sTUZY5/9YSSuB+rNDnvPj8C8zOTHDq9DuI2kYZ/c9F1uXcS8WwWi2+vvQpF8/Os728JElDHJl5idvrZ5h+6iumpo7LTsn29MAKCEX2t6hGGQgHKXoqjZbFyJOz7H38acKjY2SzKxTkBA4OH5PvQ+M/y5MEc6/P8dqbb/D2e2d5+OQrPDp2L+OljLQsuhT3gUPjPHfiWeKx3SjK3+nyAfuOoij8BQAA///dscnAAAAABklEQVQDAJfXpn5R09aSAAAAAElFTkSuQmCC">
<link rel="apple-touch-icon" sizes="180x180" href="apple-touch-icon.png">
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
