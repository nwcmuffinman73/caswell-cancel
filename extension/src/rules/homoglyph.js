// Brand impersonation in the hostname: typosquats (paypa1.com), confusables (pаypal.com with a
// Cyrillic а), punycode, and brand-as-subdomain (paypal.com.secure-login.tld). This is the small
// search-flavoured corner of the project: edit distance against a brand list.

export const BRANDS = ["paypal","google","gmail","youtube","microsoft","office365","outlook","live","hotmail",
  "apple","icloud","amazon","facebook","instagram","whatsapp","meta","netflix","linkedin","twitter","dropbox",
  "docusign","adobe","chase","wellsfargo","bankofamerica","citibank","capitalone","americanexpress","usps",
  "fedex","ups","dhl","irs","coinbase","binance","metamask","steam","roblox","epicgames","ebay","walmart",
  "costco","spotify","zoom","okta","github","att","verizon","tmobile","comcast","xfinity","spectrum"];

// Minimal confusable folding. Full UTS#39 tables come later; this covers the common kit tricks.
const CONFUSABLES = { "0":"o","1":"l","3":"e","4":"a","5":"s","7":"t","@":"a","$":"s","|":"l",
  "а":"a","е":"e","о":"o","р":"p","с":"c","х":"x","у":"y","і":"i","ј":"j","ѕ":"s","һ":"h","ԁ":"d","ɑ":"a","ο":"o","ν":"v" };

export function fold(label) {
  let s = label.normalize("NFKC").toLowerCase();
  s = s.replace(/rn/g, "m").replace(/vv/g, "w").replace(/cl/g, "d");
  return [...s].map((ch) => CONFUSABLES[ch] ?? ch).join("");
}

export function levenshtein(a, b) {
  if (a === b) return 0;
  const m = a.length, n = b.length;
  if (!m) return n; if (!n) return m;
  let prev = Array.from({ length: n + 1 }, (_, j) => j), cur = new Array(n + 1);
  for (let i = 1; i <= m; i++) {
    cur[0] = i;
    for (let j = 1; j <= n; j++) cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    [prev, cur] = [cur, prev];
  }
  return prev[n];
}

// Good-enough registrable-domain split for the skeleton. Replace with a real PSL table later.
const TWO_LEVEL = new Set(["co.uk","org.uk","ac.uk","gov.uk","com.au","net.au","org.au","co.jp","co.nz","co.za","com.br","com.mx","com.ar","co.in","com.sg","com.hk","com.tr","com.cn","com.tw"]);
export function splitHost(hostname) {
  const labels = hostname.toLowerCase().split(".").filter(Boolean);
  if (labels.length < 2) return { sub: [], domain: labels[0] || "", suffix: "" };
  const last2 = labels.slice(-2).join(".");
  const n = TWO_LEVEL.has(last2) ? 3 : 2;
  return { sub: labels.slice(0, -n), domain: labels[labels.length - n] || "", suffix: labels.slice(-n + 1).join(".") };
}

/** @returns {{score:number, reasons:string[]}} */
export function assessHostname(hostname) {
  const reasons = [];
  let score = 0;
  if (!hostname) return { score, reasons };
  const { sub, domain } = splitHost(hostname);
  const folded = fold(domain);
  const exact = BRANDS.includes(domain);

  if (hostname.split(".").some((l) => l.startsWith("xn--"))) { score += 0.3; reasons.push("punycode label"); }
  if (!exact) {
    for (const b of BRANDS) {
      if (folded === b) { score += 0.7; reasons.push(`'${domain}' folds to brand '${b}' (confusables)`); break; }
      const d = levenshtein(folded, b);
      const tol = b.length >= 8 ? 2 : 1;
      if (d <= tol && d > 0) { score += 0.5; reasons.push(`'${domain}' is ${d} edit(s) from '${b}'`); break; }
      if (domain.includes(b) && domain !== b && domain.length <= b.length + 10) { score += 0.3; reasons.push(`brand '${b}' embedded in '${domain}'`); break; }
    }
    for (const l of sub) {
      const fl = fold(l);
      if (BRANDS.includes(fl)) { score += 0.45; reasons.push(`brand '${fl}' as subdomain of '${domain}'`); break; }
    }
  }
  if (sub.length >= 4) { score += 0.1; reasons.push(`${sub.length} subdomain levels`); }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) { score += 0.3; reasons.push("raw IP address"); }
  return { score: Math.min(1, score), reasons };
}
