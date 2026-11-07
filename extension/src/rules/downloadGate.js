// Download gate: the CaswellCancel (2020) foundation, grown up.
// The 2020 version cancelled on MIME octet-stream/zip or >500MB. That is a blunt instrument;
// here each signal contributes to a 0..1 risk and the policy layer decides.
//
// What the extension CAN see on a download: filename, declared MIME, finalUrl, referrer, size,
// Content-Disposition (via headers, not exposed on DownloadItem). It can NOT read file bytes, so
// magic-byte checks live in the corpus (to learn which ext/MIME pairs are malware) and in a future
// native-messaging companion, not here.

const EXECUTABLE = new Set(["exe","msi","scr","com","pif","bat","cmd","ps1","psm1","vbs","vbe","js","jse",
  "wsf","wsh","hta","jar","reg","lnk","cpl","msc","msp","mst","sct","inf","dll","sys","drv","ocx",
  "dmg","pkg","app","command","sh","run","elf","apk","deb","rpm","appimage"]);
const DISK_IMAGE = new Set(["iso","img","vhd","vhdx","udf"]);
const ARCHIVE = new Set(["zip","rar","7z","tar","gz","bz2","xz","zst","cab","arj","lzh","ace"]);
const OFFICE_MACRO = new Set(["docm","xlsm","pptm","dotm","xltm","potm","xlam","ppam","sldm"]);
const DOCUMENT_LIKE = new Set(["pdf","doc","docx","xls","xlsx","ppt","pptx","txt","rtf","odt","csv",
  "jpg","jpeg","png","gif","webp","svg","mp3","mp4","mov","avi","html","htm"]);

// Declared MIME → extensions we expect to see with it.
const MIME_EXPECTS = {
  "application/pdf": ["pdf"],
  "image/jpeg": ["jpg","jpeg"], "image/png": ["png"], "image/gif": ["gif"], "image/webp": ["webp"],
  "text/plain": ["txt","log","csv","md"], "text/html": ["html","htm"],
  "application/zip": ["zip"], "application/x-rar-compressed": ["rar"], "application/x-7z-compressed": ["7z"],
  "application/msword": ["doc"], "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ["docx"],
  "application/vnd.ms-excel": ["xls"], "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ["xlsx"],
  "audio/mpeg": ["mp3"], "video/mp4": ["mp4"],
};

export function extensionsOf(filename) {
  const base = (filename || "").split(/[\\/]/).pop().toLowerCase();
  const parts = base.split(".").slice(1).filter(Boolean);
  return parts; // ["pdf","exe"] for invoice.pdf.exe
}

export function registrableHost(u) {
  try { return new URL(u).hostname.replace(/^www\./, ""); } catch { return ""; }
}

/** @returns {{score:number, reasons:string[]}} */
export function assessDownload(item, ctx = {}) {
  const reasons = [];
  let score = 0;
  const exts = extensionsOf(item.filename || item.finalUrl || item.url);
  const last = exts[exts.length - 1] || "";
  const mime = (item.mime || "").toLowerCase().split(";")[0].trim();

  if (EXECUTABLE.has(last)) { score += 0.25; reasons.push(`executable type .${last}`); }
  else if (OFFICE_MACRO.has(last)) { score += 0.4; reasons.push(`macro-enabled Office file .${last}`); }
  else if (DISK_IMAGE.has(last)) { score += 0.35; reasons.push(`disk image .${last}`); }
  else if (ARCHIVE.has(last)) { score += 0.15; reasons.push(`archive .${last}`); }

  // invoice.pdf.exe — the document-looking name is the attack.
  if (exts.length >= 2 && DOCUMENT_LIKE.has(exts[exts.length - 2]) && (EXECUTABLE.has(last) || DISK_IMAGE.has(last))) {
    score += 0.35; reasons.push(`double extension .${exts[exts.length - 2]}.${last}`);
  }

  // Declared MIME disagrees with the filename (image/jpeg → .exe, text/html → .scr …).
  const expected = MIME_EXPECTS[mime];
  if (expected && last && !expected.includes(last)) {
    score += (EXECUTABLE.has(last) || DISK_IMAGE.has(last)) ? 0.35 : 0.1;
    reasons.push(`MIME ${mime} vs .${last}`);
  }
  // octet-stream is what malware CDNs say about everything; mild by itself.
  if (mime === "application/octet-stream" && (EXECUTABLE.has(last) || ARCHIVE.has(last))) {
    score += 0.1; reasons.push("generic octet-stream");
  }

  // Download host differs from the page that triggered it (third-party payload).
  const dlHost = registrableHost(item.finalUrl || item.url);
  const refHost = registrableHost(item.referrer);
  if (dlHost && refHost && dlHost !== refHost && !dlHost.endsWith("." + refHost) && !refHost.endsWith("." + dlHost)) {
    score += (EXECUTABLE.has(last) || DISK_IMAGE.has(last)) ? 0.2 : 0.05;
    reasons.push(`served from ${dlHost}, page on ${refHost}`);
  }
  if (!item.referrer && (EXECUTABLE.has(last) || DISK_IMAGE.has(last))) {
    score += 0.1; reasons.push("no referrer (direct/forced link)");
  }

  // Legacy 2020 rule, kept at low weight.
  if ((item.totalBytes || 0) > 500 * 1024 * 1024) { score += 0.05; reasons.push(">500MB"); }

  // Browser's own verdict, when it has one (Chrome 'danger' field).
  if (item.danger && item.danger !== "safe" && item.danger !== "accepted") {
    score += 0.4; reasons.push(`browser flags: ${item.danger}`);
  }

  // Drive-by context supplied by the caller.
  if (ctx.msSinceNavigation != null && ctx.msSinceNavigation < 1500) {
    score += 0.25; reasons.push(`started ${ctx.msSinceNavigation}ms after page load (auto-download)`);
  }
  return { score: Math.min(1, score), reasons };
}
