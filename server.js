// AUTSYS Central Relay
// Transport-only relay between AUTSYS Manager installations and AUTSYS Centrale.
// No licensing logic. No authoritative database. No private licensing keys.
//
// v0.3.0 adds an EPHEMERAL package transport cache. AUTSYS Centrale remains
// authoritative for releases. The relay only transports a verified copy long
// enough for a Manager to download it through an opaque, expiring ticket.

import crypto from "crypto";
import fs from "fs";
import os from "os";
import path from "path";
import express from "express";

const app = express();
const port = Number(process.env.PORT || 10010);
const VERSION = "0.3.0";
const PROTOCOL = 2; // backward-compatible with Manager Android 1.0.0.17

const CENTRAL_KEY = String(process.env.AUTSYS_CENTRAL_RELAY_KEY || "");
const MANAGER_TOKEN_KEY = String(process.env.AUTSYS_MANAGER_TOKEN_KEY || "");
const STRIPE_AUTSYS_FULL_KEY = String(process.env.STRIPE_AUTSYS_FULL_KEY || "");

const MAX_EVENTS = 5000;
const MAX_COMMANDS_PER_INSTALLATION = 500;
const MAX_BODY = "256kb";
const MAX_BATCH = 100;
const DEFAULT_EVENT_TTL_SEC = 24 * 60 * 60;
const DEFAULT_COMMAND_TTL_SEC = 24 * 60 * 60;
const MANAGER_TOKEN_TTL_SEC = 7 * 24 * 60 * 60;
const DEFAULT_PACKAGE_TTL_SEC = 24 * 60 * 60;
const MAX_PACKAGE_TTL_SEC = 7 * 24 * 60 * 60;
const MAX_PACKAGE_BYTES = Math.max(1, Number(process.env.AUTSYS_RELAY_MAX_PACKAGE_BYTES || 2147483648));
const PACKAGE_ROOT = path.resolve(String(process.env.AUTSYS_RELAY_PACKAGE_ROOT || path.join(os.tmpdir(), "autsys-relay-packages")));

app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(express.json({ limit: MAX_BODY }));
app.use(express.urlencoded({ extended: false, limit: "32kb" }));

app.use((req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-AUTSYS-Relay-Version", VERSION);
  res.setHeader("X-AUTSYS-Protocol", String(PROTOCOL));
  next();
});

const nowSec = () => Math.floor(Date.now() / 1000);
const isSafeId = (v) => typeof v === "string" && /^[A-Za-z0-9._:-]{1,128}$/.test(v);
const isUuid = (v) => typeof v === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(v);
const isBindingSecret = (v) => typeof v === "string" && /^[A-Za-z0-9_-]{32,128}$/.test(v);
const isSha256 = (v) => typeof v === "string" && /^[0-9a-f]{64}$/i.test(v);
const asObject = (v) => (v && typeof v === "object" && !Array.isArray(v) ? v : null);

async function stripePost(endpoint, fields) {
  if (!STRIPE_AUTSYS_FULL_KEY) throw new Error("stripe_not_configured");
  const body = new URLSearchParams();
  for (const [k, v] of Object.entries(fields)) {
    if (v !== undefined && v !== null && v !== "") body.append(k, String(v));
  }
  const response = await fetch("https://api.stripe.com" + endpoint, {
    method: "POST",
    headers: {
      "Authorization": "Bearer " + STRIPE_AUTSYS_FULL_KEY,
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body
  });
  const json = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = json?.error?.message || ("Stripe HTTP " + response.status);
    const err = new Error(message);
    err.status = response.status;
    err.stripe = json?.error || null;
    throw err;
  }
  return json;
}

function safeEqualText(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function b64urlDecodeText(v) {
  return Buffer.from(v, "base64url").toString("utf8");
}

function sha256Text(v) {
  return crypto.createHash("sha256").update(String(v)).digest("base64url");
}

function signManagerToken(payload) {
  if (!MANAGER_TOKEN_KEY) return "";
  const payload64 = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const signature64 = crypto.createHmac("sha256", MANAGER_TOKEN_KEY).update(payload64).digest("base64url");
  return `${payload64}.${signature64}`;
}

function verifyManagerToken(token) {
  if (!MANAGER_TOKEN_KEY || typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [payload64, signature64] = parts;
  if (!payload64 || !signature64) return null;
  const expected = crypto.createHmac("sha256", MANAGER_TOKEN_KEY).update(payload64).digest("base64url");
  if (!safeEqualText(expected, signature64)) return null;
  try {
    const payload = JSON.parse(b64urlDecodeText(payload64));
    if (!payload || payload.purpose !== "manager-relay") return null;
    if (!isSafeId(payload.installation_id)) return null;
    if (!Number.isInteger(payload.exp) || payload.exp <= nowSec()) return null;
    return payload;
  } catch {
    return null;
  }
}

function bearer(req) {
  const h = String(req.get("authorization") || "");
  return h.startsWith("Bearer ") ? h.slice(7).trim() : "";
}

function requireCentral(req, res, next) {
  if (!CENTRAL_KEY) return res.status(503).json({ ok: false, error: "relay_not_configured" });
  const token = bearer(req);
  if (!token || !safeEqualText(token, CENTRAL_KEY)) return res.status(401).json({ ok: false, error: "unauthorized" });
  next();
}

function requireManager(req, res, next) {
  const payload = verifyManagerToken(bearer(req));
  if (!payload) return res.status(401).json({ ok: false, error: "unauthorized" });
  if (payload.binding_sha256) {
    const binding = String(req.get("x-autsys-binding") || "").trim();
    if (!isBindingSecret(binding) || !safeEqualText(sha256Text(binding), payload.binding_sha256)) {
      return res.status(401).json({ ok: false, error: "invalid_binding" });
    }
  }
  req.autsysManager = payload;
  next();
}

const rateBuckets = new Map();
app.use((req, res, next) => {
  const ip = String(req.ip || req.socket.remoteAddress || "unknown");
  const now = Date.now();
  let b = rateBuckets.get(ip);
  if (!b || now - b.startedAt >= 60_000) {
    b = { startedAt: now, count: 0 };
    rateBuckets.set(ip, b);
  }
  b.count += 1;
  if (b.count > 240) return res.status(429).json({ ok: false, error: "rate_limited" });
  next();
});

const bootstrapBuckets = new Map();
function allowBootstrap(req) {
  const ip = String(req.ip || req.socket.remoteAddress || "unknown");
  const now = Date.now();
  let b = bootstrapBuckets.get(ip);
  if (!b || now - b.startedAt >= 10 * 60_000) {
    b = { startedAt: now, count: 0 };
    bootstrapBuckets.set(ip, b);
  }
  b.count += 1;
  return b.count <= 20;
}

const events = [];
const eventIds = new Set();
const commandsByInstallation = new Map();
const commandIds = new Set();
const packagesByRelease = new Map();
const packageTickets = new Map();

function safeFilename(v) {
  const raw = String(v || "package.zip").trim();
  const base = path.basename(raw).replace(/[^A-Za-z0-9._-]/g, "_");
  return base || "package.zip";
}

function publicBase(req) {
  return `${req.protocol}://${req.get("host")}`.replace(/\/$/, "");
}

function packagePath(releaseId) {
  return path.join(PACKAGE_ROOT, `${releaseId}.zip`);
}

function purgeExpired() {
  const now = nowSec();
  for (let i = events.length - 1; i >= 0; i -= 1) {
    if (events[i].expires_at <= now) {
      eventIds.delete(events[i].event_id);
      events.splice(i, 1);
    }
  }
  for (const [installationId, list] of commandsByInstallation.entries()) {
    const kept = list.filter((x) => x.expires_at > now);
    for (const x of list) if (x.expires_at <= now) commandIds.delete(x.command_id);
    if (kept.length === 0) commandsByInstallation.delete(installationId);
    else commandsByInstallation.set(installationId, kept);
  }
  for (const [ticket, item] of packageTickets.entries()) {
    if (item.expires_at <= now) packageTickets.delete(ticket);
  }
  for (const [releaseId, item] of packagesByRelease.entries()) {
    if (item.expires_at <= now) {
      packagesByRelease.delete(releaseId);
      try { fs.unlinkSync(item.path); } catch {}
    }
  }
}

setInterval(purgeExpired, 60_000).unref();
try { fs.mkdirSync(PACKAGE_ROOT, { recursive: true }); } catch {}

app.get("/", (req, res) => {
  res.json({ ok: true, service: "autsys-central-relay", version: VERSION, protocol: PROTOCOL });
});

app.get("/health", (req, res) => {
  res.json({ ok: true, service: "autsys-central-relay", version: VERSION, protocol: PROTOCOL, ts: nowSec() });
});

// Public legal document endpoint used by Stripe Checkout until the AUTSYS website
// exposes the canonical legal-document area. Content mirrors AUTSYS SRLS AI 2026/001 REV.0.
app.get("/legal/autsys-srls/2026-001", (req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Cache-Control", "public, max-age=300");
  res.send(`<!doctype html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>2026/001 - Condizioni contrattuali AUTSYS S.R.L.S. / EOLO</title>
<style>
body{font-family:Arial,Helvetica,sans-serif;max-width:900px;margin:40px auto;padding:0 24px;line-height:1.55;color:#111}
h1{font-size:24px}h2{font-size:18px;margin-top:28px}.meta{font-size:14px;color:#444}.parties{margin:24px 0}
hr{margin:28px 0}.hash{font-family:monospace;font-size:12px;word-break:break-all}
@media print{body{max-width:none;margin:0}.noprint{display:none}}
</style>
</head>
<body>
<h1>CONDIZIONI CONTRATTUALI DEL SERVIZIO IN ABBONAMENTO</h1>
<p><strong>Collaborazione tecnica continuativa AUTSYS S.R.L.S. per TERMOMECCANICA EOLO</strong></p>
<p class="meta">Documento: 2026/001 - AUTSYS SRLS AI - 24/09/2026 &nbsp;|&nbsp; Revisione: REV.0</p>
<p class="meta">SHA-256 documento ufficiale: <span class="hash">a263d98e2e19d94c0f380f9fa5ec96107df084a80715fd3f66c41ceb873dee93</span></p>
<div class="parties">
<p>Tra</p>
<p><strong>AUTSYS S.R.L.S.</strong>, con sede in Genova (GE), Via Camilla 3/6, C.F. e P. IVA 02847140999, REA GE-515278, di seguito “AUTSYS” o “Fornitore”;</p>
<p>e</p>
<p><strong>TERMOMECCANICA “EOLO” DI AUTELLI ING. FRANCESCO</strong>, di seguito “EOLO” o “Cliente”;</p>
<p>congiuntamente, le “Parti”.</p>
</div>
<h2>1. Oggetto del servizio</h2>
<p>AUTSYS fornisce a EOLO un servizio continuativo di collaborazione tecnica e informatica in abbonamento, finalizzato al supporto, alla gestione, alla manutenzione e all’evoluzione dei sistemi software, informatici e digitali utilizzati dal Cliente.</p>
<p>Il servizio può comprendere, secondo le necessità operative concordate tra le Parti: assistenza tecnica e informatica; analisi e risoluzione di problematiche software e infrastrutturali; sviluppo, modifica e manutenzione di software e automazioni; supporto a database e sistemi informativi; integrazione tra applicazioni; analisi, ottimizzazione e miglioramento dei processi digitali; interventi tecnici sui sistemi e sui progetti gestiti da AUTSYS per conto di EOLO.</p>
<p>L’abbonamento costituisce un rapporto continuativo di collaborazione tecnica. Salvo diverso accordo scritto, non attribuisce un monte ore minimo garantito né un numero predeterminato di interventi mensili.</p>
<h2>2. Attività escluse o straordinarie</h2>
<p>Non sono comprese automaticamente nell’abbonamento le attività che, per natura, dimensione, costo o impegno richiesto, costituiscano una fornitura o un progetto autonomo o straordinario. Rientrano, a titolo esemplificativo, la fornitura di hardware, l’acquisto di licenze o servizi di terzi, le trasferte e relative spese, nonché sviluppi o progetti di rilevanza tale da richiedere un distinto accordo economico.</p>
<p>Prima dell’avvio di attività straordinarie con costi aggiuntivi, AUTSYS ne informa EOLO e ne concorda le condizioni.</p>
<h2>3. Corrispettivo</h2>
<p>Il corrispettivo dell’abbonamento è pari a <strong>€ 250,00 + IVA.</strong></p>
<p>Il pagamento avviene tramite il sistema elettronico messo a disposizione da AUTSYS. Con la sottoscrizione, il Cliente autorizza l’addebito ricorrente sul metodo di pagamento indicato, secondo la periodicità mensile prevista.</p>
<h2>4. Durata e rinnovo automatico</h2>
<p>L’abbonamento ha durata mensile e si rinnova automaticamente di mese in mese fino alla sua cessazione. Non è previsto un periodo minimo obbligatorio di permanenza, salvo diverso accordo scritto tra le Parti.</p>
<h2>5. Recesso e cessazione</h2>
<p>Ciascuna Parte può richiedere la cessazione dell’abbonamento. La cessazione impedisce i rinnovi successivi e non determina il rimborso dei periodi già pagati e iniziati, salvo diverso accordo tra le Parti o obblighi inderogabili di legge.</p>
<p>Le attività già concordate o avviate alla data di cessazione saranno gestite secondo buona fede e, quando necessario, completate o consegnate secondo modalità concordate tra le Parti.</p>
<h2>6. Pagamenti non riusciti</h2>
<p>In caso di mancato pagamento o impossibilità di effettuare l’addebito automatico, il sistema di pagamento potrà effettuare ulteriori tentativi di riscossione. Qualora l’insoluto permanga, AUTSYS potrà sospendere il servizio fino alla regolarizzazione, fermo restando quanto già maturato.</p>
<h2>7. Modalità operative</h2>
<p>Le singole attività vengono definite nel corso del rapporto sulla base delle necessità di EOLO e delle priorità concordate. AUTSYS mantiene autonomia tecnica e organizzativa nell’esecuzione delle attività affidate, nel rispetto delle esigenze operative del Cliente.</p>
<p>Quando un intervento possa comportare modifiche rilevanti a sistemi, dati o processi aziendali, AUTSYS può richiedere una preventiva conferma del Cliente prima di procedere.</p>
<h2>8. Obblighi del Cliente</h2>
<p>EOLO si impegna a fornire le informazioni, le autorizzazioni e gli accessi ragionevolmente necessari allo svolgimento delle attività richieste. Il Cliente rimane responsabile della correttezza delle informazioni fornite, delle decisioni aziendali assunte e dell’uso dei propri sistemi e software.</p>
<h2>9. Accessi, credenziali e sicurezza</h2>
<p>Qualora AUTSYS debba accedere a sistemi, applicazioni o infrastrutture di EOLO, tali accessi saranno utilizzati esclusivamente per le finalità del servizio e nella misura necessaria all’esecuzione delle attività concordate. AUTSYS adotta misure ragionevoli per proteggere le credenziali e le informazioni alle quali abbia accesso.</p>
<h2>10. Riservatezza</h2>
<p>Le Parti si impegnano a mantenere riservate le informazioni tecniche, commerciali, organizzative e aziendali apprese nell’ambito del rapporto e non destinate alla diffusione pubblica. L’obbligo di riservatezza permane anche dopo la cessazione dell’abbonamento.</p>
<h2>11. Dati e documentazione del Cliente</h2>
<p>I dati, i documenti e le informazioni appartenenti a EOLO rimangono di titolarità del Cliente. AUTSYS può utilizzarli esclusivamente nella misura necessaria allo svolgimento delle attività concordate, salvo ulteriori finalità espressamente autorizzate.</p>
<p>Qualora l’esecuzione del servizio comporti trattamenti di dati personali per conto del Cliente che richiedano specifici adempimenti ai sensi della normativa applicabile, le Parti provvederanno agli eventuali accordi o atti ulteriori necessari.</p>
<h2>12. Software e proprietà intellettuale</h2>
<p>Restano di proprietà di ciascuna Parte i software, i sistemi, le tecnologie, le metodologie, il codice e il patrimonio di conoscenze già esistenti prima delle singole attività.</p>
<p>La titolarità di nuovi software, modifiche, personalizzazioni o altri risultati sviluppati nell’ambito del rapporto sarà determinata, quando necessario, in funzione della natura della singola attività e degli eventuali accordi specifici relativi al progetto interessato. L’abbonamento, da solo, non comporta il trasferimento della proprietà intellettuale di software o tecnologie AUTSYS.</p>
<h2>13. Servizi e sistemi di terzi</h2>
<p>Alcune attività potranno dipendere da prodotti, servizi, infrastrutture o piattaforme di terzi. AUTSYS non risponde di interruzioni, malfunzionamenti o cessazioni direttamente imputabili a tali soggetti e non sotto il proprio controllo, fermo restando l’impegno a collaborare nella ricerca di soluzioni tecnicamente ragionevoli.</p>
<h2>14. Responsabilità</h2>
<p>AUTSYS si impegna a svolgere le attività con diligenza e secondo criteri tecnici adeguati alla natura dell’intervento. AUTSYS non garantisce l’assenza assoluta di errori o interruzioni nei sistemi informatici, né risultati dipendenti da fattori esterni al proprio controllo.</p>
<p>Eventuali limitazioni di responsabilità non si applicano nei casi in cui la responsabilità non possa essere esclusa o limitata ai sensi della legge applicabile.</p>
<h2>15. Modifiche del servizio o delle condizioni</h2>
<p>Eventuali modifiche sostanziali al prezzo, alla natura dell’abbonamento o alle presenti condizioni saranno comunicate al Cliente prima della loro applicazione. Le modifiche non avranno effetto retroattivo sui periodi già pagati.</p>
<p>Qualora EOLO non intenda accettare una modifica applicabile ai rinnovi successivi, potrà cessare l’abbonamento prima dell’entrata in vigore della nuova condizione.</p>
<h2>16. Accettazione delle condizioni</h2>
<p>La sottoscrizione dell’abbonamento richiede l’accettazione espressa delle presenti condizioni. Prima della conferma del pagamento, al Cliente viene resa disponibile la versione delle condizioni applicabile all’abbonamento.</p>
<p>L’accettazione elettronica viene associata all’abbonamento sottoscritto e ne costituisce parte integrante. AUTSYS conserva evidenza almeno dell’identità del Cliente, della versione delle condizioni accettate, della data e ora dell’accettazione, del servizio e del prezzo sottoscritti, nonché del relativo identificativo dell’abbonamento e/o della transazione elettronica.</p>
<h2>17. Comunicazioni</h2>
<p>Le comunicazioni relative al rapporto potranno essere effettuate mediante i canali normalmente utilizzati tra le Parti, ivi inclusa la posta elettronica. Salvo diverso accordo scritto, per AUTSYS il riferimento ordinario è guido.autelli@autsys-srls.com.</p>
<h2>18. Legge applicabile e foro competente</h2>
<p>Le presenti condizioni sono regolate dalla legge italiana. Per ogni controversia relativa alla loro interpretazione, esecuzione o validità sarà competente in via esclusiva il Foro di Genova, salvo norme inderogabili di legge.</p>
<hr>
<p class="meta">Versione pubblicata per il flusso di sottoscrizione elettronica. Il documento ufficiale archiviato da AUTSYS S.R.L.S. è identificato dal numero e dall'hash sopra indicati.</p>
</body>
</html>`);
});


const EOLO_PRICE_ID = "price_1UJAjBS1PEz956OxyguUscyD";
const EOLO_TAX_RATE_ID = "txr_1UJ7xeS1PEz956Ox2ZVQHlNr";
const EOLO_CONTRACT = "2026/001";
const EOLO_CONTRACT_REVISION = "REV.0";
const EOLO_CONTRACT_SHA256 = "a263d98e2e19d94c0f380f9fa5ec96107df084a80715fd3f66c41ceb873dee93";

app.get("/subscribe/eolo/2026-001", (req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html><html lang="it"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Abbonamento EOLO</title><style>
body{font-family:Arial,sans-serif;max-width:860px;margin:40px auto;padding:0 24px;line-height:1.5;color:#111}.box{border:1px solid #ddd;border-radius:10px;padding:18px;margin:20px 0}label{display:block;margin:10px 0 4px;font-weight:600}input,select{width:100%;box-sizing:border-box;padding:10px;border:1px solid #bbb;border-radius:6px}.check{display:block;margin:14px 0;padding:12px;border:1px solid #ddd;border-radius:8px;font-weight:400}.check input{width:auto;margin-right:8px}button{background:#111;color:#fff;border:0;border-radius:8px;padding:14px 18px;font-size:16px;cursor:pointer}.price{font-size:28px;font-weight:700}.meta{font-size:13px;color:#555}.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px}@media(max-width:700px){.grid,.grid3{grid-template-columns:1fr}}
</style></head><body>
<h1>Collaborazione tecnica continuativa EOLO</h1>
<p class="price">€ 250,00 + IVA 22% / mese</p>
<p>Totale al pagamento: <strong>€ 305,00 al mese</strong>.</p>

<form method="post" action="/subscribe/eolo/2026-001">
<div class="box">
<h2>Dati aziendali e fatturazione elettronica</h2>
<label>Tipo di acquirente</label>
<select name="buyer_type" required style="width:100%;box-sizing:border-box;padding:10px;border:1px solid #bbb;border-radius:6px">
<option value="">Seleziona</option>
<option value="business">Azienda / impresa / professionista con P.IVA</option>
<option value="consumer">Privato consumatore</option>
</select>
<p class="meta"><strong>Per questo servizio EOLO l'acquisto deve essere effettuato come azienda.</strong></p>
<label>Ragione sociale / denominazione</label><input name="company_name" required maxlength="140" value="TERMOMECCANICA &quot;EOLO&quot; DI AUTELLI ING. FRANCESCO">
<div class="grid">
<div><label>Partita IVA</label><input name="vat_number" required maxlength="20" autocomplete="off"></div>
<div><label>Codice fiscale</label><input name="fiscal_code" maxlength="20" autocomplete="off"></div>
</div>
<label>Indirizzo sede</label><input name="address_line1" required maxlength="180">
<div class="grid3">
<div><label>CAP</label><input name="postal_code" required maxlength="10"></div>
<div><label>Comune</label><input name="city" required maxlength="80"></div>
<div><label>Provincia</label><input name="province" required maxlength="4" placeholder="GE"></div>
</div>
<div class="grid">
<div><label>Codice destinatario SDI</label><input name="sdi_code" maxlength="7" autocomplete="off"></div>
<div><label>PEC</label><input name="pec" type="email" maxlength="254"></div>
</div>
<label>Email amministrativa / fatturazione</label><input name="billing_email" type="email" required maxlength="254">
<p class="meta">Inserire almeno uno tra Codice destinatario SDI e PEC. L'email indicata riceverà copia delle condizioni accettate e le comunicazioni relative alla sottoscrizione.</p>
</div>

<div class="box"><h2>Condizioni contrattuali</h2><p><strong>2026/001 - AUTSYS SRLS AI - 24/09/2026 - REV.0</strong></p><p><a href="/legal/autsys-srls/2026-001" target="_blank" rel="noopener">Apri le condizioni complete</a></p><p class="meta">SHA-256: a263d98e2e19d94c0f380f9fa5ec96107df084a80715fd3f66c41ceb873dee93</p></div>
<label class="check"><input type="checkbox" name="general" value="yes" required> Ho letto e accetto le condizioni contrattuali 2026/001 REV.0.</label>
<label class="check"><input type="checkbox" name="specific" value="yes" required> Approvo specificamente le clausole 4, 6, 14 e 18 relative a rinnovo automatico, sospensione per mancato pagamento, responsabilità e foro competente.</label>
<button type="submit">Accetta e vai al pagamento Stripe</button>
</form></body></html>`);
});

app.post("/subscribe/eolo/2026-001", async (req, res) => {
  if (req.body?.general !== "yes" || req.body?.specific !== "yes") {
    return res.status(400).send("Accettazione richiesta.");
  }

  const clean = (v, max=254) => String(v || "").trim().slice(0,max);
  const buyerType = clean(req.body?.buyer_type, 20);
  const companyName = clean(req.body?.company_name, 140);
  const vatNumber = clean(req.body?.vat_number, 20).replace(/\s+/g,"").toUpperCase();
  const fiscalCode = clean(req.body?.fiscal_code, 20).replace(/\s+/g,"").toUpperCase();
  const addressLine1 = clean(req.body?.address_line1, 180);
  const postalCode = clean(req.body?.postal_code, 10);
  const city = clean(req.body?.city, 80);
  const province = clean(req.body?.province, 4).toUpperCase();
  const sdiCode = clean(req.body?.sdi_code, 7).toUpperCase();
  const pec = clean(req.body?.pec, 254).toLowerCase();
  const billingEmail = clean(req.body?.billing_email, 254).toLowerCase();

  if (buyerType !== "business") {
    return res.status(400).send("Per la sottoscrizione EOLO l'acquirente deve essere un'azienda / soggetto con Partita IVA.");
  }
  if (!companyName || !vatNumber || !addressLine1 || !postalCode || !city || !province || !billingEmail) {
    return res.status(400).send("Dati aziendali e di fatturazione incompleti.");
  }
  const normalizedVat = vatNumber.startsWith("IT") ? vatNumber : ("IT" + vatNumber);
  if (!/^IT[0-9]{11}$/.test(normalizedVat)) {
    return res.status(400).send("Partita IVA italiana non valida: inserire 11 cifre (eventualmente precedute da IT).");
  }
  if (!sdiCode && !pec) {
    return res.status(400).send("Inserire almeno Codice destinatario SDI oppure PEC.");
  }
  if (!/^\S+@\S+\.\S+$/.test(billingEmail) || (pec && !/^\S+@\S+\.\S+$/.test(pec))) {
    return res.status(400).send("Indirizzo email non valido.");
  }

  const acceptedAt = new Date().toISOString();
  const receipt = {
    event: "LEGAL_ACCEPTANCE",
    contract: EOLO_CONTRACT,
    revision: EOLO_CONTRACT_REVISION,
    sha256: EOLO_CONTRACT_SHA256,
    accepted_general: true,
    accepted_specific_articles: ["4","6","14","18"],
    accepted_at: acceptedAt,
    buyer_type: buyerType,
    company_name: companyName,
    vat_number: normalizedVat,
    fiscal_code: fiscalCode,
    address_line1: addressLine1,
    postal_code: postalCode,
    city,
    province,
    country: "IT",
    sdi_code: sdiCode,
    pec,
    billing_email: billingEmail,
    ip: String(req.ip || req.socket.remoteAddress || ""),
    user_agent: String(req.get("user-agent") || "")
  };
  console.log("LEGAL_ACCEPTANCE", JSON.stringify(receipt));

  try {
    const customer = await stripePost("/v1/customers", {
      "name": companyName,
      "email": billingEmail,
      "address[line1]": addressLine1,
      "address[postal_code]": postalCode,
      "address[city]": city,
      "address[state]": province,
      "address[country]": "IT",
      "metadata[buyer_type]": buyerType,
      "metadata[fiscal_code]": fiscalCode,
      "metadata[sdi_code]": sdiCode,
      "metadata[codice_destinatario]": sdiCode,
      "metadata[pec]": pec,
      "metadata[contract_number]": EOLO_CONTRACT,
      "metadata[contract_revision]": EOLO_CONTRACT_REVISION
    });

    const taxId = await stripePost("/v1/customers/" + customer.id + "/tax_ids", {
      "type": "eu_vat",
      "value": normalizedVat
    });

    const session = await stripePost("/v1/checkout/sessions", {
      "mode": "subscription",
      "line_items[0][price]": EOLO_PRICE_ID,
      "line_items[0][quantity]": "1",
      "line_items[0][tax_rates][0]": EOLO_TAX_RATE_ID,
      "customer": customer.id,
      "billing_address_collection": "required",
      "tax_id_collection[enabled]": "true",
      "name_collection[business][enabled]": "true",
      "name_collection[business][optional]": "false",
      "success_url": publicBase(req) + "/subscribe/eolo/2026-001/success?session_id={CHECKOUT_SESSION_ID}",
      "cancel_url": publicBase(req) + "/subscribe/eolo/2026-001",
      "client_reference_id": "EOLO-2026-001",
      "metadata[contract_number]": EOLO_CONTRACT,
      "metadata[contract_revision]": EOLO_CONTRACT_REVISION,
      "metadata[contract_sha256]": EOLO_CONTRACT_SHA256,
      "metadata[accepted_at]": acceptedAt,
      "metadata[company_name]": companyName,
      "metadata[vat_number]": normalizedVat,
      "metadata[stripe_customer_id]": customer.id,
      "metadata[stripe_tax_id_id]": taxId.id,
      "metadata[fiscal_code]": fiscalCode,
      "metadata[address_line1]": addressLine1,
      "metadata[postal_code]": postalCode,
      "metadata[city]": city,
      "metadata[province]": province,
      "metadata[country]": "IT",
      "metadata[sdi_code]": sdiCode,
      "metadata[pec]": pec,
      "metadata[billing_email]": billingEmail,
      "subscription_data[metadata][contract_number]": EOLO_CONTRACT,
      "subscription_data[metadata][contract_revision]": EOLO_CONTRACT_REVISION,
      "subscription_data[metadata][contract_sha256]": EOLO_CONTRACT_SHA256,
      "subscription_data[metadata][accepted_at]": acceptedAt,
      "subscription_data[metadata][vat_number]": normalizedVat,
      "subscription_data[metadata][stripe_customer_id]": customer.id,
      "subscription_data[metadata][stripe_tax_id_id]": taxId.id,
      "subscription_data[metadata][sdi_code]": sdiCode,
      "subscription_data[metadata][pec]": pec,
      "subscription_data[metadata][billing_email]": billingEmail
    });
    console.log("STRIPE_CHECKOUT_CREATED", JSON.stringify({
      session_id: session.id,
      contract: EOLO_CONTRACT,
      revision: EOLO_CONTRACT_REVISION,
      accepted_at: acceptedAt,
      billing_email: billingEmail,
      vat_number: normalizedVat,
      stripe_customer_id: customer.id,
      stripe_tax_id_id: taxId.id,
      sdi_code: sdiCode,
      pec
    }));
    return res.redirect(303, session.url);
  } catch (err) {
    console.error("STRIPE_CHECKOUT_ERROR", err?.message || String(err));
    return res.status(502).send("Impossibile avviare il pagamento Stripe. Riprova tra poco.");
  }
});

app.get("/subscribe/eolo/2026-001/success", (req, res) => {
  const sessionId = String(req.query.session_id || "");
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html><html lang="it"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Abbonamento attivato</title><style>body{font-family:Arial,sans-serif;max-width:760px;margin:50px auto;padding:0 24px;line-height:1.5;color:#111}.ok{border:1px solid #ddd;border-radius:10px;padding:22px}</style></head><body><div class="ok"><h1>Pagamento completato</h1><p>Grazie. Stripe ha completato il flusso di pagamento per l'abbonamento EOLO.</p><p>Riferimento contratto: <strong>2026/001 REV.0</strong></p><p>Sessione Stripe: <code>${sessionId.replace(/[<>&"]/g,"")}</code></p></div></body></html>`);
});

app.post("/v1/manager/bootstrap", (req, res) => {
  if (!MANAGER_TOKEN_KEY) return res.status(503).json({ ok: false, error: "relay_not_configured" });
  if (!allowBootstrap(req)) return res.status(429).json({ ok: false, error: "bootstrap_rate_limited" });
  const body = asObject(req.body);
  if (!body) return res.status(400).json({ ok: false, error: "invalid_body" });
  const installationId = String(body.installation_id || "").trim();
  const productCode = String(body.product_code || "").trim().toUpperCase();
  const managerVersion = String(body.manager_version || "").trim();
  const platform = String(body.platform || "").trim().toUpperCase();
  const bindingSecret = String(body.binding_secret || "").trim();
  if (!isUuid(installationId)) return res.status(400).json({ ok: false, error: "invalid_installation_id" });
  if (productCode !== "AUTSYS_MANAGER") return res.status(400).json({ ok: false, error: "invalid_product" });
  if (platform !== "ANDROID") return res.status(400).json({ ok: false, error: "invalid_platform" });
  if (!/^[0-9A-Za-z._-]{1,64}$/.test(managerVersion)) return res.status(400).json({ ok: false, error: "invalid_manager_version" });
  if (!isBindingSecret(bindingSecret)) return res.status(400).json({ ok: false, error: "invalid_binding" });
  const issuedAt = nowSec();
  const expiresAt = issuedAt + MANAGER_TOKEN_TTL_SEC;
  const payload = {
    installation_id: installationId,
    purpose: "manager-relay",
    platform: "ANDROID",
    token_version: 2,
    binding_sha256: sha256Text(bindingSecret),
    iat: issuedAt,
    exp: expiresAt
  };
  const relayToken = signManagerToken(payload);
  if (!relayToken) return res.status(503).json({ ok: false, error: "relay_not_configured" });
  return res.status(201).json({
    ok: true,
    installation_id: installationId,
    relay_token: relayToken,
    expires_at: expiresAt,
    relay_version: VERSION,
    protocol: PROTOCOL
  });
});

app.post("/v1/manager/events", requireManager, (req, res) => {
  purgeExpired();
  const installationId = req.autsysManager.installation_id;
  const body = asObject(req.body);
  if (!body) return res.status(400).json({ ok: false, error: "invalid_body" });
  const eventId = String(body.event_id || "").trim();
  const kind = String(body.kind || "").trim();
  const payload = asObject(body.payload);
  const signature = typeof body.signature === "string" ? body.signature : "";
  const ts = Number.isInteger(body.ts) ? body.ts : nowSec();
  if (!isSafeId(eventId) || !isSafeId(kind) || !payload) return res.status(400).json({ ok: false, error: "invalid_event" });
  if (eventIds.has(eventId)) return res.status(200).json({ ok: true, duplicate: true, event_id: eventId });
  if (events.length >= MAX_EVENTS) return res.status(503).json({ ok: false, error: "queue_full" });
  const ttl = Number.isInteger(body.ttl_sec) ? Math.max(60, Math.min(body.ttl_sec, DEFAULT_EVENT_TTL_SEC)) : DEFAULT_EVENT_TTL_SEC;
  const item = { event_id: eventId, installation_id: installationId, kind, ts, received_at: nowSec(), expires_at: nowSec() + ttl, payload, signature };
  events.push(item);
  eventIds.add(eventId);
  return res.status(202).json({ ok: true, event_id: eventId });
});

app.get("/v1/central/events", requireCentral, (req, res) => {
  purgeExpired();
  const requested = Number.parseInt(String(req.query.limit || "50"), 10);
  const limit = Number.isFinite(requested) ? Math.max(1, Math.min(requested, MAX_BATCH)) : 50;
  return res.json({ ok: true, count: Math.min(events.length, limit), items: events.slice(0, limit) });
});

app.post("/v1/central/events/ack", requireCentral, (req, res) => {
  const ids = Array.isArray(req.body?.event_ids) ? req.body.event_ids.filter(isSafeId).slice(0, MAX_BATCH) : [];
  if (ids.length === 0) return res.status(400).json({ ok: false, error: "invalid_event_ids" });
  const wanted = new Set(ids);
  let removed = 0;
  for (let i = events.length - 1; i >= 0; i -= 1) {
    if (wanted.has(events[i].event_id)) {
      eventIds.delete(events[i].event_id);
      events.splice(i, 1);
      removed += 1;
    }
  }
  return res.json({ ok: true, removed });
});

app.get("/v1/central/packages/:releaseId", requireCentral, (req, res) => {
  purgeExpired();
  const releaseId = String(req.params.releaseId || "").trim();
  if (!isUuid(releaseId)) return res.status(400).json({ ok: false, error: "invalid_release_id" });
  const item = packagesByRelease.get(releaseId);
  if (!item || !fs.existsSync(item.path)) return res.status(404).json({ ok: false, error: "package_not_cached" });
  return res.json({ ok: true, release_id: releaseId, sha256: item.sha256, size_bytes: item.size_bytes, filename: item.filename, expires_at: item.expires_at });
});

app.put("/v1/central/packages/:releaseId", requireCentral, (req, res) => {
  purgeExpired();
  const releaseId = String(req.params.releaseId || "").trim();
  if (!isUuid(releaseId)) return res.status(400).json({ ok: false, error: "invalid_release_id" });
  const expectedSha = String(req.get("x-autsys-sha256") || "").trim().toLowerCase();
  const expectedSize = Number.parseInt(String(req.get("x-autsys-size") || "0"), 10);
  const filename = safeFilename(req.get("x-autsys-filename") || "package.zip");
  const requestedTtl = Number.parseInt(String(req.get("x-autsys-ttl-sec") || DEFAULT_PACKAGE_TTL_SEC), 10);
  const ttl = Number.isFinite(requestedTtl) ? Math.max(60, Math.min(requestedTtl, MAX_PACKAGE_TTL_SEC)) : DEFAULT_PACKAGE_TTL_SEC;
  if (!isSha256(expectedSha) || !Number.isSafeInteger(expectedSize) || expectedSize <= 0 || expectedSize > MAX_PACKAGE_BYTES) {
    return res.status(400).json({ ok: false, error: "invalid_package_metadata" });
  }
  const existing = packagesByRelease.get(releaseId);
  if (existing && existing.sha256 === expectedSha && existing.size_bytes === expectedSize && fs.existsSync(existing.path)) {
    existing.expires_at = nowSec() + ttl;
    return res.status(200).json({ ok: true, duplicate: true, release_id: releaseId, sha256: expectedSha, size_bytes: expectedSize, expires_at: existing.expires_at });
  }
  try { fs.mkdirSync(PACKAGE_ROOT, { recursive: true }); } catch {
    return res.status(503).json({ ok: false, error: "package_cache_unavailable" });
  }
  const finalPath = packagePath(releaseId);
  const tempPath = `${finalPath}.uploading.${crypto.randomBytes(8).toString("hex")}`;
  const hash = crypto.createHash("sha256");
  const out = fs.createWriteStream(tempPath, { flags: "wx" });
  let received = 0;
  let finished = false;
  const fail = (status, error) => {
    if (finished) return;
    finished = true;
    try { req.unpipe(out); } catch {}
    try { out.destroy(); } catch {}
    try { fs.unlinkSync(tempPath); } catch {}
    if (!res.headersSent) res.status(status).json({ ok: false, error });
  };
  req.on("data", (chunk) => {
    received += chunk.length;
    if (received > expectedSize || received > MAX_PACKAGE_BYTES) {
      fail(413, "package_too_large");
      try { req.destroy(); } catch {}
      return;
    }
    hash.update(chunk);
  });
  req.on("aborted", () => fail(400, "upload_aborted"));
  req.on("error", () => fail(400, "upload_failed"));
  out.on("error", () => fail(503, "package_cache_write_failed"));
  out.on("finish", () => {
    if (finished) return;
    const actualSha = hash.digest("hex");
    if (received !== expectedSize) return fail(400, "package_size_mismatch");
    if (!safeEqualText(actualSha, expectedSha)) return fail(400, "package_sha256_mismatch");
    finished = true;
    try { fs.renameSync(tempPath, finalPath); }
    catch {
      try { fs.unlinkSync(finalPath); } catch {}
      try { fs.renameSync(tempPath, finalPath); }
      catch {
        try { fs.unlinkSync(tempPath); } catch {}
        return res.status(503).json({ ok: false, error: "package_cache_commit_failed" });
      }
    }
    const item = { release_id: releaseId, sha256: actualSha, size_bytes: received, filename, path: finalPath, expires_at: nowSec() + ttl };
    packagesByRelease.set(releaseId, item);
    return res.status(201).json({ ok: true, release_id: releaseId, sha256: actualSha, size_bytes: received, filename, expires_at: item.expires_at });
  });
  req.pipe(out);
});

app.post("/v1/central/package-tickets", requireCentral, (req, res) => {
  purgeExpired();
  const body = asObject(req.body);
  if (!body) return res.status(400).json({ ok: false, error: "invalid_body" });
  const releaseId = String(body.release_id || "").trim();
  const installationId = String(body.installation_id || "").trim();
  if (!isUuid(releaseId) || !isSafeId(installationId)) return res.status(400).json({ ok: false, error: "invalid_ticket_request" });
  const pkg = packagesByRelease.get(releaseId);
  if (!pkg || !fs.existsSync(pkg.path)) return res.status(404).json({ ok: false, error: "package_not_cached" });
  const requested = Number.isInteger(body.ttl_sec) ? body.ttl_sec : DEFAULT_COMMAND_TTL_SEC;
  const ttl = Math.max(60, Math.min(requested, MAX_PACKAGE_TTL_SEC));
  const ticket = crypto.randomBytes(32).toString("base64url");
  const expiresAt = nowSec() + ttl;
  packageTickets.set(ticket, { release_id: releaseId, installation_id: installationId, expires_at: expiresAt });
  pkg.expires_at = Math.max(pkg.expires_at, expiresAt);
  return res.status(201).json({ ok: true, release_id: releaseId, installation_id: installationId, expires_at: expiresAt, download_url: `${publicBase(req)}/v1/download/${ticket}` });
});

app.get("/v1/download/:ticket", (req, res) => {
  purgeExpired();
  const ticket = String(req.params.ticket || "").trim();
  if (!/^[A-Za-z0-9_-]{40,128}$/.test(ticket)) return res.status(404).end();
  const access = packageTickets.get(ticket);
  if (!access || access.expires_at <= nowSec()) return res.status(404).end();
  const pkg = packagesByRelease.get(access.release_id);
  if (!pkg || !fs.existsSync(pkg.path)) return res.status(404).end();
  res.setHeader("Content-Type", "application/zip");
  res.setHeader("Content-Length", String(pkg.size_bytes));
  res.setHeader("Content-Disposition", `attachment; filename="${safeFilename(pkg.filename)}"`);
  res.setHeader("X-AUTSYS-Package-SHA256", pkg.sha256);
  const stream = fs.createReadStream(pkg.path);
  stream.on("error", () => { if (!res.headersSent) res.status(503).end(); else res.destroy(); });
  stream.pipe(res);
});

app.post("/v1/central/commands", requireCentral, (req, res) => {
  purgeExpired();
  const body = asObject(req.body);
  if (!body) return res.status(400).json({ ok: false, error: "invalid_body" });
  const commandId = String(body.command_id || "").trim();
  const installationId = String(body.installation_id || "").trim();
  const kind = String(body.kind || "").trim();
  const payload = asObject(body.payload);
  const signature = typeof body.signature === "string" ? body.signature : "";
  if (!isSafeId(commandId) || !isSafeId(installationId) || !isSafeId(kind) || !payload || !signature) {
    return res.status(400).json({ ok: false, error: "invalid_command" });
  }
  if (commandIds.has(commandId)) return res.status(200).json({ ok: true, duplicate: true, command_id: commandId });
  const list = commandsByInstallation.get(installationId) || [];
  if (list.length >= MAX_COMMANDS_PER_INSTALLATION) return res.status(503).json({ ok: false, error: "queue_full" });
  const ttl = Number.isInteger(body.ttl_sec) ? Math.max(60, Math.min(body.ttl_sec, DEFAULT_COMMAND_TTL_SEC)) : DEFAULT_COMMAND_TTL_SEC;
  const item = { command_id: commandId, installation_id: installationId, kind, created_at: nowSec(), expires_at: nowSec() + ttl, payload, signature };
  list.push(item);
  commandsByInstallation.set(installationId, list);
  commandIds.add(commandId);
  return res.status(202).json({ ok: true, command_id: commandId });
});

app.get("/v1/manager/commands", requireManager, (req, res) => {
  purgeExpired();
  const installationId = req.autsysManager.installation_id;
  const list = commandsByInstallation.get(installationId) || [];
  return res.json({ ok: true, count: list.length, items: list });
});

app.post("/v1/central/commands/ack", requireCentral, (req, res) => {
  const ids = Array.isArray(req.body?.command_ids) ? req.body.command_ids.filter(isSafeId).slice(0, MAX_BATCH) : [];
  if (ids.length === 0) return res.status(400).json({ ok: false, error: "invalid_command_ids" });
  const wanted = new Set(ids);
  let removed = 0;
  for (const [installationId, list] of commandsByInstallation.entries()) {
    const kept = [];
    for (const item of list) {
      if (wanted.has(item.command_id)) {
        commandIds.delete(item.command_id);
        removed += 1;
      } else kept.push(item);
    }
    if (kept.length === 0) commandsByInstallation.delete(installationId);
    else commandsByInstallation.set(installationId, kept);
  }
  return res.json({ ok: true, removed });
});

app.get("/diag", requireCentral, (req, res) => {
  purgeExpired();
  let commandCount = 0;
  for (const list of commandsByInstallation.values()) commandCount += list.length;
  let cachedBytes = 0;
  for (const item of packagesByRelease.values()) cachedBytes += item.size_bytes;
  return res.json({
    ok: true,
    service: "autsys-central-relay",
    version: VERSION,
    protocol: PROTOCOL,
    ts: nowSec(),
    manager_events_queued: events.length,
    manager_installations_with_commands: commandsByInstallation.size,
    commands_queued: commandCount,
    package_cache_items: packagesByRelease.size,
    package_cache_bytes: cachedBytes,
    package_tickets: packageTickets.size,
    persistence: "memory+ephemeral_package_files",
    authoritative: false
  });
});

app.use((req, res) => res.status(404).json({ ok: false, error: "not_found" }));
app.use((err, req, res, next) => {
  if (err?.type === "entity.too.large") return res.status(413).json({ ok: false, error: "payload_too_large" });
  if (err instanceof SyntaxError) return res.status(400).json({ ok: false, error: "invalid_json" });
  return res.status(500).json({ ok: false, error: "internal_error" });
});

app.listen(port, () => {
  console.log(`AUTSYS Central Relay ${VERSION} listening on port ${port}`);
});
