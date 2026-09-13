import crypto from 'crypto';
import zlib from 'zlib';
import express from 'express';
import pg from 'pg';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const { Pool } = pg;
const app = express();
const PORT = Number(process.env.PORT || 10000);
const APP_PASSWORD = String(process.env.APP_PASSWORD || '');
const APP_SECRET = String(process.env.APP_SECRET || '');
const SEED_STATE_B64 = String(process.env.SEED_STATE_B64 || '');
const VERSION = 'WEB 1.0.0.1';
const TZ = 'Europe/Rome';

if (!APP_PASSWORD || !APP_SECRET) throw new Error('APP_PASSWORD/APP_SECRET mancanti');
if (!SEED_STATE_B64) throw new Error('SEED_STATE_B64 mancante');

const pool = new Pool({
  host: process.env.PGHOST,
  port: Number(process.env.PGPORT || 5432),
  user: process.env.PGUSER,
  password: process.env.PGPASSWORD || undefined,
  database: process.env.PGDATABASE,
  ssl: false,
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(express.json({limit:'128kb'}));
app.use(express.urlencoded({extended:false}));
app.use((req,res,next)=>{
  res.setHeader('Cache-Control','no-store');
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('Referrer-Policy','no-referrer');
  res.setHeader('X-Frame-Options','DENY');
  next();
});

function safeEqual(a,b){
  const aa=Buffer.from(String(a)), bb=Buffer.from(String(b));
  return aa.length===bb.length && crypto.timingSafeEqual(aa,bb);
}
function sessionToken(){return crypto.createHmac('sha256',APP_SECRET).update('AUTSYS_BETTING_SESSION').digest('base64url')}
function cookies(req){
  const out={}; for(const p of String(req.headers.cookie||'').split(';')){const i=p.indexOf('=');if(i>0)out[p.slice(0,i).trim()]=decodeURIComponent(p.slice(i+1).trim())} return out;
}
function authed(req){return safeEqual(cookies(req).autsys_betting||'',sessionToken())}
function requireAuth(req,res,next){if(!authed(req))return res.status(401).json({error:'Accesso richiesto'});next()}

function todayISO(){
  const parts=new Intl.DateTimeFormat('en-CA',{timeZone:TZ,year:'numeric',month:'2-digit',day:'2-digit'}).formatToParts(new Date());
  const o=Object.fromEntries(parts.map(x=>[x.type,x.value])); return `${o.year}-${o.month}-${o.day}`;
}
function nowISO(){
  const d=new Date();
  const parts=new Intl.DateTimeFormat('sv-SE',{timeZone:TZ,year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}).format(d).replace(' ','T');
  return `${parts}+02:00`;
}
function addDays(s,n){const d=new Date(`${s}T12:00:00Z`);d.setUTCDate(d.getUTCDate()+n);return d.toISOString().slice(0,10)}
function monthEndPlusOne(iso){
  const [y,m]=iso.split('-').map(Number); const d=new Date(Date.UTC(y,m+1,0)); return d.toISOString().slice(0,10);
}
function centsToIt(c){return (Number(c||0)/100).toLocaleString('it-IT',{minimumFractionDigits:2,maximumFractionDigits:2})}
function parseCents(v){
  let s=String(v??'').trim().replace(/\s/g,'').replace(/€/g,'');
  if(!s) throw new Error('Inserisci un importo');
  if(s.includes(',')) s=s.replace(/\./g,'').replace(',','.');
  const n=Number(s); if(!Number.isFinite(n)||n<0)throw new Error('Importo non valido'); return Math.round(n*100);
}
function pctIt(v){return `${v>=0?'+':''}${v.toLocaleString('it-IT',{minimumFractionDigits:2,maximumFractionDigits:2})}%`}
function dateIt(s){const [y,m,d]=s.split('-');return `${d}/${m}/${y}`}
function round(n){return Math.round(n)}
function trunc10(c){return Math.max(0,Math.floor(c/10)*10)}

function decodeSeed(){return JSON.parse(zlib.inflateSync(Buffer.from(SEED_STATE_B64,'base64')).toString('utf8'))}
async function initDb(){
  const c=await pool.connect();
  try{
    await c.query(`CREATE TABLE IF NOT EXISTS betting_state(id integer PRIMARY KEY, data jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())`);
    const r=await c.query('SELECT 1 FROM betting_state WHERE id=1');
    if(!r.rowCount){const seed=decodeSeed(); if(seed.Withdrawals==null)seed.Withdrawals=[]; await c.query('INSERT INTO betting_state(id,data) VALUES(1,$1::jsonb)',[JSON.stringify(seed)])}
  }finally{c.release()}
}
async function readState(){const r=await pool.query('SELECT data FROM betting_state WHERE id=1');if(!r.rowCount)throw new Error('Stato assente');return r.rows[0].data}
async function mutateState(fn){
  const c=await pool.connect();
  try{await c.query('BEGIN');const r=await c.query('SELECT data FROM betting_state WHERE id=1 FOR UPDATE');let s=r.rows[0].data;const out=await fn(s);s=out||s;s.LastSavedAt=nowISO();await c.query('UPDATE betting_state SET data=$1::jsonb,updated_at=now() WHERE id=1',[JSON.stringify(s)]);await c.query('COMMIT');return s}catch(e){await c.query('ROLLBACK');throw e}finally{c.release()}
}

function calendarWithdrawalCount(s){return Object.values(s.Calendar||{}).filter(x=>Number(x.TheoreticalWithdrawalCents||0)>0).length}
function extendCalendar(s,through){
  s.Calendar ||= {};
  if(!s.CalendarUntil){s.CalendarUntil=s.StartDate}
  let last=s.CalendarUntil;
  let lastDay=s.Calendar[last];
  if(!lastDay){
    const keys=Object.keys(s.Calendar).sort(); last=keys[keys.length-1]; lastDay=s.Calendar[last]; s.CalendarUntil=last;
  }
  let personal=Number(lastDay?.TheoreticalPersonalCents ?? s.PersonalBalanceCents ?? -s.InitialCapital);
  let threshold=20000+5000*calendarWithdrawalCount(s);
  while(last < through){
    const date=addDays(last,1); const start=Number(lastDay.TheoreticalTargetCents); let target=round(start*1.0635); let wd=0;
    while(target>=threshold){
      wd+=5000; personal+=5000; const after=threshold-5000; threshold=after+10000; target=round(after*1.0635);
    }
    const day={Date:date,TheoreticalStartCents:start,TheoreticalTargetCents:target,TheoreticalWithdrawalCents:wd,TheoreticalPersonalCents:personal};
    s.Calendar[date]=day; last=date;lastDay=day;s.CalendarUntil=date;
  }
}
function ensureCalendar(s){extendCalendar(s,monthEndPlusOne(todayISO()))}

function standardPartTargets(base){const p=base/5;return [round(p*1.0251),round(p*1.0336),round(p*1.0508),round(p*1.1041)]}
function standardTotalTargets(base){return [round(base*1.0251),round(base*1.0319),round(base*1.0422),round(base*1.0635)]}
function stageForBalance(base,balance){const t=standardTotalTargets(base);let st=0;for(const x of t)if(balance>=x)st++;else break;return st}
function emergencyTargets(base){return [round(base*1.04),round(base*1.0625),round(base*1.0825),round(base*1.095)]}
function emergencyPartTargets(base){const p=base/4;return [round(p*1.04),round(p*1.07),round(p*1.11),round(p*1.16)]}

function currentInstruction(s,d){
  const bal=Number(d.CurrentBalanceCents||0);
  if(d.Mode==='RECOVERY_BASE'){
    const target=Number(d.OperationalBaseCents||d.RealStartCents);return {bet:trunc10(bal),target,betLabel:'PUNTA TUTTO',targetLabel:'FINO A SALDO',status:`Recupera prudentemente la base di ${centsToIt(target)} € prima di ripartire con gli step standard.`};
  }
  if(d.Mode==='EMERGENCY'){
    const base=Number(d.EmergencyCycleBase||bal), st=Math.max(0,Math.min(3,Number(d.Stage||0))), pts=emergencyPartTargets(base), frozen=pts.slice(0,st).reduce((a,b)=>a+b,0), active=Math.max(0,bal-frozen), targets=emergencyTargets(base);
    return {bet:trunc10(active),target:targets[st],betLabel:'PUNTA',targetLabel:'FINO A SALDO',status:`EMERGENZA: ciclo a 4 parti (4% → 7% → 11% → 16%) fino al riallineamento con il teorico ${centsToIt(d.TheoreticalStartCents)} €.`};
  }
  const base=Number(d.OperationalBaseCents||d.RealStartCents), st=Math.max(0,Math.min(4,Number(d.Stage||0))), pts=standardPartTargets(base), frozen=pts.slice(0,Math.min(st,4)).reduce((a,b)=>a+b,0), active=Math.max(0,bal-frozen), targets=standardTotalTargets(base);
  if(st>=4)return {bet:trunc10(active),target:0,betLabel:'PUNTA FREE',targetLabel:'NESSUN LIMITE',status:'Hai raggiunto tutti i quattro target. È attiva soltanto la quota FREE.'};
  return {bet:trunc10(active),target:targets[st],betLabel:st===0?'PUNTA TUTTO':'PUNTA',targetLabel:'FINO A SALDO',status:`Step standard ${st+1}/4: prosegui fino al saldo indicato.`};
}
function stepsView(d){
  if(d.Mode==='EMERGENCY'){
    const labels=['4%','7%','11%','16%'], base=Number(d.EmergencyCycleBase||d.CurrentBalanceCents), parts=emergencyPartTargets(base), totals=emergencyTargets(base), st=Number(d.Stage||0);
    return labels.map((label,i)=>({label,part_target:centsToIt(parts[i]),total_target:centsToIt(totals[i]),state:i<st?'done':i===st?'current':''}));
  }
  const labels=['2,51%','3,36%','5,08%','10,41%','FREE'], base=Number(d.OperationalBaseCents||d.RealStartCents), parts=standardPartTargets(base), totals=standardTotalTargets(base), st=Number(d.Stage||0);
  return labels.map((label,i)=>({label,part_target:i<4?centsToIt(parts[i]):'—',total_target:i<4?centsToIt(totals[i]):'—',state:i<st?'done':i===st?'current':''}));
}
function previousDeviation(s,currentDate){
  const prev=addDays(currentDate,-1), dr=s.Days?.[prev], cal=s.Calendar?.[prev];
  if(!dr||!dr.Closed||!cal)return {label:`SCOSTAMENTO AL ${dateIt(prev).slice(0,5)}`,amount:'',percent:''};
  const real=Number(dr.ClosingBalanceCents), theo=Number(cal.TheoreticalTargetCents), diff=real-theo, pct=theo?diff/theo*100:0;
  return {label:`SCOSTAMENTO AL ${dateIt(prev).slice(0,5)}`,amount:centsToIt(diff),percent:pctIt(pct)};
}
function stateView(s){
  ensureCalendar(s); const today=todayISO(), d=s.Days?.[s.CurrentDay]||null, needs=today!==s.CurrentDay, pd=previousDeviation(s,today), ins=d?currentInstruction(s,d):null;
  return {version:VERSION,today:dateIt(today),initialized:!!s.Initialized,start_date:dateIt(s.StartDate),calendar_until:dateIt(s.CalendarUntil),needs_new_day_balance:needs,needs_withdrawal:!!(d&&Number(d.CurrentBalanceCents)>=Number(s.NextWithdrawalThresholdCents)),previous_deviation_label:pd.label,previous_deviation_amount:pd.amount,previous_deviation_percent:pd.percent,personal_balance:centsToIt(s.PersonalBalanceCents),next_withdrawal:centsToIt(s.NextWithdrawalThresholdCents),steps:d?stepsView(d):[],day:d?{date:d.Date,theoretical_start:centsToIt(d.TheoreticalStartCents),real_start:centsToIt(d.RealStartCents),current_balance:centsToIt(d.CurrentBalanceCents),mode:d.Mode,stage:d.Stage,bet_label:ins.betLabel,bet_amount:centsToIt(ins.bet),target_label:ins.targetLabel,target_balance:ins.target?centsToIt(ins.target):'',status:ins.status}:null};
}
function addEvent(d,kind,balance,note=''){d.Events ||= [];d.Events.push({At:nowISO(),Kind:kind,BalanceCents:balance,Note:note})}

function applyTarget(s,d,balance){
  d.CurrentBalanceCents=balance; addEvent(d,'TARGET',balance,'');
  if(d.Mode==='RECOVERY_BASE'){
    const target=Number(d.OperationalBaseCents||d.RealStartCents);
    if(balance>=target){d.Mode='STANDARD';d.Stage=stageForBalance(target,balance);d.OperationalBaseCents=target}
    return;
  }
  if(d.Mode==='EMERGENCY'){
    if(balance>=Number(d.TheoreticalStartCents)){d.Mode='STANDARD';d.OperationalBaseCents=balance;d.Stage=0;d.EmergencyCycleBase=0;return}
    const base=Number(d.EmergencyCycleBase||balance), ts=emergencyTargets(base);let st=0;for(const x of ts)if(balance>=x)st++;else break;
    if(st>=4){d.EmergencyCycleBase=balance;d.Stage=0}else d.Stage=st;return;
  }
  const base=Number(d.OperationalBaseCents||d.RealStartCents);d.Stage=stageForBalance(base,balance);
}
function applyLoss(s,d,balance){
  d.CurrentBalanceCents=balance; addEvent(d,'LOSS',balance,'');
  const base=Number(d.OperationalBaseCents||d.RealStartCents), theo=Number(d.TheoreticalStartCents);
  if(balance>=base){d.Mode='STANDARD';d.Stage=stageForBalance(base,balance);d.EmergencyCycleBase=0;return}
  if(balance>=theo){d.Mode='RECOVERY_BASE';d.Stage=0;d.EmergencyCycleBase=0;return}
  d.Mode='EMERGENCY';d.EmergencyCycleBase=balance;d.Stage=0;
}
function startDay(s,date,balance){
  ensureCalendar(s); const cal=s.Calendar[date]; if(!cal)throw new Error('Calendario teorico non disponibile');
  const mode=balance<Number(cal.TheoreticalStartCents)?'EMERGENCY':'STANDARD';
  const d={Date:date,TheoreticalStartCents:Number(cal.TheoreticalStartCents),RealStartCents:balance,OperationalBaseCents:balance,CurrentBalanceCents:balance,Mode:mode,Stage:0,EmergencyCycleBase:mode==='EMERGENCY'?balance:0,ClosingBalanceCents:0,Closed:false,Events:[]};
  addEvent(d,'DAY_START',balance,'Saldo iniziale reale');s.Days ||= {};s.Days[date]=d;s.CurrentDay=date;return d;
}

function loginPage(err='') {return `<!doctype html><html lang="it"><head><meta name="viewport" content="width=device-width,initial-scale=1"><meta charset="utf-8"><title>AUTSYS BETTING</title><style>body{margin:0;background:#111316;color:#f4f6f8;font:16px Segoe UI,Arial;display:grid;place-items:center;min-height:100vh}.box{width:min(420px,calc(100% - 32px));background:#1a1e23;border:1px solid #343b44;border-radius:14px;padding:24px;box-sizing:border-box}h1{font-size:24px;margin:0 0 6px}p{color:#9ea8b3}input,button{width:100%;box-sizing:border-box;border-radius:9px;padding:13px;font-size:17px}input{background:#0f1114;color:white;border:1px solid #343b44}button{margin-top:12px;border:0;background:#49c976;color:#07140b;font-weight:800}.e{color:#ef6b6b;min-height:22px}</style></head><body><form class="box" method="post" action="/login"><h1>AUTSYS BETTING</h1><p>Accesso alla tua cassa BETTING online.</p><input type="password" name="password" placeholder="Password" autofocus required><div class="e">${err}</div><button>ENTRA</button></form></body></html>`}

app.get('/health',async(req,res)=>{try{await pool.query('SELECT 1');res.json({ok:true,service:'autsys-betting-web',version:VERSION,db:'postgres'})}catch(e){res.status(503).json({ok:false,error:e.message})}});
app.get('/login',(req,res)=>res.send(loginPage()));
app.post('/login',(req,res)=>{if(!safeEqual(req.body.password||'',APP_PASSWORD))return res.status(401).send(loginPage('Password non corretta'));res.cookie('autsys_betting',sessionToken(),{httpOnly:true,secure:true,sameSite:'strict',maxAge:30*24*3600*1000});res.redirect('/')});
app.post('/logout',(req,res)=>{res.clearCookie('autsys_betting');res.redirect('/login')});
app.get('/',(req,res)=>{if(!authed(req))return res.redirect('/login');res.send(INDEX_HTML)});
app.get('/manifest.webmanifest',(req,res)=>res.type('application/manifest+json').send(JSON.stringify({name:'AUTSYS BETTING',short_name:'BETTING',start_url:'/',display:'standalone',background_color:'#111316',theme_color:'#111316'})));
app.get('/api/state',requireAuth,async(req,res)=>{try{const s=await mutateState(x=>{ensureCalendar(x);return x});res.json(stateView(s))}catch(e){res.status(500).json({error:e.message})}});
app.get('/api/calendar',requireAuth,async(req,res)=>{try{const s=await readState();ensureCalendar(s);const today=todayISO();const [cy,cm]=today.split('-').map(Number);const months=[];const names=['GENNAIO','FEBBRAIO','MARZO','APRILE','MAGGIO','GIUGNO','LUGLIO','AGOSTO','SETTEMBRE','OTTOBRE','NOVEMBRE','DICEMBRE'];for(let off=0;off<2;off++){const dt=new Date(Date.UTC(cy,cm-1+off,1));const y=dt.getUTCFullYear(),m=dt.getUTCMonth()+1,days=new Date(Date.UTC(y,m,0)).getUTCDate(),arr=[];for(let day=1;day<=days;day++){const date=`${y}-${String(m).padStart(2,'0')}-${String(day).padStart(2,'0')}`,cal=s.Calendar?.[date],dr=s.Days?.[date];let dev='';if(cal&&dr?.Closed){const diff=Number(dr.ClosingBalanceCents)-Number(cal.TheoreticalTargetCents);dev=pctIt(diff/Number(cal.TheoreticalTargetCents)*100)}arr.push({day,date,has_value:!!cal,is_today:date===today,is_start_date:date===s.StartDate,start:cal?centsToIt(cal.TheoreticalStartCents):'',target:cal?centsToIt(cal.TheoreticalTargetCents):'',withdrawal:cal?.TheoreticalWithdrawalCents?centsToIt(cal.TheoreticalWithdrawalCents):'',real_close:dr?.Closed?centsToIt(dr.ClosingBalanceCents):'',deviation_percent:dev})}months.push({year:y,month:m,name:`${names[m-1]} ${y}`,days:arr})}res.json({months})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/event',requireAuth,async(req,res)=>{try{const kind=String(req.body.kind||'').toUpperCase();if(!['TARGET','LOSS'].includes(kind))throw new Error('Evento non valido');const bal=parseCents(req.body.balance);const s=await mutateState(x=>{const d=x.Days?.[x.CurrentDay];if(!d)throw new Error('Giornata non trovata');if(kind==='TARGET')applyTarget(x,d,bal);else applyLoss(x,d,bal);return x});res.json(stateView(s))}catch(e){res.status(400).json({error:e.message})}});
app.post('/api/newday',requireAuth,async(req,res)=>{try{const bal=parseCents(req.body.balance),today=todayISO();const s=await mutateState(x=>{ensureCalendar(x);const prev=x.Days?.[x.CurrentDay];if(prev&&!prev.Closed){prev.CurrentBalanceCents=bal;prev.ClosingBalanceCents=bal;prev.Closed=true;addEvent(prev,'DAY_CLOSE',bal,'')}startDay(x,today,bal);return x});res.json(stateView(s))}catch(e){res.status(400).json({error:e.message})}});
app.post('/api/withdraw',requireAuth,async(req,res)=>{try{const s=await mutateState(x=>{const d=x.Days?.[x.CurrentDay];if(!d)throw new Error('Giornata non trovata');const before=Number(d.CurrentBalanceCents);if(before<Number(x.NextWithdrawalThresholdCents))throw new Error('Soglia di prelievo non ancora raggiunta');const amount=5000,after=before-amount;x.PersonalBalanceCents=Number(x.PersonalBalanceCents)+amount;x.NextWithdrawalThresholdCents=after+10000;x.Withdrawals ||= [];x.Withdrawals.push({At:nowISO(),BeforeCents:before,AmountCents:amount,AfterCents:after,PersonalBalanceCents:x.PersonalBalanceCents,NextThresholdCents:x.NextWithdrawalThresholdCents});d.CurrentBalanceCents=after;d.OperationalBaseCents=after;d.Mode='STANDARD';d.Stage=0;d.EmergencyCycleBase=0;addEvent(d,'WITHDRAWAL',after,'Prelievo 50,00 € e reset ciclo');return x});res.json(stateView(s))}catch(e){res.status(400).json({error:e.message})}});

const __dirname=path.dirname(fileURLToPath(import.meta.url));
const INDEX_HTML=fs.readFileSync(path.join(__dirname,'index.html'),'utf8');

await initDb();
app.listen(PORT,'0.0.0.0',()=>console.log(`AUTSYS BETTING ${VERSION} online su porta ${PORT}`));
