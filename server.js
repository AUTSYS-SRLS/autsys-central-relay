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


async function initPersonalDb(){
  await pool.query(`
    CREATE TABLE IF NOT EXISTS personal_events(
      id bigserial PRIMARY KEY,
      occurred_at timestamptz NOT NULL DEFAULT now(),
      local_day date NOT NULL,
      event_type text NOT NULL,
      raw_text text NOT NULL,
      quantity_value numeric,
      quantity_unit text,
      calories_kcal numeric,
      protein_g numeric,
      carbohydrates_g numeric,
      sugars_g numeric,
      fats_g numeric,
      saturated_fats_g numeric,
      fiber_g numeric,
      sodium_mg numeric,
      alcohol_g numeric,
      dietary_triglycerides_estimated_g numeric,
      details jsonb NOT NULL DEFAULT '{}'::jsonb,
      is_estimated boolean NOT NULL DEFAULT true,
      needs_enrichment boolean NOT NULL DEFAULT false,
      created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS idx_personal_events_day ON personal_events(local_day);
    CREATE INDEX IF NOT EXISTS idx_personal_events_type ON personal_events(event_type);
    CREATE TABLE IF NOT EXISTS personal_migrations(
      migration_key text PRIMARY KEY,
      applied_at timestamptz NOT NULL DEFAULT now()
    );
  `);
}

async function seedPersonal20260921(){
  const rows=[
    ['2026-09-21T07:00:00+02:00','COFFEE','Caffe con un cucchiaino di zucchero',22,.3,5,5,0,0,0,0,0,0,'local-20260921-1',0],
    ['2026-09-21T08:00:00+02:00','COFFEE','Caffe con dolcificante',2,.3,0,0,0,0,0,0,0,0,'local-20260921-2',0],
    ['2026-09-21T09:30:00+02:00','COFFEE','Caffe con dolcificante',2,.3,0,0,0,0,0,0,0,0,'local-20260921-3',0],
    ['2026-09-21T14:44:00+02:00','FOOD',"Pranzo: 5 pomodori, 2 spicchi d'aglio, molto basilico, olio, sale, aceto di vino. Poi caffe con dolcificante.",216,6.5,26.4,16.2,11.3,1.6,7.8,427,0,10.17,'local-20260921-4',1],
    ['2026-09-21T15:25:00+02:00','COFFEE','Caffe con dolcificante',2,.3,0,0,0,0,0,0,0,0,'local-20260921-5',0],
    ['2026-09-21T21:05:00+02:00','FOOD',"Cena: insalata Trentina Bonduelle con un po di olio, sale e aceto di vino; una crocchetta di patate; un'orata al forno; caffe con dolcificante. Poi broccoli con un filo d'olio, aglio e un'acciughina.",662,57.7,35.1,8.1,32.9,6.0,12.1,1237,0,29.61,'local-20260921-6',1]
  ];
  for(const r of rows){
    const [at,type,raw,cal,prot,carb,sug,fat,sat,fiber,sodium,alcohol,trig,key,coffeesInside]=r;
    await pool.query(`
      INSERT INTO personal_events(
        occurred_at,local_day,event_type,raw_text,quantity_value,quantity_unit,
        calories_kcal,protein_g,carbohydrates_g,sugars_g,fats_g,saturated_fats_g,
        fiber_g,sodium_mg,alcohol_g,dietary_triglycerides_estimated_g,
        details,is_estimated,needs_enrichment
      )
      SELECT $1::timestamptz,'2026-09-21'::date,$2,$3,1,'evento',$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,
             jsonb_build_object('migration_key',$14::text,'source','DIETA.db','coffees_inside',$15::int),true,false
      WHERE NOT EXISTS (
        SELECT 1 FROM personal_events WHERE details->>'migration_key'=$14::text
      )
    `,[at,type,raw,cal,prot,carb,sug,fat,sat,fiber,sodium,alcohol,trig,key,coffeesInside]);
  }
  await pool.query(`
    INSERT INTO personal_events(occurred_at,local_day,event_type,raw_text,quantity_value,quantity_unit,details,is_estimated,needs_enrichment)
    SELECT '2026-09-21T23:59:00+02:00'::timestamptz,'2026-09-21'::date,'CIGARETTE',
           'Totale giornaliero sigarette comunicato a posteriori',40,'sigarette',
           jsonb_build_object('migration_key','local-20260921-cigarettes','source','manual_daily_total','timing','orari individuali non disponibili'),false,false
    WHERE NOT EXISTS (SELECT 1 FROM personal_events WHERE details->>'migration_key'='local-20260921-cigarettes')
  `);
  await pool.query(`
    INSERT INTO personal_events(occurred_at,local_day,event_type,raw_text,quantity_value,quantity_unit,details,is_estimated,needs_enrichment)
    SELECT '2026-09-21T21:00:00+02:00'::timestamptz,'2026-09-21'::date,'WEIGHT',
           'Peso vestito 105 kg; riferimento 102 kg con correzione -3 kg',102,'kg',
           jsonb_build_object('migration_key','local-20260921-weight','measured_dressed_kg',105,'reference_adjustment_kg',-3,'conditions','vestito'),false,false
    WHERE NOT EXISTS (SELECT 1 FROM personal_events WHERE details->>'migration_key'='local-20260921-weight')
  `);
}

const personalWords={una:1,uno:1,un:1,due:2,tre:3,quattro:4,cinque:5,sei:6,sette:7,otto:8,nove:9,dieci:10};
function personalFirstNumber(s,f=1){const m=s.match(/\b(\d+(?:[.,]\d+)?)\b/);if(m)return Number(m[1].replace(',','.'));for(const [w,n] of Object.entries(personalWords))if(new RegExp('\\b'+w+'\\b','i').test(s))return n;return f}
function personalTrig(e){if(e.fats_g!=null)e.dietary_triglycerides_estimated_g=Number(e.fats_g)*0.90;return e}
function parsePersonalEvent(raw){
  const s=String(raw||'').trim(),l=s.toLowerCase();if(!s)throw new Error('Frase vuota');
  const e={event_type:'NOTE',raw_text:s,quantity_value:null,quantity_unit:null,calories_kcal:null,protein_g:null,carbohydrates_g:null,sugars_g:null,fats_g:null,saturated_fats_g:null,fiber_g:null,sodium_mg:null,alcohol_g:null,dietary_triglycerides_estimated_g:null,details:{},is_estimated:false,needs_enrichment:false};

  // Personal intents with highest priority.
  if(/\bno\s*smoke\b|\bnosmoke\b|spruzz(?:o|ino)|spray/.test(l)){
    e.event_type='NOSMOKE';e.quantity_value=personalFirstNumber(l,1);e.quantity_unit='uso';e.details={product:'NoSmoke'};return e;
  }
  if(/sigarett|\bfumat[oa]\b|\bfumare\b/.test(l)){
    e.event_type='CIGARETTE';e.quantity_value=personalFirstNumber(l,1);e.quantity_unit='sigaretta';return e;
  }

  const wm=l.match(/peso[^\d]*(\d+(?:[.,]\d+)?)/);
  if(wm){
    const measured=Number(wm[1].replace(',','.')),dressed=/vestit/.test(l);
    e.event_type='WEIGHT';e.quantity_value=dressed?Math.max(0,measured-3):measured;e.quantity_unit='kg';
    e.details=dressed?{conditions:'vestito',measured_dressed_kg:measured,reference_adjustment_kg:-3}:{conditions:null};
    return e;
  }

  if(/caff[eè]/.test(l)){
    const q=personalFirstNumber(l,1);
    e.event_type='COFFEE';e.quantity_value=q;e.quantity_unit='tazzina';e.is_estimated=true;
    e.calories_kcal=2*q;e.protein_g=.3*q;e.carbohydrates_g=0;e.sugars_g=0;e.fats_g=0;
    if(/zuccher/.test(l)){e.calories_kcal=22*q;e.carbohydrates_g=5*q;e.sugars_g=5*q;e.details={sugar:'1 cucchiaino stimato per caffe'}}
    if(/dolcificant/.test(l))e.details={sweetener:true};
    return personalTrig(e);
  }

  let cal=0,prot=0,carb=0,sug=0,fat=0,sat=0,fib=0,sod=0,matched=false;
  const add=(a,b,c,d,f,g,h,i)=>{cal+=a;prot+=b;carb+=c;sug+=d;fat+=f;sat+=g;fib+=h;sod+=i;matched=true};
  if(/pomodor/.test(l)){const n=personalFirstNumber(l,1);add(22*n,1.1*n,4.8*n,3.2*n,.2*n,0,1.5*n,6*n)}
  if(/aglio/.test(l)){const n=personalFirstNumber(l,1);add(4.5*n,.2*n,1*n,.05*n,0,0,.05*n,.5*n)}
  if(/basilic/.test(l))add(2,.3,.3,0,.1,0,.2,0);
  if(/olio/.test(l)){const n=/filo/.test(l)?5:10;add(9*n,0,0,0,n,1.4*(n/10),0,0)}
  if(/aceto/.test(l))add(3,0,.1,.1,0,0,0,1);
  if(/crocchett/.test(l)){const n=personalFirstNumber(l,1);add(110*n,2*n,15*n,1*n,5*n,1*n,1*n,180*n)}
  if(/orata/.test(l))add(280,45,0,0,11,2.5,0,150);
  if(/broccol/.test(l))add(85,7,13,4,1,.2,8,80);
  if(/acciug/.test(l))add(8,1.2,0,0,.4,.1,0,370);
  if(/insalata/.test(l))add(35,2,6,3,.5,.1,3,60);

  // Unknown text must never become FOOD automatically.
  if(!matched){
    e.event_type='NOTE';e.quantity_value=1;e.quantity_unit='evento';
    e.details={parser:'personal_v2',classified:false};
    return e;
  }

  e.event_type='FOOD';e.quantity_value=1;e.quantity_unit='evento';e.is_estimated=true;
  e.calories_kcal=cal;e.protein_g=prot;e.carbohydrates_g=carb;e.sugars_g=sug;e.fats_g=fat;e.saturated_fats_g=sat;e.fiber_g=fib;e.sodium_mg=sod;e.alcohol_g=0;
  e.details={parser:'personal_v2',matched:true};
  return personalTrig(e);
}
async function insertPersonalEvent(raw){
  const e=parsePersonalEvent(raw);
  const q=`INSERT INTO personal_events(local_day,event_type,raw_text,quantity_value,quantity_unit,calories_kcal,protein_g,carbohydrates_g,sugars_g,fats_g,saturated_fats_g,fiber_g,sodium_mg,alcohol_g,dietary_triglycerides_estimated_g,details,is_estimated,needs_enrichment)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16::jsonb,$17,$18) RETURNING *`;
  const v=[todayISO(),e.event_type,e.raw_text,e.quantity_value,e.quantity_unit,e.calories_kcal,e.protein_g,e.carbohydrates_g,e.sugars_g,e.fats_g,e.saturated_fats_g,e.fiber_g,e.sodium_mg,e.alcohol_g,e.dietary_triglycerides_estimated_g,JSON.stringify(e.details),e.is_estimated,e.needs_enrichment];
  return (await pool.query(q,v)).rows[0];
}
async function replacePersonalEvent(id,raw){
  const current=(await pool.query('SELECT local_day FROM personal_events WHERE id=$1',[id])).rows[0];
  if(!current)throw new Error('Evento non trovato');
  const e=parsePersonalEvent(raw);
  const q=`UPDATE personal_events SET
    event_type=$2,raw_text=$3,quantity_value=$4,quantity_unit=$5,
    calories_kcal=$6,protein_g=$7,carbohydrates_g=$8,sugars_g=$9,fats_g=$10,saturated_fats_g=$11,
    fiber_g=$12,sodium_mg=$13,alcohol_g=$14,dietary_triglycerides_estimated_g=$15,
    details=$16::jsonb,is_estimated=$17,needs_enrichment=$18
    WHERE id=$1 RETURNING *`;
  const v=[id,e.event_type,e.raw_text,e.quantity_value,e.quantity_unit,e.calories_kcal,e.protein_g,e.carbohydrates_g,e.sugars_g,e.fats_g,e.saturated_fats_g,e.fiber_g,e.sodium_mg,e.alcohol_g,e.dietary_triglycerides_estimated_g,JSON.stringify({...e.details,edited:true}),e.is_estimated,e.needs_enrichment];
  return (await pool.query(q,v)).rows[0];
}
async function deletePersonalEvent(id){
  const r=await pool.query('DELETE FROM personal_events WHERE id=$1 RETURNING local_day::text AS day',[id]);
  if(!r.rowCount)throw new Error('Evento non trovato');
  return r.rows[0].day;
}

async function personalSummary(day=todayISO()){
  const totals=(await pool.query(`SELECT COALESCE(SUM(calories_kcal),0)::float calories,COALESCE(SUM(protein_g),0)::float protein,COALESCE(SUM(carbohydrates_g),0)::float carbs,COALESCE(SUM(sugars_g),0)::float sugars,COALESCE(SUM(fats_g),0)::float fats,COALESCE(SUM(saturated_fats_g),0)::float saturated,COALESCE(SUM(fiber_g),0)::float fiber,COALESCE(SUM(sodium_mg),0)::float sodium,COALESCE(SUM(alcohol_g),0)::float alcohol,COALESCE(SUM(dietary_triglycerides_estimated_g),0)::float triglycerides,(COUNT(*) FILTER (WHERE event_type='COFFEE') + COALESCE(SUM(CASE WHEN details ? 'coffees_inside' THEN (details->>'coffees_inside')::int ELSE 0 END),0))::int coffees,COALESCE(SUM(quantity_value) FILTER (WHERE event_type='CIGARETTE'),0)::float cigarettes,COALESCE(SUM(quantity_value) FILTER (WHERE event_type='NOSMOKE'),0)::float nosmoke,COUNT(*) FILTER (WHERE needs_enrichment)::int needs_enrichment FROM personal_events WHERE local_day=$1`,[day])).rows[0];
  const weight=(await pool.query(`SELECT quantity_value::float value,details FROM personal_events WHERE local_day=$1 AND event_type='WEIGHT' ORDER BY occurred_at DESC LIMIT 1`,[day])).rows[0]||null;
  const recent=(await pool.query(`SELECT id,event_type,raw_text,quantity_value,quantity_unit,occurred_at,needs_enrichment FROM personal_events WHERE local_day=$1 ORDER BY occurred_at DESC LIMIT 30`,[day])).rows;
  return {day,totals,weight,recent,version:'PERSONAL 0.2.0'};
}

async function migratePersonal20260922Exact(){
  const key='personal-20260922-exact-timeline-v1';
  const c=await pool.connect();
  try{
    await c.query('BEGIN');
    const done=await c.query('SELECT 1 FROM personal_migrations WHERE migration_key=$1 FOR UPDATE',[key]);
    if(done.rowCount){await c.query('COMMIT');return}

    // Remove only any provisional 22/09 smoking/NoSmoke rows, then write the exact user-supplied timeline.
    await c.query(`DELETE FROM personal_events
      WHERE local_day='2026-09-22'::date AND event_type IN ('CIGARETTE','NOSMOKE')`);

    const rows=[
      ['2026-09-22T00:05:00+02:00','CIGARETTE','Una sigaretta alle 00:05',1,'sigaretta',{}],
      ['2026-09-22T00:15:00+02:00','NOSMOKE','Uno spruzzo di NoSmoke alle 00:15',1,'uso',{product:'NoSmoke'}],
      ['2026-09-22T01:00:00+02:00','CIGARETTE','Una sigaretta alle 01:00',1,'sigaretta',{}],
      ['2026-09-22T01:15:00+02:00','NOSMOKE','Uno spruzzo di NoSmoke alle 01:15',1,'uso',{product:'NoSmoke'}],
      ['2026-09-22T01:45:00+02:00','CIGARETTE','Una sigaretta alle 01:45',1,'sigaretta',{}],
      ['2026-09-22T07:00:00+02:00','CIGARETTE','Una sigaretta alle 07:00',1,'sigaretta',{}],
      ['2026-09-22T07:15:00+02:00','NOSMOKE','Uno spruzzo di NoSmoke alle 07:15',1,'uso',{product:'NoSmoke'}]
    ];
    for(const [at,type,raw,q,unit,details] of rows){
      await c.query(`INSERT INTO personal_events(
        occurred_at,local_day,event_type,raw_text,quantity_value,quantity_unit,details,is_estimated,needs_enrichment
      ) VALUES($1::timestamptz,'2026-09-22'::date,$2,$3,$4,$5,$6::jsonb,false,false)`,
      [at,type,raw,q,unit,JSON.stringify({...details,source:'user_exact_timeline'})]);
    }
    await c.query('INSERT INTO personal_migrations(migration_key) VALUES($1)',[key]);
    await c.query('COMMIT');
  }catch(e){await c.query('ROLLBACK');throw e}finally{c.release()}
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


function personalLoginPage(err=''){return '<!doctype html><html lang="it"><head><meta name="viewport" content="width=device-width,initial-scale=1"><meta charset="utf-8"><title>PERSONAL</title><style>body{margin:0;background:#111316;color:#f4f6f8;font:16px system-ui;display:grid;place-items:center;min-height:100vh}.box{width:min(420px,calc(100% - 32px));background:#1a1e23;border:1px solid #343b44;border-radius:16px;padding:24px;box-sizing:border-box}h1{font-size:28px;margin:0 0 6px}p{color:#9ea8b3}input,button{width:100%;box-sizing:border-box;border-radius:10px;padding:14px;font-size:17px}input{background:#0f1114;color:white;border:1px solid #343b44}button{margin-top:12px;border:0;background:#49c976;color:#07140b;font-weight:800}.e{color:#ef6b6b;min-height:22px}</style></head><body><form class="box" method="post" action="/personal/login"><h1>PERSONAL</h1><p>Diario personale online.</p><input type="password" name="password" placeholder="Password" autofocus required><div class="e">'+err+'</div><button>ENTRA</button></form></body></html>'}

function loginPage(err='') {return `<!doctype html><html lang="it"><head><meta name="viewport" content="width=device-width,initial-scale=1"><meta charset="utf-8"><title>AUTSYS BETTING</title><style>body{margin:0;background:#111316;color:#f4f6f8;font:16px Segoe UI,Arial;display:grid;place-items:center;min-height:100vh}.box{width:min(420px,calc(100% - 32px));background:#1a1e23;border:1px solid #343b44;border-radius:14px;padding:24px;box-sizing:border-box}h1{font-size:24px;margin:0 0 6px}p{color:#9ea8b3}input,button{width:100%;box-sizing:border-box;border-radius:9px;padding:13px;font-size:17px}input{background:#0f1114;color:white;border:1px solid #343b44}button{margin-top:12px;border:0;background:#49c976;color:#07140b;font-weight:800}.e{color:#ef6b6b;min-height:22px}</style></head><body><form class="box" method="post" action="/login"><h1>AUTSYS BETTING</h1><p>Accesso alla tua cassa BETTING online.</p><input type="password" name="password" placeholder="Password" autofocus required><div class="e">${err}</div><button>ENTRA</button></form></body></html>`}

app.get('/health',async(req,res)=>{try{await pool.query('SELECT 1');res.json({ok:true,service:'autsys-betting-web',version:VERSION,db:'postgres'})}catch(e){res.status(503).json({ok:false,error:e.message})}});
app.get('/login',(req,res)=>res.send(loginPage()));
app.post('/login',(req,res)=>{if(!safeEqual(req.body.password||'',APP_PASSWORD))return res.status(401).send(loginPage('Password non corretta'));res.cookie('autsys_betting',sessionToken(),{httpOnly:true,secure:true,sameSite:'strict',maxAge:30*24*3600*1000});res.redirect('/')});
app.post('/logout',(req,res)=>{res.clearCookie('autsys_betting');res.redirect('/login')});
app.get('/',(req,res)=>{if(!authed(req))return res.redirect('/login');res.send(INDEX_HTML)});
app.get('/manifest.webmanifest',(req,res)=>res.type('application/manifest+json').send(JSON.stringify({name:'AUTSYS BETTING',short_name:'BETTING',start_url:'/',display:'standalone',background_color:'#111316',theme_color:'#111316'})));
app.get('/personal/login',(req,res)=>res.send(personalLoginPage()));
app.post('/personal/login',(req,res)=>{if(!safeEqual(req.body.password||'',APP_PASSWORD))return res.status(401).send(personalLoginPage('Password non corretta'));res.cookie('autsys_betting',sessionToken(),{httpOnly:true,secure:true,sameSite:'strict',maxAge:30*24*3600*1000});res.redirect('/personal')});
app.get('/personal',(req,res)=>{if(!authed(req))return res.redirect('/personal/login');res.send(PERSONAL_HTML)});
app.post('/personal/logout',(req,res)=>{res.clearCookie('autsys_betting');res.redirect('/personal/login')});
app.get('/personal-manifest.webmanifest',(req,res)=>res.type('application/manifest+json').send(JSON.stringify({name:'Guido Autelli - Personal',short_name:'PERSONAL',start_url:'/personal',display:'standalone',background_color:'#111316',theme_color:'#111316'})));
app.get('/api/personal/summary',requireAuth,async(req,res)=>{try{res.json(await personalSummary(String(req.query.day||todayISO())))}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/personal/say',requireAuth,async(req,res)=>{try{const event=await insertPersonalEvent(String(req.body.text||''));res.json({ok:true,event,summary:await personalSummary()})}catch(e){res.status(400).json({error:e.message})}});
app.put('/api/personal/events/:id',requireAuth,async(req,res)=>{try{
  const id=Number(req.params.id);if(!Number.isInteger(id)||id<=0)throw new Error('ID evento non valido');
  const event=await replacePersonalEvent(id,String(req.body.text||''));
  res.json({ok:true,event,summary:await personalSummary(String(event.local_day).slice(0,10))});
}catch(e){res.status(400).json({error:e.message})}});
app.delete('/api/personal/events/:id',requireAuth,async(req,res)=>{try{
  const id=Number(req.params.id);if(!Number.isInteger(id)||id<=0)throw new Error('ID evento non valido');
  const day=await deletePersonalEvent(id);
  res.json({ok:true,summary:await personalSummary(day)});
}catch(e){res.status(400).json({error:e.message})}});

app.get('/api/state',requireAuth,async(req,res)=>{try{const s=await mutateState(x=>{ensureCalendar(x);return x});res.json(stateView(s))}catch(e){res.status(500).json({error:e.message})}});
app.get('/api/calendar',requireAuth,async(req,res)=>{try{const s=await readState();ensureCalendar(s);const today=todayISO();const [cy,cm]=today.split('-').map(Number);const months=[];const names=['GENNAIO','FEBBRAIO','MARZO','APRILE','MAGGIO','GIUGNO','LUGLIO','AGOSTO','SETTEMBRE','OTTOBRE','NOVEMBRE','DICEMBRE'];for(let off=0;off<2;off++){const dt=new Date(Date.UTC(cy,cm-1+off,1));const y=dt.getUTCFullYear(),m=dt.getUTCMonth()+1,days=new Date(Date.UTC(y,m,0)).getUTCDate(),arr=[];for(let day=1;day<=days;day++){const date=`${y}-${String(m).padStart(2,'0')}-${String(day).padStart(2,'0')}`,cal=s.Calendar?.[date],dr=s.Days?.[date];let dev='';if(cal&&dr?.Closed){const diff=Number(dr.ClosingBalanceCents)-Number(cal.TheoreticalTargetCents);dev=pctIt(diff/Number(cal.TheoreticalTargetCents)*100)}arr.push({day,date,has_value:!!cal,is_today:date===today,is_start_date:date===s.StartDate,start:cal?centsToIt(cal.TheoreticalStartCents):'',target:cal?centsToIt(cal.TheoreticalTargetCents):'',withdrawal:cal?.TheoreticalWithdrawalCents?centsToIt(cal.TheoreticalWithdrawalCents):'',real_close:dr?.Closed?centsToIt(dr.ClosingBalanceCents):'',deviation_percent:dev})}months.push({year:y,month:m,name:`${names[m-1]} ${y}`,days:arr})}res.json({months})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/event',requireAuth,async(req,res)=>{try{const kind=String(req.body.kind||'').toUpperCase();if(!['TARGET','LOSS'].includes(kind))throw new Error('Evento non valido');const bal=parseCents(req.body.balance);const s=await mutateState(x=>{const d=x.Days?.[x.CurrentDay];if(!d)throw new Error('Giornata non trovata');if(kind==='TARGET')applyTarget(x,d,bal);else applyLoss(x,d,bal);return x});res.json(stateView(s))}catch(e){res.status(400).json({error:e.message})}});
app.post('/api/newday',requireAuth,async(req,res)=>{try{const bal=parseCents(req.body.balance),today=todayISO();const s=await mutateState(x=>{ensureCalendar(x);const prev=x.Days?.[x.CurrentDay];if(prev&&!prev.Closed){prev.CurrentBalanceCents=bal;prev.ClosingBalanceCents=bal;prev.Closed=true;addEvent(prev,'DAY_CLOSE',bal,'')}startDay(x,today,bal);return x});res.json(stateView(s))}catch(e){res.status(400).json({error:e.message})}});
app.post('/api/withdraw',requireAuth,async(req,res)=>{try{const s=await mutateState(x=>{const d=x.Days?.[x.CurrentDay];if(!d)throw new Error('Giornata non trovata');const before=Number(d.CurrentBalanceCents);if(before<Number(x.NextWithdrawalThresholdCents))throw new Error('Soglia di prelievo non ancora raggiunta');const amount=5000,after=before-amount;x.PersonalBalanceCents=Number(x.PersonalBalanceCents)+amount;x.NextWithdrawalThresholdCents=after+10000;x.Withdrawals ||= [];x.Withdrawals.push({At:nowISO(),BeforeCents:before,AmountCents:amount,AfterCents:after,PersonalBalanceCents:x.PersonalBalanceCents,NextThresholdCents:x.NextWithdrawalThresholdCents});d.CurrentBalanceCents=after;d.OperationalBaseCents=after;d.Mode='STANDARD';d.Stage=0;d.EmergencyCycleBase=0;addEvent(d,'WITHDRAWAL',after,'Prelievo 50,00 € e reset ciclo');return x});res.json(stateView(s))}catch(e){res.status(400).json({error:e.message})}});

const __dirname=path.dirname(fileURLToPath(import.meta.url));
const INDEX_HTML=fs.readFileSync(path.join(__dirname,'index.html'),'utf8');
const PERSONAL_HTML=fs.readFileSync(path.join(__dirname,'personal.html'),'utf8');

await initDb();
await initPersonalDb();
await migratePersonal20260922Exact();
app.listen(PORT,'0.0.0.0',()=>console.log(`AUTSYS BETTING ${VERSION} online su porta ${PORT}`));
