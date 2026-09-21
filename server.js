import crypto from 'crypto';
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
const TZ = 'Europe/Rome';
const VERSION = 'PERSONAL WEB 0.1.0';
if (!APP_PASSWORD || !APP_SECRET) throw new Error('APP_PASSWORD/APP_SECRET mancanti');

const pool = new Pool({host:process.env.PGHOST,port:Number(process.env.PGPORT||5432),user:process.env.PGUSER,password:process.env.PGPASSWORD||undefined,database:process.env.PGDATABASE,ssl:false,max:5,idleTimeoutMillis:30000,connectionTimeoutMillis:10000});
app.set('trust proxy',1); app.disable('x-powered-by'); app.use(express.json({limit:'128kb'})); app.use(express.urlencoded({extended:false}));
app.use((req,res,next)=>{res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('X-Frame-Options','DENY');next();});

function safeEqual(a,b){const aa=Buffer.from(String(a)),bb=Buffer.from(String(b));return aa.length===bb.length&&crypto.timingSafeEqual(aa,bb)}
function sessionToken(){return crypto.createHmac('sha256',APP_SECRET).update('AUTSYS_PERSONAL_SESSION').digest('base64url')}
function cookies(req){const out={};for(const p of String(req.headers.cookie||'').split(';')){const i=p.indexOf('=');if(i>0)out[p.slice(0,i).trim()]=decodeURIComponent(p.slice(i+1).trim())}return out}
function authed(req){return safeEqual(cookies(req).autsys_personal||'',sessionToken())}
function requireAuth(req,res,next){if(!authed(req))return res.status(401).json({error:'Accesso richiesto'});next()}
function localDay(){const parts=new Intl.DateTimeFormat('en-CA',{timeZone:TZ,year:'numeric',month:'2-digit',day:'2-digit'}).formatToParts(new Date());const o=Object.fromEntries(parts.map(x=>[x.type,x.value]));return o.year+'-'+o.month+'-'+o.day}

async function initDb(){await pool.query("CREATE TABLE IF NOT EXISTS personal_events(id bigserial PRIMARY KEY,occurred_at timestamptz NOT NULL DEFAULT now(),local_day date NOT NULL,event_type text NOT NULL,raw_text text NOT NULL,quantity_value numeric,quantity_unit text,calories_kcal numeric,protein_g numeric,carbohydrates_g numeric,sugars_g numeric,fats_g numeric,saturated_fats_g numeric,fiber_g numeric,sodium_mg numeric,alcohol_g numeric,dietary_triglycerides_estimated_g numeric,details jsonb NOT NULL DEFAULT '{}'::jsonb,is_estimated boolean NOT NULL DEFAULT true,needs_enrichment boolean NOT NULL DEFAULT false,created_at timestamptz NOT NULL DEFAULT now()); CREATE INDEX IF NOT EXISTS idx_personal_events_day ON personal_events(local_day); CREATE INDEX IF NOT EXISTS idx_personal_events_type ON personal_events(event_type);")}

const words={una:1,uno:1,un:1,due:2,tre:3,quattro:4,cinque:5,sei:6,sette:7,otto:8,nove:9,dieci:10};
function firstNumber(s,f=1){const m=s.match(/\b(\d+(?:[.,]\d+)?)\b/);if(m)return Number(m[1].replace(',','.'));for(const [w,n] of Object.entries(words))if(new RegExp('\\b'+w+'\\b','i').test(s))return n;return f}
function trig(e){if(e.fats_g!=null)e.dietary_triglycerides_estimated_g=Number(e.fats_g)*0.90;return e}
function parseEvent(raw){
 const s=String(raw||'').trim(),l=s.toLowerCase(); if(!s)throw new Error('Frase vuota');
 const e={event_type:'NOTE',raw_text:s,quantity_value:null,quantity_unit:null,calories_kcal:null,protein_g:null,carbohydrates_g:null,sugars_g:null,fats_g:null,saturated_fats_g:null,fiber_g:null,sodium_mg:null,alcohol_g:null,dietary_triglycerides_estimated_g:null,details:{},is_estimated:true,needs_enrichment:false};
 if(/sigarett|fumato|fumare/.test(l)){e.event_type='CIGARETTE';e.quantity_value=firstNumber(l,1);e.quantity_unit='sigaretta';return e}
 if(/nosmoke|spruzzino|spray/.test(l)){e.event_type='NOSMOKE';e.quantity_value=firstNumber(l,1);e.quantity_unit='uso';return e}
 const wm=l.match(/peso[^\d]*(\d+(?:[.,]\d+)?)/); if(wm){e.event_type='WEIGHT';e.quantity_value=Number(wm[1].replace(',','.'));e.quantity_unit='kg';e.details={conditions:/vestit/.test(l)?'vestito':null};return e}
 if(/caff[eè]/.test(l)){e.event_type='COFFEE';e.quantity_value=1;e.quantity_unit='tazzina';e.calories_kcal=2;e.protein_g=.3;e.carbohydrates_g=0;e.sugars_g=0;e.fats_g=0;if(/zuccher/.test(l)){e.calories_kcal=22;e.carbohydrates_g=5;e.sugars_g=5;e.details={sugar:'1 cucchiaino stimato'}}if(/dolcificant/.test(l))e.details={sweetener:true};return trig(e)}
 e.event_type='FOOD';e.quantity_value=1;e.quantity_unit='evento';
 let cal=0,prot=0,carb=0,sug=0,fat=0,sat=0,fib=0,sod=0,matched=false;
 const add=(a,b,c,d,f,g,h,i)=>{cal+=a;prot+=b;carb+=c;sug+=d;fat+=f;sat+=g;fib+=h;sod+=i;matched=true};
 if(/pomodor/.test(l)){const n=firstNumber(l,1);add(22*n,1.1*n,4.8*n,3.2*n,.2*n,0,1.5*n,6*n)}
 if(/aglio/.test(l)){const n=firstNumber(l,1);add(4.5*n,.2*n,1*n,.05*n,0,0,.05*n,.5*n)}
 if(/basilic/.test(l))add(2,.3,.3,0,.1,0,.2,0);
 if(/olio/.test(l)){const n=/filo/.test(l)?5:10;add(9*n,0,0,0,n,1.4*(n/10),0,0)}
 if(/aceto/.test(l))add(3,0,.1,.1,0,0,0,1);
 if(/crocchett/.test(l)){const n=firstNumber(l,1);add(110*n,2*n,15*n,1*n,5*n,1*n,1*n,180*n)}
 if(/orata/.test(l))add(280,45,0,0,11,2.5,0,150);
 if(/broccol/.test(l))add(85,7,13,4,1,.2,8,80);
 if(/acciug/.test(l))add(8,1.2,0,0,.4,.1,0,370);
 if(/insalata/.test(l))add(35,2,6,3,.5,.1,3,60);
 e.calories_kcal=matched?cal:null;e.protein_g=matched?prot:null;e.carbohydrates_g=matched?carb:null;e.sugars_g=matched?sug:null;e.fats_g=matched?fat:null;e.saturated_fats_g=matched?sat:null;e.fiber_g=matched?fib:null;e.sodium_mg=matched?sod:null;e.alcohol_g=0;e.needs_enrichment=!matched;e.details={parser:'local_v1',matched};return trig(e)
}

async function insertParsed(raw){const e=parseEvent(raw);const q='INSERT INTO personal_events(local_day,event_type,raw_text,quantity_value,quantity_unit,calories_kcal,protein_g,carbohydrates_g,sugars_g,fats_g,saturated_fats_g,fiber_g,sodium_mg,alcohol_g,dietary_triglycerides_estimated_g,details,is_estimated,needs_enrichment) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16::jsonb,$17,$18) RETURNING *';const v=[localDay(),e.event_type,e.raw_text,e.quantity_value,e.quantity_unit,e.calories_kcal,e.protein_g,e.carbohydrates_g,e.sugars_g,e.fats_g,e.saturated_fats_g,e.fiber_g,e.sodium_mg,e.alcohol_g,e.dietary_triglycerides_estimated_g,JSON.stringify(e.details),e.is_estimated,e.needs_enrichment];return (await pool.query(q,v)).rows[0]}
async function summary(day=localDay()){const totals=(await pool.query("SELECT COALESCE(SUM(calories_kcal),0)::float calories,COALESCE(SUM(protein_g),0)::float protein,COALESCE(SUM(carbohydrates_g),0)::float carbs,COALESCE(SUM(sugars_g),0)::float sugars,COALESCE(SUM(fats_g),0)::float fats,COALESCE(SUM(saturated_fats_g),0)::float saturated,COALESCE(SUM(fiber_g),0)::float fiber,COALESCE(SUM(sodium_mg),0)::float sodium,COALESCE(SUM(alcohol_g),0)::float alcohol,COALESCE(SUM(dietary_triglycerides_estimated_g),0)::float triglycerides,COUNT(*) FILTER (WHERE event_type='COFFEE')::int coffees,COALESCE(SUM(quantity_value) FILTER (WHERE event_type='CIGARETTE'),0)::float cigarettes,COALESCE(SUM(quantity_value) FILTER (WHERE event_type='NOSMOKE'),0)::float nosmoke,COUNT(*) FILTER (WHERE needs_enrichment)::int needs_enrichment FROM personal_events WHERE local_day=$1",[day])).rows[0];const weight=(await pool.query("SELECT quantity_value::float value,details FROM personal_events WHERE local_day=$1 AND event_type='WEIGHT' ORDER BY occurred_at DESC LIMIT 1",[day])).rows[0]||null;const recent=(await pool.query("SELECT id,event_type,raw_text,quantity_value,quantity_unit,occurred_at,needs_enrichment FROM personal_events WHERE local_day=$1 ORDER BY occurred_at DESC LIMIT 20",[day])).rows;return {day,totals,weight,recent,version:VERSION}}

function loginPage(err=''){return '<!doctype html><html lang="it"><head><meta name="viewport" content="width=device-width,initial-scale=1"><meta charset="utf-8"><title>PERSONAL</title><style>body{margin:0;background:#111316;color:#f4f6f8;font:16px system-ui;display:grid;place-items:center;min-height:100vh}.box{width:min(420px,calc(100% - 32px));background:#1a1e23;border:1px solid #343b44;border-radius:16px;padding:24px;box-sizing:border-box}input,button{width:100%;box-sizing:border-box;border-radius:10px;padding:14px;font-size:17px}input{background:#0f1114;color:white;border:1px solid #343b44}button{margin-top:12px;border:0;background:#49c976;color:#07140b;font-weight:800}.e{color:#ef6b6b;min-height:22px}</style></head><body><form class="box" method="post" action="/login"><h1>PERSONAL</h1><p>Diario personale online.</p><input type="password" name="password" placeholder="Password" autofocus required><div class="e">'+err+'</div><button>ENTRA</button></form></body></html>'}

app.get('/health',async(req,res)=>{try{await pool.query('SELECT 1');res.json({ok:true,service:'autsys-personal',version:VERSION,db:'postgres'})}catch(e){res.status(503).json({ok:false,error:e.message})}});
app.get('/login',(req,res)=>res.send(loginPage()));
app.post('/login',(req,res)=>{if(!safeEqual(req.body.password||'',APP_PASSWORD))return res.status(401).send(loginPage('Password non corretta'));res.cookie('autsys_personal',sessionToken(),{httpOnly:true,secure:true,sameSite:'strict',maxAge:30*24*3600*1000});res.redirect('/')});
app.post('/logout',(req,res)=>{res.clearCookie('autsys_personal');res.redirect('/login')});
app.get('/',(req,res)=>{if(!authed(req))return res.redirect('/login');res.send(INDEX_HTML)});
app.get('/manifest.webmanifest',(req,res)=>res.type('application/manifest+json').send(JSON.stringify({name:'Guido Autelli - Personal',short_name:'PERSONAL',start_url:'/',display:'standalone',background_color:'#111316',theme_color:'#111316'})));
app.get('/api/summary',requireAuth,async(req,res)=>{try{res.json(await summary(String(req.query.day||localDay())))}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/say',requireAuth,async(req,res)=>{try{const event=await insertParsed(String(req.body.text||''));res.json({ok:true,event,summary:await summary()})}catch(e){res.status(400).json({error:e.message})}});
const __dirname=path.dirname(fileURLToPath(import.meta.url)); const INDEX_HTML=fs.readFileSync(path.join(__dirname,'index.html'),'utf8');
await initDb(); app.listen(PORT,'0.0.0.0',()=>console.log('AUTSYS PERSONAL '+VERSION+' online su porta '+PORT));