import crypto from 'crypto';
import express from 'express';
import pg from 'pg';

const { Pool } = pg;
const TOKEN = String(process.env.DESKTOP_SYNC_TOKEN || '');
const APP_SECRET = String(process.env.APP_SECRET || '');
const PORT = Number(process.env.PORT || 10000);

function safeEqual(a,b){
  const aa=Buffer.from(String(a)), bb=Buffer.from(String(b));
  return aa.length===bb.length && crypto.timingSafeEqual(aa,bb);
}
function desktopAuth(req,res,next){
  const h=String(req.get('authorization')||'');
  const token=h.startsWith('Bearer ')?h.slice(7).trim():'';
  if(!TOKEN || !safeEqual(token,TOKEN)) return res.status(401).json({error:'Desktop non autorizzato'});
  next();
}
function sessionCookie(){
  const value=crypto.createHmac('sha256',APP_SECRET).update('AUTSYS_BETTING_SESSION').digest('base64url');
  return `autsys_betting=${value}`;
}
const pool=new Pool({
  host:process.env.PGHOST,
  port:Number(process.env.PGPORT||5432),
  user:process.env.PGUSER,
  password:process.env.PGPASSWORD||undefined,
  database:process.env.PGDATABASE,
  ssl:false,
  max:2,
  idleTimeoutMillis:30000,
  connectionTimeoutMillis:10000,
});
async function snapshot(){
  const r=await pool.query('SELECT data FROM betting_state WHERE id=1');
  if(!r.rowCount) throw new Error('Stato centrale assente');
  return r.rows[0].data;
}
async function callLocal(path,method='GET',body=null){
  const headers={Cookie:sessionCookie()};
  if(body!==null) headers['Content-Type']='application/json';
  const r=await fetch(`http://127.0.0.1:${PORT}${path}`,{method,headers,body:body===null?undefined:JSON.stringify(body)});
  const text=await r.text();
  let data; try{data=JSON.parse(text)}catch{data={error:text||`HTTP ${r.status}`}}
  if(!r.ok){const e=new Error(data.error||`HTTP ${r.status}`);e.status=r.status;throw e}
  return data;
}
function install(app){
  app.get('/api/desktop/snapshot',desktopAuth,async(req,res)=>{
    try{await callLocal('/api/state');res.json(await snapshot())}catch(e){res.status(e.status||500).json({error:e.message})}
  });
  app.get('/api/desktop/state',desktopAuth,async(req,res)=>{
    try{const view=await callLocal('/api/state');res.json({view,snapshot:await snapshot()})}catch(e){res.status(e.status||500).json({error:e.message})}
  });
  app.get('/api/desktop/calendar',desktopAuth,async(req,res)=>{
    try{res.json(await callLocal('/api/calendar'))}catch(e){res.status(e.status||500).json({error:e.message})}
  });
  app.post('/api/desktop/event',desktopAuth,async(req,res)=>{
    try{const view=await callLocal('/api/event','POST',req.body);res.json({view,snapshot:await snapshot()})}catch(e){res.status(e.status||400).json({error:e.message})}
  });
  app.post('/api/desktop/newday',desktopAuth,async(req,res)=>{
    try{const view=await callLocal('/api/newday','POST',req.body);res.json({view,snapshot:await snapshot()})}catch(e){res.status(e.status||400).json({error:e.message})}
  });
  app.post('/api/desktop/withdraw',desktopAuth,async(req,res)=>{
    try{const view=await callLocal('/api/withdraw','POST',req.body||{});res.json({view,snapshot:await snapshot()})}catch(e){res.status(e.status||400).json({error:e.message})}
  });
}

const originalListen=express.application.listen;
express.application.listen=function(...args){install(this);return originalListen.apply(this,args)};
