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
function nowISO(){return new Date().toISOString()}
function centsToIt(c){return (Number(c||0)/100).toLocaleString('it-IT',{minimumFractionDigits:2,maximumFractionDigits:2})}
function pctIt(v){return `${v>=0?'+':''}${Number(v||0).toLocaleString('it-IT',{minimumFractionDigits:2,maximumFractionDigits:2})}%`}
function withdrawalDate(w){return String(w?.Date||w?.At||'').slice(0,10)}
function actualWithdrawalsThrough(s,date){return (s.Withdrawals||[]).reduce((n,w)=>withdrawalDate(w)&&withdrawalDate(w)<=date?n+Number(w?.AmountCents||0):n,0)}
function theoreticalWithdrawalsThrough(s,date){return Object.entries(s.Calendar||{}).reduce((n,[d,v])=>d<=date?n+Number(v?.TheoreticalWithdrawalCents||0):n,0)}
function correctedDeviation(s){
  const dates=Object.keys(s.Days||{}).filter(d=>d<String(s.CurrentDay||'')&&s.Days?.[d]?.Closed).sort();
  const date=dates[dates.length-1]; if(!date)return null;
  const dr=s.Days?.[date],cal=s.Calendar?.[date]; if(!dr||!cal)return null;
  const real=Number(dr.ClosingBalanceCents||0)+actualWithdrawalsThrough(s,date);
  const theo=Number(cal.TheoreticalTargetCents||0)+theoreticalWithdrawalsThrough(s,date);
  const diff=real-theo,pct=theo?diff/theo*100:0;
  return {date,diff,pct};
}
function correctStateView(s,view){
  if(!view||typeof view!=='object')return view;
  view.version='WEB 1.0.0.2';
  const x=correctedDeviation(s);
  if(x){view.previous_deviation_amount=centsToIt(x.diff);view.previous_deviation_percent=pctIt(x.pct)}
  return view;
}
function correctCalendarView(s,payload){
  if(!payload?.months)return payload;
  for(const m of payload.months||[])for(const d of m.days||[]){
    const dr=s.Days?.[d.date],cal=s.Calendar?.[d.date];
    if(!dr?.Closed||!cal)continue;
    const real=Number(dr.ClosingBalanceCents||0)+actualWithdrawalsThrough(s,d.date);
    const theo=Number(cal.TheoreticalTargetCents||0)+theoreticalWithdrawalsThrough(s,d.date);
    d.deviation_percent=pctIt(theo?(real-theo)/theo*100:0);
  }
  return payload;
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

function actualWithdrawn(s){
  const hist=Array.isArray(s.Withdrawals)?s.Withdrawals.reduce((n,w)=>n+Math.max(0,Number(w?.AmountCents||0)),0):0;
  const inferred=Math.max(0,Number(s.PersonalBalanceCents||0)+Math.max(0,Number(s.InitialCapital||0)));
  return Math.max(hist,inferred);
}
function normalizeThreshold(s){
  s.Withdrawals ||= [];
  const tranches=Math.floor(actualWithdrawn(s)/5000);
  s.NextWithdrawalThresholdCents=20000+tranches*5000;
  return s;
}
async function normalizeCentral(){
  const c=await pool.connect();
  try{
    await c.query('BEGIN');
    const r=await c.query('SELECT data FROM betting_state WHERE id=1 FOR UPDATE');
    if(!r.rowCount)throw new Error('Stato centrale assente');
    const s=r.rows[0].data,before=Number(r.rows[0].data.NextWithdrawalThresholdCents||0);
    normalizeThreshold(s);
    if(before!==Number(s.NextWithdrawalThresholdCents)){
      s.LastSavedAt=nowISO();
      await c.query('UPDATE betting_state SET data=$1::jsonb,updated_at=now() WHERE id=1',[JSON.stringify(s)]);
    }
    await c.query('COMMIT');return s;
  }catch(e){await c.query('ROLLBACK');throw e}finally{c.release()}
}
function withdrawalPlan(balance,threshold){
  let after=Number(balance),next=Number(threshold),amount=0,tranches=0;
  while(after>=next&&tranches<10000){amount+=5000;after-=5000;next+=5000;tranches++}
  return {after,next,amount,tranches};
}
async function performWithdrawal(){
  const c=await pool.connect();
  try{
    await c.query('BEGIN');
    const r=await c.query('SELECT data FROM betting_state WHERE id=1 FOR UPDATE');
    if(!r.rowCount)throw new Error('Stato centrale assente');
    const s=r.rows[0].data;normalizeThreshold(s);
    const d=s.Days?.[s.CurrentDay];if(!d)throw new Error('Giornata non trovata');
    const before=Number(d.CurrentBalanceCents||0),plan=withdrawalPlan(before,Number(s.NextWithdrawalThresholdCents));
    if(plan.amount<=0)throw new Error('Soglia di prelievo non ancora raggiunta');
    s.PersonalBalanceCents=Number(s.PersonalBalanceCents||0)+plan.amount;
    s.NextWithdrawalThresholdCents=plan.next;
    s.Withdrawals.push({At:nowISO(),Date:s.CurrentDay,BeforeCents:before,AmountCents:plan.amount,AfterCents:plan.after,PersonalBalanceCents:s.PersonalBalanceCents,NextThresholdCents:plan.next});
    d.CurrentBalanceCents=plan.after;d.OperationalBaseCents=plan.after;d.Mode='STANDARD';d.Stage=0;d.EmergencyCycleBase=0;
    d.Events ||= [];d.Events.push({At:nowISO(),Kind:'WITHDRAWAL',BalanceCents:plan.after,Note:`Prelievo ${(plan.amount/100).toFixed(2)} EUR (${plan.tranches} soglie) e reset ciclo`});
    s.LastSavedAt=nowISO();
    await c.query('UPDATE betting_state SET data=$1::jsonb,updated_at=now() WHERE id=1',[JSON.stringify(s)]);
    await c.query('COMMIT');return s;
  }catch(e){await c.query('ROLLBACK');throw e}finally{c.release()}
}

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

const originalGet=express.application.get;
express.application.get=function(path,...handlers){
  if(path==='/api/state'&&handlers.length){
    const [auth,...rest]=handlers;
    return originalGet.call(this,path,auth,async(req,res,next)=>{
      try{
        const s=await normalizeCentral(),send=res.json.bind(res);
        res.json=(body)=>send(correctStateView(s,body));
        next();
      }catch(e){res.status(500).json({error:e.message})}
    },...rest);
  }
  if(path==='/api/calendar'&&handlers.length){
    const [auth,...rest]=handlers;
    return originalGet.call(this,path,auth,async(req,res,next)=>{
      try{
        const s=await normalizeCentral(),send=res.json.bind(res);
        res.json=(body)=>send(correctCalendarView(s,body));
        next();
      }catch(e){res.status(500).json({error:e.message})}
    },...rest);
  }
  return originalGet.call(this,path,...handlers);
};
const originalPost=express.application.post;
express.application.post=function(path,...handlers){
  if(path==='/api/withdraw'&&handlers.length){
    const [auth]=handlers;
    return originalPost.call(this,path,auth,async(req,res)=>{try{await performWithdrawal();res.json(await callLocal('/api/state'))}catch(e){res.status(400).json({error:e.message})}});
  }
  return originalPost.call(this,path,...handlers);
};

function install(app){
  app.get('/api/desktop/snapshot',desktopAuth,async(req,res)=>{
    try{await normalizeCentral();await callLocal('/api/state');res.json(await snapshot())}catch(e){res.status(e.status||500).json({error:e.message})}
  });
  app.get('/api/desktop/state',desktopAuth,async(req,res)=>{
    try{await normalizeCentral();const view=await callLocal('/api/state');res.json({view,snapshot:await snapshot()})}catch(e){res.status(e.status||500).json({error:e.message})}
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
