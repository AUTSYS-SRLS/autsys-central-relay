// Redis-backed relay mailbox. ACKs, deduplication and expiry are atomic.
export function createMessageStore(client,{prefix="autsys:relay-mailbox:v1:"}={}){
 const keys=(kind)=>({pending:prefix+kind+":pending",body:prefix+kind+":body",seen:prefix+kind+":seen"});
 const PUSH=`
local id=ARGV[1]
local now=tonumber(ARGV[2])
local expires=tonumber(ARGV[3])
local cap=tonumber(ARGV[4])
local scope=ARGV[5]
local body=ARGV[6]
local expired=redis.call('ZRANGEBYSCORE',KEYS[1],'-inf',now)
for _,x in ipairs(expired) do
 redis.call('ZREM',KEYS[1],x)
 redis.call('HDEL',KEYS[2],x)
end
redis.call('ZREMRANGEBYSCORE',KEYS[3],'-inf',now)
if redis.call('ZSCORE',KEYS[3],id) then
 if tonumber(redis.call('ZSCORE',KEYS[3],id))>now then return 'duplicate' end
 redis.call('ZREM',KEYS[3],id)
end
if tonumber(redis.call('ZCARD',KEYS[1]))>=cap then return 'full' end
if scope~='' then
 local all=redis.call('ZRANGE',KEYS[1],0,-1)
 local count=0
 for _,x in ipairs(all) do
  local raw=redis.call('HGET',KEYS[2],x)
  if raw then
   local ok,item=pcall(cjson.decode,raw)
   if ok and item.installation_id==scope then count=count+1 end
  end
 end
 if count>=tonumber(ARGV[7]) then return 'full' end
end
redis.call('HSET',KEYS[2],id,body)
redis.call('ZADD',KEYS[1],expires,id)
redis.call('ZADD',KEYS[3],expires,id)
return 'accepted'
`;
 const ACK=`
local removed=0
for _,id in ipairs(ARGV) do
 if redis.call('ZREM',KEYS[1],id)==1 then
  redis.call('HDEL',KEYS[2],id)
  removed=removed+1
 end
end
return removed
`;
 const LIST=`
local now=tonumber(ARGV[1])
local max=tonumber(ARGV[2])
local scope=ARGV[3]
local ids=redis.call('ZRANGE',KEYS[1],0,-1)
local result={}
for _,id in ipairs(ids) do
 local exp=tonumber(redis.call('ZSCORE',KEYS[1],id) or '0')
 if exp>now then
  local raw=redis.call('HGET',KEYS[2],id)
  if raw then
   if scope=='' then table.insert(result,raw)
   else
    local ok,item=pcall(cjson.decode,raw)
    if ok and item.installation_id==scope then table.insert(result,raw) end
   end
   if #result>=max then break end
  end
 end
end
return result
`;
 async function enqueue(kind,item,{id,scope="",max=5000,maxPerScope=500}){
  const k=keys(kind);
  return client.eval(PUSH,{keys:[k.pending,k.body,k.seen],arguments:[id,String(Math.floor(Date.now()/1000)),String(item.expires_at),String(max),scope,JSON.stringify(item),String(maxPerScope)]});
 }
 async function list(kind,{scope="",limit=100}={}){
  const k=keys(kind);const data=await client.eval(LIST,{keys:[k.pending,k.body],arguments:[String(Math.floor(Date.now()/1000)),String(limit),scope]});
  return data.map(x=>JSON.parse(x));
 }
 async function ack(kind,ids){const k=keys(kind);return client.eval(ACK,{keys:[k.pending,k.body],arguments:ids});}
 async function count(kind){const k=keys(kind);return client.zCount(k.pending,Math.floor(Date.now()/1000)+1,"+inf");}
 return {enqueue,list,ack,count};
}
