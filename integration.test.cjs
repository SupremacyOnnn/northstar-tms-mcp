// Isolated integration tests: real HTTP/OAuth/MCP/REST code, fixture database only.
// All credentials are ephemeral test data in memory; no .env or real DB is read/written.
const test = require('node:test');
const crypto = require('node:crypto');
const {once} = require('node:events');
const path = require('node:path');
const {pathToFileURL} = require('node:url');
const nativeFetch = global.fetch;
const http = require('node:http');
// Node's fetch ignores an overridden Host header. Use real HTTP for proxy fixtures.
function proxyFetch(url, init = {}) {
  return new Promise((resolve, reject) => {
    const headers = Object.fromEntries(new Headers(init.headers));
    const request = http.request(url, {method:init.method || 'GET', headers, signal:init.signal}, response => {
      const chunks=[];
      response.on('data',chunk=>chunks.push(chunk));
      response.on('error',()=>reject(new Error('Fixture response failed')));
      response.on('end',()=>{
        const resultHeaders=new Headers();
        for(let i=0;i<response.rawHeaders.length;i+=2) resultHeaders.append(response.rawHeaders[i],response.rawHeaders[i+1]);
        resolve(new Response([204,304].includes(response.statusCode) ? null : Buffer.concat(chunks), {status:response.statusCode,headers:resultHeaders}));
      });
    });
    request.on('error',()=>reject(new Error('Fixture HTTP request failed')));
    if(init.body) request.write(init.body.toString());
    request.end();
  });
}
function expect(ok, label) { if (!ok) throw new Error(label); }

test('ChatGPT OAuth, MCP, REST and tenant isolation', async t => {
  const issuer = 'https://oauth.example.test';
  const resource = 'https://mcp.example.test/mcp';
  const callback = 'https://client.example.test/callback'; // Fixture only; never registered in production.
  const jwtSecret = crypto.randomBytes(32).toString('hex');
  const introspectionSecret = crypto.randomBytes(32).toString('hex');
  const {privateKey} = crypto.generateKeyPairSync('rsa', {modulusLength: 2048});
  const jwk = {...privateKey.export({format:'jwk'}), kid:'fixture-key', use:'sig', alg:'RS256'};
  const savedEnv = {...process.env};
  for (const key of ['OAUTH_STORAGE_DATABASE_URL','DOTENV_CONFIG_PATH','DEBUG','NODE_TLS_REJECT_UNAUTHORIZED']) delete process.env[key];
  Object.assign(process.env, {
    NODE_ENV:'production', RENDER:'true', DATABASE_URL:'postgresql://fixture:fixture@invalid/fixture',
    DOTENV_CONFIG_PATH:path.join(require('node:os').tmpdir(), `${crypto.randomUUID()}.no-env`),
    OAUTH_ISSUER:issuer, MCP_RESOURCE:resource, OAUTH_INTROSPECTION_URL:`${issuer}/token/introspection`,
    OAUTH_CLIENT_ID:'northstar-mcp-backend', OAUTH_CLIENT_SECRET:introspectionSecret,
    MCP_INTROSPECTION_SECRET:introspectionSecret, JWT_SECRET:jwtSecret,
    OAUTH_JWKS_JSON:JSON.stringify({keys:[jwk]}),
    CHATGPT_CLIENT_ID:'fixture-chatgpt', CHATGPT_REDIRECT_URIS:callback
  });
  const storage = new Map();
  const bcrypt = require('./oauth-server/node_modules/bcrypt');
  const password = crypto.randomBytes(24).toString('hex');
  const passwordHash = await bcrypt.hash(password, 4);
  const owners = {'NS-A-001':'user-a', 'NS-B-001':'user-b'};
  const calls = [];
  async function query(sql, values = []) {
    if (sql.includes('oidc_adapter_store')) {
      const [model, id] = values, key = `${model}:${id}`;
      if (/^INSERT/.test(sql)) { storage.set(key, {payload:JSON.parse(JSON.stringify(values[2])), expires:values[3]}); return {rows:[]}; }
      if (/^UPDATE/.test(sql)) { const row=storage.get(key); if(row) row.payload.consumed=Math.floor(Date.now()/1000); return {rows:[]}; }
      if (/^DELETE/.test(sql)) {
        if (sql.includes('grant_id')) for(const [k,row] of storage) { if(row.payload.grantId===values[0]) storage.delete(k); }
        else storage.delete(key);
        return {rows:[]};
      }
      const field = sql.includes('WHERE model=$1 AND uid=$2') ? 'uid' : sql.includes('WHERE model=$1 AND user_code=$2') ? 'userCode' : null;
      const row = field ? [...storage].find(([k,r]) => k.startsWith(`${model}:`) && r.payload[field] === id)?.[1] : storage.get(key);
      return {rows:row && (!row.expires || row.expires > new Date()) ? [{payload:JSON.parse(JSON.stringify(row.payload))}] : []};
    }
    if (sql.includes('public.users')) return {rows: ['user-a','user-b'].includes(values[0]) ? [{id:values[0],display_name:'Fixture user',role:'customer',active:true,allowed:true,tenant_allowed:true,password_hash:passwordHash}] : []};
    if (sql.includes('demo_can_view_load')) { calls.push(['authorization',...values]); return {rows:[{allowed:owners[values[1]] === values[0]}]}; }
    if (sql.includes('public.load_events')) { calls.push(['events',values[0]]); return {rows:[{id:1,load_id:values[0],event_type:'fixture-event'}]}; }
    if (sql.includes('public.loads')) { calls.push(['status',values[0]]); return {rows:[{load_id:values[0],status:'In transit'}]}; }
    throw new Error('Unexpected fixture query');
  }
  const pools = ['./oauth-server/node_modules/pg','./mcp-server/node_modules/pg','./legacy-api/node_modules/pg'].map(p => require(p).Pool);
  const originals = pools.map(Pool => Pool.prototype.query);
  pools.forEach(Pool => { Pool.prototype.query = query; });
  const servers=[];
  t.after(async () => {
    global.fetch=nativeFetch;
    for (const server of servers) await new Promise(resolve=>server.close(resolve));
    pools.forEach((Pool,i)=>{Pool.prototype.query=originals[i];});
    for (const key of Object.keys(process.env)) if (!(key in savedEnv)) delete process.env[key];
    Object.assign(process.env,savedEnv);
  });
  async function listen(app) { const server=app.listen(0,'127.0.0.1'); servers.push(server); await once(server,'listening'); return `http://127.0.0.1:${server.address().port}`; }
  const {app:oauthApp} = await import(pathToFileURL(path.join(__dirname,'oauth-server/server.js')));
  const {app:restApp} = require('./legacy-api/server.js');
  const {app:mcpApp} = require('./mcp-server/server.js');
  const oauthBase=await listen(oauthApp),restBase=await listen(restApp),mcpBase=await listen(mcpApp);
  const mapped = {[issuer]:oauthBase, 'https://rest.example.test':restBase, 'https://mcp.example.test':mcpBase};
  global.fetch = async (input,init={}) => {
    const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
    if (!mapped[url.origin]) throw new Error('Test attempted an external request');
    const headers = new Headers(init.headers);
    headers.set('host',url.host); headers.set('x-forwarded-proto','https');
    return proxyFetch(`${mapped[url.origin]}${url.pathname}${url.search}`, {...init,headers});
  };
  const get = (url,init={}) => global.fetch(url,{...init,redirect:'manual'});
  let discovery;
  await t.test('OAuth discovery, public JWKS and protected-resource discovery',async()=>{
    const response=await get(`${issuer}/.well-known/openid-configuration`);
    expect(response.status===200,'OAuth discovery failed'); discovery=await response.json();
    expect(discovery.issuer===issuer && discovery.authorization_endpoint.startsWith(issuer) && discovery.token_endpoint.startsWith(issuer),'Discovery endpoint or issuer mismatch');
    expect(discovery.code_challenge_methods_supported.includes('S256') && discovery.token_endpoint_auth_methods_supported.includes('none'),'PKCE public client not supported');
    const jwks=await (await get(discovery.jwks_uri)).json();
    expect(jwks.keys.length>0 && jwks.keys.every(k=>!k.d && !k.p && !k.k),'Private key exposed');
    for (const suffix of ['','/mcp']) {
      const response=await get(`https://mcp.example.test/.well-known/oauth-protected-resource${suffix}`);
      const metadata=await response.json();
      expect(response.status===200 && metadata.resource===resource && metadata.authorization_servers[0]===issuer && metadata.scopes_supported.includes('northstar:loads:read'),'Protected resource metadata mismatch');
    }
  });
  await t.test('Render HTTPS enforcement, host validation and secure cookies',async()=>{
    const plain=await nativeFetch(`${oauthBase}/.well-known/openid-configuration`,{headers:{host:'oauth.example.test'}});
    expect(plain.status===400,'Plain HTTP accepted');
    const ambiguous=await nativeFetch(`${oauthBase}/.well-known/openid-configuration`,{headers:{host:'oauth.example.test','x-forwarded-proto':'https, http'}});
    expect(ambiguous.status===400,'Ambiguous proxy protocol accepted');
    const badHost=await nativeFetch(`${oauthBase}/.well-known/openid-configuration`,{headers:{host:'evil.example.test','x-forwarded-proto':'https'}});
    expect(badHost.status===400,'Unexpected host accepted');
    const forwardedHost=await get(`${issuer}/.well-known/openid-configuration`,{headers:{'x-forwarded-host':'evil.example.test'}});
    expect((await forwardedHost.json()).issuer===issuer,'Forwarded host changed discovery');
    const {configureTransport}=require('./oauth-server/transport.cjs');
    const app=require('./mcp-server/node_modules/express')();
    configureTransport(app,'https://direct.example.test',{NODE_ENV:'production'}); app.get('/probe',(req,res)=>res.sendStatus(200));
    const base=await listen(app);
    expect((await nativeFetch(`${base}/probe`,{headers:{host:'direct.example.test','x-forwarded-proto':'https'}})).status===400,'Untrusted forwarded headers accepted');
  });
  await t.test('MCP authentication challenges and missing/invalid credentials',async()=>{
    for (const method of ['GET','POST']) {
      const response=await get(resource,{method});
      expect(response.status===401 && response.headers.get('www-authenticate')?.includes('resource_metadata="https://mcp.example.test/.well-known/oauth-protected-resource/mcp"'),'Missing authentication challenge');
    }
    const response=await get(resource,{method:'POST',headers:{authorization:'Bearer fixture-invalid'}});
    expect(response.status===401 && response.headers.get('www-authenticate')?.includes('error="invalid_token"'),'Invalid token accepted or missing challenge');
  });
  async function login(account, replayCheck = false) {
    const jar=new Map();
    async function request(url,init={}) {
      const headers=new Headers(init.headers); if(jar.size) headers.set('cookie',[...jar].map(([k,v])=>`${k}=${v}`).join('; '));
      const response=await get(new URL(url,issuer),{...init,headers});
      for(const cookie of response.headers.getSetCookie()) { const pair=cookie.split(';')[0]; const index=pair.indexOf('='); jar.set(pair.slice(0,index),pair.slice(index+1)); expect(/; secure/i.test(cookie) && /; httponly/i.test(cookie),'OAuth cookie security weakened'); }
      return response;
    }
    const verifier=crypto.randomBytes(32).toString('base64url'),state=crypto.randomBytes(16).toString('hex');
    const authorization=new URL(discovery.authorization_endpoint);
    const params={client_id:'fixture-chatgpt',redirect_uri:callback,response_type:'code',scope:'openid northstar:loads:read',resource,code_challenge:crypto.createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256',state};
    authorization.search=new URLSearchParams(params);
    let response=await request(authorization);
    for(let step=0;step<15;step++) {
      if(response.status>=300 && response.status<400) {
        const location=new URL(response.headers.get('location'),issuer);
        if(location.origin===new URL(callback).origin) {
          expect(location.searchParams.get('state')===state && Boolean(location.searchParams.get('code')) && !location.searchParams.has('error'),'OAuth callback failed');
          const code=location.searchParams.get('code');
          const exchange={grant_type:'authorization_code',client_id:'fixture-chatgpt',code,redirect_uri:callback,code_verifier:verifier,resource};
          const tokenResponse=await request(discovery.token_endpoint,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams(exchange)});
          expect(tokenResponse.status===200,'PKCE token exchange failed');
          const tokens=await tokenResponse.json(); expect(Boolean(tokens.access_token),'Access token missing');
          if (replayCheck) {
            const replay=await request(discovery.token_endpoint,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams(exchange)});
            expect(replay.status===400,'Authorization code replay accepted');
          }
          return tokens.access_token;
        }
        response=await request(location);
      } else {
        expect(response.status===200,'OAuth interaction page failed');
        const html=await response.text(),csrf=html.match(/name="_csrf"\s+value="([a-f0-9]+)"/);
        expect(Boolean(csrf),'CSRF form missing');
        const action=html.match(/action="([^"]+)"/);
        expect(Boolean(action),'Interaction action missing');
        const isLogin=action[1].endsWith('/login');
        const form=isLogin?{user_id:account,password,_csrf:csrf[1]}:{decision:'allow',_csrf:csrf[1]};
        if (replayCheck) {
          const invalid=await request(action[1],{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({...form,_csrf:'invalid'})});
          expect(invalid.status===403,'Invalid CSRF accepted');
        }
        response=await request(action[1],{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams(form)});
      }
    }
    throw new Error('OAuth flow did not finish');
  }
  let tokenA,tokenB;
  await t.test('Separate ChatGPT client: PKCE login, consent, CSRF and code replay protection',async()=>{
    await login('user-a', true); // Replaying a code intentionally revokes its associated tokens.
    tokenA=await login('user-a'); tokenB=await login('user-b');
  });
  await t.test('Unregistered callback and missing PKCE rejected',async()=>{
    for(const extra of [{redirect_uri:'https://unregistered.example.test/callback',code_challenge:'fixture',code_challenge_method:'S256'},{}]) {
      const url=new URL(discovery.authorization_endpoint); url.search=new URLSearchParams({client_id:'fixture-chatgpt',redirect_uri:callback,response_type:'code',scope:'openid',...extra});
      const response=await get(url);
      expect(response.status===400 || (response.status===303 && response.headers.get('location')?.includes('error=')),'Unsafe authorization request accepted');
    }
  });
  await t.test('Expired, wrong-audience and insufficient-scope tokens rejected',async()=>{
    expect(Boolean(tokenA),'Valid fixture token unavailable');
    const entries=[...storage].filter(([key])=>key.startsWith('AccessToken:'));
    expect(entries.length>0,'Fixture access tokens missing');
    for(const invalidate of [row=>{row.expires=new Date(0);},row=>{row.payload.aud='https://other.example.test/mcp';},row=>{row.payload.scope='openid';}]) {
      const saved=entries.map(([key,row])=>[key,{payload:structuredClone(row.payload),expires:row.expires}]);
      try {
        for(const [,row] of entries)invalidate(row);
        const response=await get(resource,{method:'POST',headers:{authorization:`Bearer ${tokenA}`}});
        expect(response.status===401 && response.headers.has('www-authenticate'),'Invalid token attributes accepted');
      } finally {
        for(const [key,row] of saved)Object.assign(storage.get(key),row);
      }
    }
  });
  await t.test('REST rejects invalid internal JWTs',async()=>{
    const response=await get('https://rest.example.test/api/v1/loads/NS-A-001/events',{headers:{authorization:'Bearer invalid-fixture'}});
    expect(response.status===401,'Invalid internal JWT accepted');
  });
  await t.test('Real MCP tool calls and REST tenant authorization for both tenants',async()=>{
    expect(Boolean(tokenA && tokenB),'Valid OAuth tokens unavailable');
    const {Client}=require('./mcp-server/node_modules/@modelcontextprotocol/sdk/dist/cjs/client/index.js');
    const {StreamableHTTPClientTransport}=require('./mcp-server/node_modules/@modelcontextprotocol/sdk/dist/cjs/client/streamableHttp.js');
    for(const [token,own,other] of [[tokenA,'NS-A-001','NS-B-001'],[tokenB,'NS-B-001','NS-A-001']]) {
      const client=new Client({name:'isolated-test',version:'1.0.0'});
      try {
        await client.connect(new StreamableHTTPClientTransport(new URL(resource),{requestInit:{headers:{authorization:`Bearer ${token}`}}}));
        const tools=await client.listTools(); expect(tools.tools.length===2,'Unexpected tool list');
        for(const name of ['get_load_status','get_load_events']) {
          const allowed=await client.callTool({name,arguments:{load_id:own}}); expect(!allowed.isError,'Authorized tool call failed');
          const before=calls.filter(c=>c[0]=== (name==='get_load_events'?'events':'status')).length;
          const denied=await client.callTool({name,arguments:{load_id:other}}); expect(denied.isError===true,'Cross-tenant access succeeded');
          expect(calls.filter(c=>c[0]===(name==='get_load_events'?'events':'status')).length===before,'Denied request read shipment data');
        }
      } finally { await client.close(); }
    }
  });
});
