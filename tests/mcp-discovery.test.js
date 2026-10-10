import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {once} from 'node:events';
import {randomBytes} from 'node:crypto';
import {config,seal} from '../api/oauth.js';

test('MCP initialize and tool discovery over separate stateless HTTP requests', async () => {
  process.env.OAUTH_ISSUER='https://meshy-test.vercel.app';
  process.env.OAUTH_SECRET=randomBytes(48).toString('base64url');
  const handler=(await import('../api/index.js')).default;
  const cfg=config();
  const token=seal({type:'access',clientId:'test-client',resource:cfg.resource,scope:'meshy:read meshy:generate',key:'msy_test_no_real_key'},cfg.encKey,300);
  const server=createServer(async (req,res)=>{
    res.status=function(code){this.statusCode=code;return this};
    res.json=function(body){this.setHeader('Content-Type','application/json');this.end(JSON.stringify(body));return this};
    req.body=JSON.parse((await Array.fromAsync(req)).map(x=>x.toString('utf8')).join('')||'{}');
    try {await handler(req,res)}catch(e){console.error('MCP test handler error',e);res.statusCode=500;res.end('handler crashed: '+e.message)}
  });
  server.listen(0,'127.0.0.1');
  await once(server,'listening');
  try {
    const base='http://127.0.0.1:'+server.address().port;
    const request=async (body)=>{
      const r=await fetch(base+'/mcp',{method:'POST',headers:{'content-type':'application/json','accept':'application/json, text/event-stream','mcp-protocol-version':'2025-03-26',authorization:'Bearer '+token},body:JSON.stringify(body)});
      const text=await r.text();
      let parsed;
      try {parsed=JSON.parse(text)}catch{parsed=text}
      return {status:r.status,parsed,body:text};
    };
    const init=await request({jsonrpc:'2.0',id:1,method:'initialize',params:{protocolVersion:'2025-03-26',capabilities:{},clientInfo:{name:'integration-test',version:'1.0.0'}}});
    assert.equal(init.status,200,'initialize failed: '+init.body.slice(0,1500));
    const tools=await request({jsonrpc:'2.0',id:2,method:'tools/list',params:{}});
    assert.equal(tools.status,200,'tools/list failed: '+tools.body.slice(0,2500));
    assert.ok(Array.isArray(tools.parsed?.result?.tools),'No list of tools: '+tools.body.slice(0,1500));
    assert.ok(tools.parsed.result.tools.length>=20,'Too few tools discovered: '+tools.parsed.result.tools.length);
    assert.ok(tools.parsed.result.tools.some(tool=>tool.name==='meshy_check_balance'));
  }finally{server.close();await once(server,'close')}
});
