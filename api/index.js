import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { getTaskWithAutoInference, MeshyClient } from '@meshy-ai/meshy-mcp-server/dist/services/meshy-client.js';
import { registerGenerationTools } from '@meshy-ai/meshy-mcp-server/dist/tools/generation.js';
import { registerTaskTools } from '@meshy-ai/meshy-mcp-server/dist/tools/tasks.js';
import { registerWorkspaceTools } from '@meshy-ai/meshy-mcp-server/dist/tools/workspace.js';
import { registerPostProcessingTools } from '@meshy-ai/meshy-mcp-server/dist/tools/postprocessing.js';
import { registerConversionTools } from '@meshy-ai/meshy-mcp-server/dist/tools/conversion.js';
import { registerImageTools } from '@meshy-ai/meshy-mcp-server/dist/tools/image.js';
import { registerPrintingTools } from '@meshy-ai/meshy-mcp-server/dist/tools/printing.js';
import { registerCreativeLabTools } from '@meshy-ai/meshy-mcp-server/dist/tools/creative-lab.js';
import { registerBalanceTool } from '@meshy-ai/meshy-mcp-server/dist/tools/balance.js';
import { MESHY_INSTRUCTIONS } from '@meshy-ai/meshy-mcp-server/dist/instructions.js';
import { VERSION } from '@meshy-ai/meshy-mcp-server/dist/version.js';
import { getTaskEndpoint } from '@meshy-ai/meshy-mcp-server/dist/utils/endpoints.js';
import {
  config, seal, unseal, makeClientId, getClient, validateRedirect,
  sha256pkce, isValidVerifier, safeEqual, escapeHtml, parseParams, contentSecurityPolicy
} from './oauth.js';

const json = (res, status, data) => res.status(status).setHeader('Cache-Control','no-store').json(data);
const fail = (res, status, error, description) => json(res, status, {error, error_description: description});
const originError = 'Invalid OAuth configuration';
const scopeDefault = 'meshy:read meshy:generate offline_access';

function addHeaders(res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('Referrer-Policy','no-referrer');
  res.setHeader('X-Frame-Options','DENY');
  res.setHeader('Content-Security-Policy', contentSecurityPolicy());
}

function asString(p) { return typeof p === 'string' ? p : ''; }
function callback(uri, p) {
  const url = new URL(uri);
  for (const [k,v] of Object.entries(p)) if (v !== undefined) url.searchParams.set(k,v);
  return url.toString();
}

function authorizeParameters(p, cfg) {
  const clientId = asString(p.client_id);
  const redirectUri = validateRedirect(asString(p.redirect_uri), cfg);
  const registered = getClient(clientId, cfg);
  if (!Array.isArray(registered) || !registered.includes(redirectUri)) throw new Error('Unregistered redirect URI');
  if (p.response_type !== 'code') throw new Error('Only response_type=code is supported');
  if (p.code_challenge_method !== 'S256' || !/^[A-Za-z0-9_-]{43}$/.test(asString(p.code_challenge))) {
    throw new Error('PKCE S256 is mandatory');
  }
  const resource = asString(p.resource) || cfg.resource;
  if (resource !== cfg.resource) throw new Error('Invalid OAuth resource');
  const scope = asString(p.scope) || scopeDefault;
  if (scope.split(' ').some(s => !['meshy:read','meshy:generate','offline_access'].includes(s))) throw new Error('Unsupported OAuth scope');
  return {clientId, redirectUri, state: asString(p.state), challenge: p.code_challenge, resource, scope};
}

function renderAuthPage(requestToken, scope) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connect Meshy</title><style>body{font-family:system-ui,-apple-system,sans-serif;background:#10131a;color:#f3f5f9;margin:0;min-height:100vh;display:grid;place-items:center}main{width:min(420px,calc(100% - 48px));background:#202530;padding:32px;border:1px solid #3a4250;border-radius:16px}h1{font-size:25px}p{line-height:1.6;color:#c2c8d2}label{display:block;margin:24px 0 8px}input{width:100%;box-sizing:border-box;padding:13px;border:1px solid #667083;background:#111722;color:#fff;border-radius:9px}button{width:100%;background:#eef2fb;color:#161b25;font-size:16px;font-weight:700;padding:14px;border:0;border-radius:9px;margin-top:20px;cursor:pointer}small{display:block;margin-top:18px;color:#aab2c0}</style></head><body><main><h1>Connect your Meshy account</h1><p>Use your own Meshy API key. Your credentials are encrypted into your OAuth session and never shared with other users.</p><p>Requested permissions: ${escapeHtml(scope.replaceAll(' ',' and '))}.</p><form method="post" action="/authorize"><input type="hidden" name="request" value="${escapeHtml(requestToken)}"><label for="key">Meshy API key</label><input id="key" name="api_key" type="password" autocomplete="off" spellcheck="false" required minlength="8"><button type="submit">Authorize Meshy</button></form><small>Requires Meshy API access. This service uses your Meshy credits, not another user's.</small></main></body></html>`;
}

async function validateMeshyKey(key) {
  const host = process.env.MESHY_API_HOST || 'https://api.meshy.ai';
  if (!/^https:\/\//.test(host)) throw new Error('Invalid Meshy API host');
  const response = await fetch(new URL('/openapi/v1/balance', host), {
    headers: {'Authorization': `Bearer ${key}`, 'Accept':'application/json'},
    signal: AbortSignal.timeout(12000)
  });
  return response.ok;
}

function publishMetadata(path, cfg, res) {
  if (path.includes('oauth-protected-resource')) {
    return json(res, 200, {
      resource: cfg.resource, authorization_servers: [cfg.issuer],
      scopes_supported: ['meshy:read','meshy:generate','offline_access'],
      bearer_methods_supported: ['header']
    });
  }
  return json(res, 200, {
    issuer: cfg.issuer,
    authorization_endpoint: `${cfg.issuer}/authorize`,
    token_endpoint: `${cfg.issuer}/token`,
    registration_endpoint: `${cfg.issuer}/register`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code','refresh_token'],
    token_endpoint_auth_methods_supported: ['none'],
    code_challenge_methods_supported: ['S256'],
    scopes_supported: ['meshy:read','meshy:generate','offline_access'],
    authorization_response_iss_parameter_supported: true
  });
}

function buildServer(apiKey) {
  const server = new McpServer(
    {name:'meshy-mcp-vercel',version:VERSION},
    {instructions: MESHY_INSTRUCTIONS}
  );
  const client = new MeshyClient(apiKey);
  registerGenerationTools(server, client);
  // Replace local disk downloads with browser-usable, per-user Meshy URLs.
  // Nothing is written to Vercel's ephemeral filesystem or shared across users.
  const registerTool = server.registerTool.bind(server);
  server.registerTool = (name, options, callback) => {
    if (name === 'meshy_download_model') {
      return registerTool(name, {
        ...options,
        title: 'Get Model or Image Download URLs',
        description: 'Retrieve direct download URLs for a completed Meshy task. No files are saved on the remote server. Returns available 3D formats and image URLs. The user can download these URLs directly.',
        annotations: {readOnlyHint:true,destructiveHint:false,idempotentHint:true,openWorldHint:true}
      }, async params => {
        try {
          const endpoint = getTaskEndpoint(params.task_type);
          const {task} = await getTaskWithAutoInference(client,params.task_id,endpoint);
          if (task.status !== 'SUCCEEDED') return {
            isError:true,
            content:[{type:'text',text:`Task is ${task.status}. Check again when it completes.`}]
          };
          const modelUrls = Object.fromEntries(Object.entries(task.model_urls || {}).filter(([,url])=>Boolean(url)));
          const imageUrls = (task.image_urls || []).filter(Boolean);
          const selectedFormat = params.format && modelUrls[params.format]
            ? {[params.format]:modelUrls[params.format]} : modelUrls;
          const result = {task_id:params.task_id,model_urls:selectedFormat,image_urls:imageUrls};
          if (!Object.keys(selectedFormat).length && !imageUrls.length) return {
            isError:true,content:[{type:'text',text:'Task has no downloadable URLs.'}]
          };
          return {content:[{type:'text',text:JSON.stringify(result,null,2)}]};
        } catch (e) {return {isError:true,content:[{type:'text',text:'Unable to fetch task URLs: '+(e.message || 'Unknown error')}]};}
      });
    }
    if (name === 'meshy_get_task_status') {
      return registerTool(name, {
        ...options,
        description:'Check a Meshy generation task. Remote transport uses short polling with a maximum 90-second wait; prefer wait=false and poll on subsequent messages.'
      }, (params, extra) => callback({...params,timeout_seconds:Math.min(params.timeout_seconds || 90,90)},extra));
    }
    if (name === 'meshy_send_to_slicer') {
      return registerTool(name, {...options,description:'Local slicer integration is not supported in serverless environments. Download the 3MF/OBJ file and open your preferred slicer locally.'},
        async () => ({isError:true,content:[{type:'text',text:'Remote MCP servers cannot launch a local slicer. Download the model URL and import it into a slicer installed on your device.'}]}));
    }
    return registerTool(name, options, callback);
  };
  registerTaskTools(server, client);
  // The three registrations above retain original tool names and input schemas.
  registerWorkspaceTools(server, client);
  registerPostProcessingTools(server, client);
  registerConversionTools(server, client);
  registerImageTools(server, client);
  registerPrintingTools(server, client);
  server.registerTool = registerTool;
  registerCreativeLabTools(server, client);
  registerBalanceTool(server, client);
  return server;
}

export default async function handler(req, res) {
  addHeaders(res);
  const routeName = asString(req.query?.__endpoint);
  const pathname = routeName && /^[a-z/]+$/.test(routeName)
    ? (routeName.startsWith('well-known/') ? '/.' + routeName : '/' + routeName)
    : new URL(req.url, 'https://localhost').pathname;
  if (pathname === '/health' && req.method === 'GET') return json(res, 200, {status:'ok',version:VERSION,transport:'streamable-http',auth:'oauth2'});

  let cfg;
  try { cfg = config(); } catch (error) { return fail(res,503,'server_configuration',originError); }

  if (pathname.startsWith('/.well-known/')) {
    res.setHeader('Access-Control-Allow-Origin','*');
    res.setHeader('Access-Control-Allow-Methods','GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers','Content-Type');
    if (req.method === 'OPTIONS') { res.statusCode=204; return res.end(); }
    if (req.method === 'GET') return publishMetadata(pathname, cfg, res);
  }

  if (pathname === '/register' && req.method === 'POST') {
    const input = parseParams(req);
    try {
      if (!Array.isArray(input.redirect_uris) || input.redirect_uris.length < 1 || input.redirect_uris.length > 5) throw new Error('redirect_uris required');
      const uris = input.redirect_uris.map(u => validateRedirect(u,cfg));
      if (input.token_endpoint_auth_method && input.token_endpoint_auth_method !== 'none') throw new Error('Only public PKCE clients are supported');
      return json(res,201,{
        client_id: makeClientId(uris,cfg), client_name: asString(input.client_name).slice(0,100) || 'MCP Client',
        redirect_uris: uris, token_endpoint_auth_method:'none',
        grant_types:['authorization_code','refresh_token'], response_types:['code']
      });
    } catch(e) { return fail(res,400,'invalid_client_metadata',e.message); }
  }

  if (pathname === '/authorize' && req.method === 'GET') {
    // A form POST finishes with an OAuth redirect to the registered ChatGPT host.
    // CSP form-action must allow that exact destination as well as this server.
    res.setHeader('Content-Security-Policy', contentSecurityPolicy(cfg.allowedHosts));
    try {
      const p = authorizeParameters(new URL(req.url,'https://localhost').searchParams && Object.fromEntries(new URL(req.url,'https://localhost').searchParams),cfg);
      const token = seal({type:'request',...p},cfg.encKey,600);
      res.statusCode=200;res.setHeader('Content-Type','text/html; charset=utf-8');
      return res.end(renderAuthPage(token,p.scope));
    } catch(e) { return fail(res,400,'invalid_request',e.message); }
  }

  if (pathname === '/authorize' && req.method === 'POST') {
    const p = parseParams(req);
    try {
      const state = unseal(p.request,cfg.encKey,'request');
      const key = asString(p.api_key).trim();
      if (!/^msy_[A-Za-z0-9_-]{6,}$/.test(key) || key.length > 500 || !(await validateMeshyKey(key))) {
        return fail(res,401,'access_denied','Invalid Meshy API key or balance API unavailable');
      }
      const code = seal({type:'code', clientId:state.clientId,resource:state.resource,
        scope:state.scope,challenge:state.challenge,key},cfg.encKey,90);
      res.statusCode=302;res.setHeader('Location',callback(state.redirectUri,{code,state:state.state,iss:cfg.issuer}));return res.end();
    } catch(e) { return fail(res,400,'invalid_request','OAuth authorization request expired or invalid'); }
  }

  if (pathname === '/token' && req.method === 'POST') {
    const p = parseParams(req);
    try {
      const clientId = asString(p.client_id);
      getClient(clientId,cfg);
      let session;
      if (p.grant_type === 'authorization_code') {
        const code = unseal(p.code,cfg.encKey,'code');
        if (code.clientId !== clientId || !isValidVerifier(p.code_verifier) ||
            !safeEqual(sha256pkce(p.code_verifier),code.challenge) ||
            (p.resource && p.resource !== code.resource)) throw new Error('Invalid code or PKCE verifier');
        session={clientId,resource:code.resource,scope:code.scope,key:code.key};
      } else if (p.grant_type === 'refresh_token') {
        const token = unseal(p.refresh_token,cfg.encKey,'refresh');
        if (token.clientId !== clientId || (p.resource && p.resource !== token.resource)) throw new Error('Invalid refresh token');
        session={clientId,resource:token.resource,scope:token.scope,key:token.key};
      } else return fail(res,400,'unsupported_grant_type','Only authorization_code and refresh_token are supported');
      return json(res,200,{
        access_token:seal({type:'access',...session},cfg.encKey,3600),
        token_type:'Bearer', expires_in:3600,scope:session.scope,
        refresh_token:seal({type:'refresh',...session},cfg.encKey,60*60*24*14)
      });
    } catch(e) { return fail(res,400,'invalid_grant','Invalid or expired grant'); }
  }

  if (pathname === '/mcp') {
    res.setHeader('WWW-Authenticate',`Bearer resource_metadata="${cfg.issuer}/.well-known/oauth-protected-resource"`);
    const authorization = asString(req.headers.authorization);
    let identity;
    try {
      identity = unseal(authorization.startsWith('Bearer ') ? authorization.slice(7) : '',cfg.encKey,'access');
      if (identity.resource !== cfg.resource || !identity.scope?.includes('meshy:read')) throw new Error('Invalid scope or audience');
    } catch { return fail(res,401,'unauthorized','A valid Meshy OAuth bearer token is required'); }
    if (req.method !== 'POST') return fail(res,405,'method_not_allowed','Use MCP POST with streamable HTTP');
    if (Number(req.headers['content-length'] || 0) > 4_000_000) return fail(res,413,'request_too_large','Payload exceeds 4 MB');
    const msg = parseParams(req);
    // Credit-consuming tools require the generate scope.
    if (msg.method === 'tools/call' && !identity.scope.split(' ').includes('meshy:generate') && msg.params?.name !== 'meshy_check_balance' && msg.params?.name !== 'meshy_list_models' && msg.params?.name !== 'meshy_list_tasks' && msg.params?.name !== 'meshy_get_task_status') {
      return fail(res,403,'insufficient_scope','meshy:generate is required');
    }
    const server = buildServer(identity.key);
    const transport = new StreamableHTTPServerTransport({sessionIdGenerator:undefined,enableJsonResponse:true});
    const originalSend = transport.send.bind(transport);
    transport.send = (message, options) => {
      const tools = message?.result?.tools;
      if (Array.isArray(tools)) for (const tool of tools) {
        if (tool.inputSchema) delete tool.inputSchema.$schema;
        if (tool.outputSchema) delete tool.outputSchema.$schema;
      }
      return originalSend(message,options);
    };
    try {
      await server.connect(transport);
      await transport.handleRequest(req,res,req.body);
    } catch(e) {
      console.error('MCP request failed:',e?.message || e);
      if (!res.headersSent) return fail(res,500,'internal_error','MCP operation failed');
    } finally { await transport.close(); await server.close(); }
    return;
  }
  return fail(res,404,'not_found','Unknown endpoint');
}
