import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {config,seal,unseal,makeClientId,getClient,validateRedirect,sha256pkce,isValidVerifier,safeEqual,escapeHtml,contentSecurityPolicy} from '../api/oauth.js';

process.env.OAUTH_ISSUER='https://meshy-test.vercel.app';
process.env.OAUTH_SECRET=randomBytes(48).toString('base64url');
const cfg=config();

test('AES-GCM token roundtrip and type enforcement',()=>{
  const token=seal({type:'access',key:'msy_fake_sensitive_key',resource:cfg.resource},cfg.encKey,300);
  assert.equal(unseal(token,cfg.encKey,'access').key,'msy_fake_sensitive_key');
  assert.ok(!token.includes('msy_fake_sensitive_key'));
  assert.throws(()=>unseal(token,cfg.encKey,'code'));
});
test('ciphertext alteration rejected',()=>{
  const token=seal({type:'code',scope:'meshy:generate'},cfg.encKey,120);
  const altered=token.slice(0,-3) + 'abc';
  assert.throws(()=>unseal(altered,cfg.encKey,'code'));
});
test('dynamic OAuth clients are authenticated without storage',()=>{
  const uri='https://chatgpt.com/connector_platform_oauth_redirect';
  const id=makeClientId([uri],cfg);
  assert.deepEqual(getClient(id,cfg),[uri]);
  assert.throws(()=>getClient(id.slice(0,-3)+'bad',cfg));
});
test('untrusted OAuth callbacks refused',()=>{
  assert.equal(validateRedirect('https://chatgpt.com/connector_platform_oauth_redirect',cfg),'https://chatgpt.com/connector_platform_oauth_redirect');
  for(const bad of ['http://chatgpt.com/callback','https://chatgpt.com.evil.org/callback','https://evil.org/callback','https://user@chatgpt.com/callback']) {
    assert.throws(()=>validateRedirect(bad,cfg));
  }
});
test('PKCE SHA-256 verifier matches challenge',()=>{
  const verifier='a'.repeat(43);
  assert.equal(isValidVerifier(verifier),true);
  assert.equal(isValidVerifier('short'),false);
  assert.ok(safeEqual(sha256pkce(verifier),sha256pkce(verifier)));
  assert.ok(!safeEqual(sha256pkce(verifier),sha256pkce('b'.repeat(43))));
});
test('HTML values escaped',()=>assert.equal(escapeHtml('<img src=x onerror="alert(1)">'),'&lt;img src=x onerror=&quot;alert(1)&quot;&gt;'));
test('missing configuration fails closed',()=>{
  const old=process.env.OAUTH_SECRET;
  delete process.env.OAUTH_SECRET;
  assert.throws(()=>config());
  process.env.OAUTH_SECRET=old;
});

test('OAuth form CSP allows the registered ChatGPT redirect after POST', () => {
  const policy = contentSecurityPolicy(cfg.allowedHosts);
  assert.match(policy, /form-action 'self' https:\/\/chatgpt\.com;/);
  assert.match(policy, /default-src 'none'/);
  assert.match(policy, /frame-ancestors 'none'/);
});
test('OAuth form CSP restricts destinations to valid configured hosts', () => {
  const policy = contentSecurityPolicy(['chatgpt.com', 'other.example.com', 'evil.com; script-src *', 'chatgpt.com']);
  assert.match(policy, /https:\/\/other\.example\.com/);
  assert.equal((policy.match(/https:\/\/chatgpt\.com/g) || []).length, 1);
  assert.ok(!policy.includes('evil.com;'));
  assert.ok(!policy.includes('script-src'));
});
