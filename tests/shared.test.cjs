const test=require('node:test');
const assert=require('node:assert/strict');
const {guard,limited,safeEqual,cleanText,TOKEN_RE,ID_RE}=require('../api/_shared.js');

function mockResponse() {
  const res={statusCode:200,payload:null,headers:{}};
  res.setHeader=(name,value)=>{res.headers[name]=value;};
  res.status=function(code){this.statusCode=code;return this;};
  res.json=function(data){this.payload=data;return this;};
  return res;
}
test('registration API only accepts JSON POST',()=>{
  const res=mockResponse();
  assert.equal(guard({method:'GET',headers:{}},res),null);
  assert.equal(res.statusCode,405);
  const res2=mockResponse();
  assert.equal(guard({method:'POST',headers:{'content-type':'text/plain'}},res2),null);
  assert.equal(res2.statusCode,415);
});
test('cross-origin registration requests are refused',()=>{
  const res=mockResponse();
  const out=guard({method:'POST',headers:{origin:'https://attacker.example',host:'mun.example','content-type':'application/json'}},res);
  assert.equal(out,null);
  assert.equal(res.statusCode,403);
});
test('large registration payloads are refused',()=>{
  const res=mockResponse();
  assert.equal(guard({method:'POST',headers:{host:'mun.example','content-type':'application/json','content-length':'5000'}},res),null);
  assert.equal(res.statusCode,413);
});
test('valid same-origin requests pass through',()=>{
  const res=mockResponse();
  const body={name:'test'};
  assert.deepEqual(guard({method:'POST',headers:{host:'mun.example',origin:'https://mun.example','content-type':'application/json'},body},res),body);
});
test('token and delegate IDs use strict formats',()=>{
  assert(TOKEN_RE.test('a'.repeat(32)));
  assert(!TOKEN_RE.test('not-a-token'));
  assert(ID_RE.test('MUN26-1234'));
  assert(!ID_RE.test('../bad'));
});
test('constant-time digest comparison and bounded text cleanup',()=>{
  assert.equal(safeEqual('a','a'),true);
  assert.equal(safeEqual('a','b'),false);
  assert.equal(cleanText(' A\nB   C ',5),'A B C');
  assert.equal(cleanText('x'.repeat(99),8).length,8);
});
test('limiter constrains repeated requests',()=>{
  const key='unit-test-'+Math.random().toString(36).slice(2);
  assert.equal(limited(key,2,60000),false);
  assert.equal(limited(key,2,60000),false);
  assert.equal(limited(key,2,60000),true);
});
