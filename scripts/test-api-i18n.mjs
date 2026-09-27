import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import {fileURLToPath} from 'node:url';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const ui=path.join(root,'internal/web/static');
const document={documentElement:{dataset:{defaultLanguage:'en-US'},lang:''},querySelectorAll:()=>[],dispatchEvent:()=>{},title:''};
const context=vm.createContext({window:{},document,localStorage:{getItem:()=>null,setItem:()=>{}},CustomEvent:class {}});
vm.runInContext(fs.readFileSync(path.join(ui,'i18n.js'),'utf8'),context);
const i18n=context.window.PB_I18N;

const serverSource=fs.readFileSync(path.join(root,'internal/web/server.go'),'utf8')+fs.readFileSync(path.join(root,'internal/web/api_errors.go'),'utf8');
for(const [,key] of serverSource.matchAll(/"(api[A-Z]\w+)"/g))assert(i18n.hasMessageKey(key),`Missing bilingual API key: ${key}`);
assert.equal(i18n.t('apiJSONTooLarge',{limit:1048576}),'JSON request body must not exceed 1048576 bytes.');
assert.equal(i18n.t('apiRuleNotFound',{id:'missing'}),'Rule "missing" was not found.');
i18n.setLanguage('zh-CN');
assert.equal(i18n.t('apiJSONTooLarge',{limit:1048576}),'JSON 请求体不能超过 1048576 字节。');
assert.equal(i18n.t('apiRuleNotFound',{id:'missing'}),'未找到规则“missing”。');
assert(!i18n.hasMessageKey('unknownServerKey'));

const app=fs.readFileSync(path.join(ui,'app.js'),'utf8');
const start=app.indexOf('function apiErrorFromResponse('),end=app.indexOf('function showError(',start);
assert(start>=0&&end>start&&app.includes('throw apiErrorFromResponse(data,response.status)'));
const apiContext=vm.createContext({t:i18n.t,hasMessageKey:i18n.hasMessageKey,
  localizedError:(key,args)=>({messageKey:key,messageArgs:args,message:i18n.t(key,args)})});
vm.runInContext(app.slice(start,end)+'\nglobalThis.convert=apiErrorFromResponse;',apiContext);
const convert=apiContext.convert;
const keyed=convert({error:'管理员令牌无效',messageKey:'apiInvalidToken'},401);
assert.equal(keyed.messageKey,'apiInvalidToken');
assert.equal(i18n.t(keyed.messageKey,keyed.messageArgs),'管理员令牌无效。');
const withArgs=convert({error:'JSON 请求体不能超过 1048576 字节',messageKey:'apiJSONTooLarge',messageArgs:{limit:1048576}},400);
assert.equal(i18n.t(withArgs.messageKey,withArgs.messageArgs),'JSON 请求体不能超过 1048576 字节。');
assert.equal(convert({error:'legacy text',messageKey:'unknownServerKey'},400).message,'legacy text');
assert.equal(convert({error:'legacy text'},400).message,'legacy text');
assert.equal(convert(null,400).messageKey,'requestFailed');
i18n.setLanguage('en-US');
assert.equal(i18n.t(keyed.messageKey,keyed.messageArgs),'Invalid administrator token.');

console.log('API i18n PASS: server keys, bilingual arguments, client fallback, language switch.');
