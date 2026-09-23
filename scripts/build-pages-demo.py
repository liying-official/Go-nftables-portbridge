#!/usr/bin/env python3
"""Generate an isolated, backend-free Pages UI from the production static assets."""
import argparse
import hashlib
import json
import pathlib
import re
import sys

root=pathlib.Path(__file__).resolve().parents[1]
ui=root/'internal/web/static'
def once(text,old,new):
    if text.count(old)!=1:raise ValueError('UI generation boundary changed: '+old[:80])
    return text.replace(old,new,1)
def outputs():
    files={}
    sources={name: (ui/name).read_bytes() for name in ('index.html','app.js','i18n.js','style.css','security.css','tabler-icons.svg','vendor/tabler.min.css','vendor/tabler.min.js','vendor/LICENSES.txt')}
    for name,data in sources.items():
        if name not in ('index.html','app.js','i18n.js'):files['docs/assets/ui/'+name]=data
    html=sources['index.html'].decode().replace('/static/','assets/ui/')
    csp="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-src 'none'; worker-src 'none'"
    html=once(html,'<head><meta charset="utf-8">','<head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="'+csp+'"><meta name="referrer" content="no-referrer">')
    html=once(html,'</head>','<link rel="stylesheet" href="assets/demo.css"><link rel="icon" type="image/svg+xml" href="assets/favicon.svg"></head>')
    html=once(html,'<body>','<body><noscript><p class="pb-demo-noscript">JavaScript is required for this static demo. Public demo password: PortBridge. Never enter real credentials.<br>静态演示需要 JavaScript。公开演示密码：PortBridge。请勿输入真实凭据。</p></noscript>')
    html=once(html,'<main class="pb-content">','<main class="pb-content"><aside class="pb-demo-notice" aria-label="Demo notice"><p data-i18n="demoNotice">DEMO · Synthetic data only. No real API or forwarding. Changes reset on refresh. Public demo password: PortBridge.</p><div class="pb-demo-actions"><button id="resetDemoBtn" class="btn btn-outline-primary" type="button" data-i18n="demoReset">Reset demo</button><a class="btn" href="https://github.com/liying-official/Go-nftables-portbridge/blob/main/docs/INDEX.md" target="_blank" rel="noopener noreferrer" data-i18n="demoDocs">Documentation</a></div></aside>')
    html=once(html,'<span class="pb-topbar-label">Go-nftables-portbridge</span>','<span class="pb-topbar-label" data-i18n="demoHeader">PortBridge · DEMO</span>')
    html=html.replace('placeholder="1.1.1.1\n8.8.8.8:53\n[2606:4700:4700::1111]:53"','placeholder="192.0.2.53\n[2001:db8::53]:53"')
    html=html.replace('192.168.50.0/24','192.0.2.0/24').replace('fd00:1234::/64','2001:db8:1234::/64')
    html=once(html,'<script src="assets/ui/app.js" defer></script>','<script src="assets/demo-backend.js" defer></script><script src="assets/ui/app.js" defer></script>')
    # These fallbacks remain safe before i18n initializes, including no-JS readers.
    html=html.replace('Use the administrator token generated during installation.','Demo password: PortBridge. Never enter a real administrator token.')
    html=html.replace('The token stays in this browser tab’s session. Sign out when you finish.','Public static demo only. All data is synthetic; changes reset on refresh.')
    html=html.replace('Administrator token','Demo password').replace('Sign in to PortBridge','Explore the PortBridge demo')
    files['docs/index.html']=html.encode()
    app=sources['app.js'].decode().replace("'portbridge_token'","'portbridge_demo_session'").replace('/static/tabler-icons.svg','assets/ui/tabler-icons.svg')
    app=once(app,'await fetch(path,{...opts,headers})','await window.PB_DEMO.request(path,{...opts,headers})')
    app=once(app,"closeNavigation();syncStrictUI();bootstrap()","$('resetDemoBtn').onclick=async()=>{window.PB_DEMO.reset();await loadAll();toast('demoResetDone');};\ncloseNavigation();syncStrictUI();bootstrap()")
    files['docs/assets/ui/app.js']=app.encode()
    i18n=sources['i18n.js'].decode().replace('portbridge_language','portbridge_demo_language')
    i18n=once(i18n,"  if(!supported(current))current='en-US';","  const requested=new URLSearchParams(location.search).get('lang');if(supported(requested))current=requested;\n  if(!supported(current))current='en-US';")
    overrides=json.loads((root/'packaging/pages-demo-i18n.json').read_text(encoding='utf-8'))
    injection='  const demoMessages='+json.dumps(overrides,ensure_ascii=False,separators=(',',':'))+';\n  for(const lang of Object.keys(demoMessages))Object.assign(messages[lang],demoMessages[lang]);\n'
    i18n=once(i18n,'  const supported =',injection+'  const supported =')
    files['docs/assets/ui/i18n.js']=i18n.encode()
    files['docs/assets/ui/source-manifest.json']=(json.dumps({'version':(root/'VERSION').read_text().strip(),'sources':{name:hashlib.sha256(data).hexdigest() for name,data in sources.items()},'demo_only':True},indent=2)+'\n').encode()
    icon=re.search(r'<symbol id="arrows-transfer-up-down" viewBox="0 0 24 24">(.*?)</symbol>',sources['tabler-icons.svg'].decode(),re.S)
    if icon is None:raise ValueError('Missing Tabler demo icon')
    files['docs/assets/favicon.svg']=('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#0D394A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><!-- Tabler Icons 3.48.0, MIT; ui/vendor/LICENSES.txt -->'+icon[1]+'</svg>\n').encode()
    files['docs/.nojekyll']=b''
    return files
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true');args=parser.parse_args()
    generated=outputs();stale=[]
    for name,data in generated.items():
        path=root/name
        if args.check:
            if not path.is_file() or path.read_bytes()!=data:stale.append(name)
        else:
            path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
    if stale:print('Out-of-date Pages files: '+', '.join(stale),file=sys.stderr);sys.exit(1)
    print(('Verified' if args.check else 'Generated')+' '+str(len(generated))+' Pages files; production UI unchanged.')
