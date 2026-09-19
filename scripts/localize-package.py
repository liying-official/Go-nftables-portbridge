#!/usr/bin/env python3
import argparse,json,pathlib,re

def localize(root, language):
    root=pathlib.Path(root)
    if language not in ('en-US','zh-CN'):
        raise ValueError('Unsupported package language')
    if (root/'.git').exists():
        raise ValueError('Localize a staging copy, not a Git worktree')
    originals=root/'packaging/document-sources'
    for name in ('README.md','README.zh-CN.md','RELEASE_NOTES.md','RELEASE_NOTES.zh-CN.md','CONTRIBUTING.md','VENDOR_PATCHES.md','SECURITY.md','docs/udp-dataplane.md','docs/forwarding-limits.md'):
        saved=originals/name
        if not saved.exists():
            saved.parent.mkdir(parents=True,exist_ok=True)
            saved.write_bytes((root/name).read_bytes())
        (root/name).write_bytes(saved.read_bytes())
    for name in ('v2.4.5-candidate.md','v2.4.6-candidate.md','v2.4.6-fix-candidate.md','v2.4.7-candidate.md','v2.4.8-candidate.md'):
        (root/'docs'/name).unlink(missing_ok=True)
    for name in ('index.html','app.js'):
        (root/'internal/web/static'/name).write_bytes((root/'packaging/web-zh-CN'/name).read_bytes())
    if language=='en-US':
        mapping=json.loads((root/'packaging/web-en.json').read_text(encoding='utf-8'))
        pattern=re.compile('|'.join(re.escape(x) for x in sorted(mapping,key=len,reverse=True)))
        for name in ('index.html','app.js'):
            path=root/'internal/web/static'/name
            text=path.read_text(encoding='utf-8')
            text=pattern.sub(lambda m:mapping[m.group()],text)
            if name=='index.html':text=text.replace('lang="zh-CN"','lang="en-US"')
            if re.search('[\u4e00-\u9fff]',text):
                raise ValueError('Untranslated GUI text: '+name)
            if name=='app.js':
                errors=json.loads((root/'packaging/api-en.json').read_text(encoding='utf-8'))
                text=text.replace('j.error||','translateAPIError(j.error)||')
                text+='\nfunction translateAPIError(message){if(typeof message!=="string")return message;for(const [original,translated] of Object.entries('+json.dumps(errors,ensure_ascii=True)+'))message=message.replaceAll(original,translated);return message}\n'
            path.write_text(text,encoding='utf-8',newline='\n')
    for name in ('package-release.sh','verify-candidate.sh','test-clean-go-netns.sh','test-recovery-proc-subset.sh','test-recovery-boot-bind.sh'):
        saved=root/'packaging/script-sources'/name
        if not saved.exists():
            saved.parent.mkdir(parents=True,exist_ok=True)
            saved.write_bytes((root/'scripts'/name).read_bytes())
        text=saved.read_text(encoding='utf-8')
        if language=='zh-CN':
            messages=json.loads((root/'packaging/scripts-zh.json').read_text(encoding='utf-8'))
            pattern=re.compile('|'.join(re.escape(x) for x in sorted(messages,key=len,reverse=True)))
            text=''.join(line if line.lstrip().startswith('#') else pattern.sub(lambda m:messages[m.group()],line) for line in text.splitlines(keepends=True))
        (root/'scripts'/name).write_text(text,encoding='utf-8',newline='\n')
    for name in ('install','uninstall'):
        variant='en' if language=='en-US' else 'zh-CN'
        (root/'scripts'/f'{name}.sh').write_bytes((root/'scripts'/f'{name}.{variant}.sh').read_bytes())
    if language=='zh-CN':
        for name in ('README','RELEASE_NOTES'):
            en=root/(name+'.en-US.md')
            if not en.exists():en.write_bytes((root/(name+'.md')).read_bytes())
            text=(root/(name+'.zh-CN.md')).read_text(encoding='utf-8').replace('(README.md)','(README.en-US.md)')
            (root/(name+'.md')).write_text(text,encoding='utf-8',newline='\n')
            (root/(name+'.zh-CN.md')).write_text(text,encoding='utf-8',newline='\n')
    docs=['CONTRIBUTING.md','VENDOR_PATCHES.md','SECURITY.md','docs/udp-dataplane.md','docs/forwarding-limits.md']
    for name in docs:
        path=root/name;text=path.read_text(encoding='utf-8')
        parts=re.split(r'\n## (?:简体中文|中文说明)\n',text,maxsplit=1)
        if len(parts)!=2:raise ValueError('Missing bilingual document boundary: '+name)
        en,zh=parts
        title=en.splitlines()[0]
        if ' / ' in title:
            left,right=title.split(' / ',1)
            title=left if language=='en-US' else '# Go-nftables-portbridge v2.4.9 — '+right
        if language=='en-US':
            text=title+'\n'+en[en.index('\n'):]
        else:
            text=title+'\n\n'+zh.lstrip()
            if name=='CONTRIBUTING.md':
                text=text.replace('代码修改应执行上方测试、race 和 vet 命令','代码修改应执行测试、race 和 vet 命令')
                text+='\n```bash\nGOTOOLCHAIN=local GOFLAGS=-mod=vendor GOPROXY=off go test ./...\nGOTOOLCHAIN=local GOFLAGS=-mod=vendor GOPROXY=off go test -race ./...\nGOTOOLCHAIN=local GOFLAGS=-mod=vendor GOPROXY=off go vet ./...\n```\n'
        path.write_text(text,encoding='utf-8',newline='\n')
    (root/'PACKAGE_LANGUAGE').write_text(language+'\n',encoding='ascii')

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('root',type=pathlib.Path);p.add_argument('language',choices=['en-US','zh-CN']);a=p.parse_args();localize(a.root,a.language)
