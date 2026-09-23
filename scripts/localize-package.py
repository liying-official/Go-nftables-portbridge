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
    # Both packages contain the same bilingual application. Only its initial
    # language follows the installer/documentation language; the UI can switch.
    index=root/'internal/web/static/index.html'
    text=index.read_text(encoding='utf-8')
    text,count=re.subn(r'<html lang="(?:en-US|zh-CN)" data-default-language="(?:en-US|zh-CN)">',
                      f'<html lang="{language}" data-default-language="{language}">',text,count=1)
    if count!=1:raise ValueError('Missing bilingual GUI language marker')
    index.write_text(text,encoding='utf-8',newline='\n')
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
            version=(root/'VERSION').read_text(encoding='ascii').strip()
            title=left if language=='en-US' else '# Go-nftables-portbridge v'+version+' — '+right
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
