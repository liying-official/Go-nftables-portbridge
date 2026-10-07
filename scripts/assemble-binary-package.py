#!/usr/bin/env python3
"""Project a localized build tree into a runtime-only, single-language bundle."""
import argparse
import pathlib
import posixpath
import re
import shutil


GUIDES = ('INSTALL', 'ONECLICK', 'API', 'MONITORING', 'DIAGNOSTICS')
PROJECT_URL = 'https://github.com/liying-official/Go-nftables-portbridge'


def copy_file(source, destination):
    if source.is_symlink() or not source.is_file():
        raise ValueError('Expected a regular package input: ' + str(source))
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def project_document(text, name, language, delivered, version):
    # Remove document language selectors, not the application's bilingual UI.
    if name == 'README.md':
        text = re.sub(r'<p align="center">\s*(?:<strong>English</strong>|<a href="README\.md">English</a>).*?</p>\s*',
                      '', text, flags=re.S)
        text = '\n'.join(line for line in text.split('\n')
                         if 'https://liying-official.github.io/Go-nftables-portbridge/' not in line)
    text = re.sub(r'\[(?:English|简体中文)\]\([^)]*\)(?: · )?', '', text)
    text = re.sub(r' · (?=\n|$)', '', text)

    def target(link):
        if not link or link.startswith(('#', '/')) or re.match(r'\w+:', link):
            return link
        path, separator, anchor = link.partition('#')
        relative = posixpath.normpath(posixpath.join(posixpath.dirname(name), path))
        if relative in ('README.zh-CN.md', 'README.en-US.md'):
            relative = 'README.md'
        if relative in ('RELEASE_NOTES.zh-CN.md', 'RELEASE_NOTES.en-US.md'):
            relative = 'RELEASE_NOTES.md'
        if relative == 'VENDOR_PATCHES.md':
            relative = 'licenses/INDEX.md'
            separator = anchor = ''
        if relative in delivered:
            return posixpath.relpath(relative, posixpath.dirname(name) or '.') + separator + anchor
        # Development references and optional examples stay online, not in the
        # installation archive. Pin them to the matching release source tag.
        if relative.startswith('../'):
            raise ValueError('Document link escapes source tree: ' + link)
        if relative in ('docs/CONFIGURATION.md', 'docs/udp-dataplane.md') and not separator:
            separator, anchor = '#', '简体中文' if language == 'zh-CN' else 'english'
        return PROJECT_URL + '/blob/v' + version + '/' + relative + separator + anchor

    text = re.sub(r'\]\(([^)]+)\)', lambda m: '](' + target(m[1]) + ')', text)
    text = re.sub(r'href="([^"]+)"', lambda m: 'href="' + target(m[1]) + '"', text)
    return text


def assemble(source, destination, language, go_root):
    source, destination = source.resolve(), destination.resolve()
    if source == destination or destination.is_relative_to(source) or destination.exists():
        raise ValueError('Use a new output directory outside the build tree')
    if (source / 'PACKAGE_LANGUAGE').read_text().strip() != language:
        raise ValueError('Build tree language does not match the package')
    version = (source / 'VERSION').read_text(encoding='ascii').strip()
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('Invalid package version')
    documents = ['README.md', 'RELEASE_NOTES.md', 'SECURITY.md', 'docs/forwarding-limits.md']
    documents += ['docs/' + guide + '.' + language + '.md' for guide in GUIDES]
    files = documents + ['LICENSE', 'VERSION', 'PACKAGE_LANGUAGE',
                         'scripts/install.sh', 'scripts/uninstall.sh',
                         'packaging/portbridge.service', 'packaging/90-portbridge.conf',
                         'packaging/release-signers']
    licenses = {'licenses/WEB.txt': source / 'internal/web/static/vendor/LICENSES.txt',
                'licenses/GO-LICENSE': go_root / 'LICENSE',
                'licenses/GO-PATENTS': go_root / 'PATENTS'}
    for module in ('net', 'sys'):
        for notice in ('LICENSE', 'PATENTS'):
            licenses['licenses/X-' + module.upper() + '-' + notice] = source / 'vendor/golang.org/x' / module / notice
    delivered = set(files) | set(licenses) | {'docs/INDEX.md', 'licenses/INDEX.md'}
    destination.mkdir(parents=True)
    for name in files:
        copy_file(source / name, destination / name)
    for name, origin in licenses.items():
        copy_file(origin, destination / name)
    for name in documents:
        path = destination / name
        text = project_document(path.read_text(encoding='utf-8'), name, language, delivered, version)
        path.write_text(text, encoding='utf-8', newline='\n')
    index = '# PortBridge documentation — v' + version + '\n\n'
    if language == 'zh-CN':
        index = '# PortBridge 文档 — v' + version + '\n\n'
    labels = ('Installation and upgrades', 'Interactive fresh installation', 'API reference', 'Monitoring', 'Diagnostics')
    if language == 'zh-CN':
        labels = ('安装与升级', '交互式全新安装', 'API 接口', '监控', '只读诊断')
    index += '[README](../README.md)\n\n'
    index += ''.join('- [' + label + '](' + guide + '.' + language + '.md)\n'
                     for guide, label in zip(GUIDES, labels))
    extra = ('Forwarding limits', 'Security', 'Release notes', 'Licenses')
    if language == 'zh-CN':
        extra = ('转发边界', '安全说明', '版本说明', '许可证')
    index += ''.join('- [' + label + '](' + link + ')\n' for label, link in
                     zip(extra, ('forwarding-limits.md', '../SECURITY.md', '../RELEASE_NOTES.md', '../licenses/INDEX.md')))
    if language == 'en-US':
        index += '\nThis prebuilt package contains no source, tests or static demo. Development references and optional examples link to the matching repository tag and require Internet access. WebGUI remains bilingual.\n'
        notices = '# Third-party licenses\n\nOriginal copyright, license and patent notices are retained without translation. WebUI resources are embedded in the binary; no separate assets are required.\n\n'
    else:
        index += '\n预编译包不包含源码、测试或静态演示。开发参考和可选示例链接到对应版本的仓库，需要联网访问。WebGUI 仍支持中英双语。\n'
        notices = '# 第三方许可证\n\n版权、许可证和专利声明保留原文，不作翻译。WebUI 资源已嵌入二进制，不需要额外资源文件。\n\n'
    (destination / 'docs/INDEX.md').write_text(index, encoding='utf-8', newline='\n')
    notices += '- [PortBridge MIT](../LICENSE)\n- [Tabler Core / Icons, Bootstrap, Popper](WEB.txt)\n'
    notices += '- [Go BSD](GO-LICENSE) · [PATENTS](GO-PATENTS)\n'
    for module in ('NET', 'SYS'):
        notices += '- [golang.org/x/' + module.lower() + ' BSD](X-' + module + '-LICENSE) · [PATENTS](X-' + module + '-PATENTS)\n'
    (destination / 'licenses/INDEX.md').write_text(notices, encoding='utf-8', newline='\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=pathlib.Path)
    parser.add_argument('destination', type=pathlib.Path)
    parser.add_argument('language', choices=['en-US', 'zh-CN'])
    parser.add_argument('--go-root', type=pathlib.Path, required=True)
    args = parser.parse_args()
    assemble(args.source, args.destination, args.language, args.go_root)
