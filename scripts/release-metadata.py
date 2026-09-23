#!/usr/bin/env python3
"""Create deterministic metadata for signed, architecture-specific bundles."""
import argparse
import base64
import hashlib
import json
import pathlib
import re


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')


def bundle(args):
    root = args.root.resolve()
    binary = root / 'dist' / ('go-nftables-portbridge-linux-' + args.arch)
    source_manifest = root / 'source-tree.sha256'
    write_json(root / 'release-bundle-manifest.json', {
        'project': 'Go-nftables-portbridge',
        'version': args.version,
        'source_revision': args.revision,
        'release_toolchain': args.toolchain,
        'source_manifest_sha256': sha256(source_manifest),
        'architecture': args.arch,
        'language': args.language,
        'web_languages': ['en-US', 'zh-CN'],
        'binaries': {args.arch: sha256(binary)},
    })


def sbom(args):
    dependencies = json.loads((args.source / 'packaging/web-dependencies.json').read_text(encoding='utf-8'))
    components = []
    for kind, name in [('core', '@tabler/core'), ('icons', '@tabler/icons')]:
        item = dependencies[kind]
        integrity = item['integrity']
        if not integrity.startswith('sha512-'):
            raise ValueError('Expected npm SHA-512 package integrity')
        components.append({
            'type': 'library', 'bom-ref': name, 'name': name, 'version': item['version'],
            'purl': 'pkg:npm/' + name.replace('@', '%40', 1) + '@' + item['version'],
            'licenses': [{'license': {'id': 'MIT'}}],
            'hashes': [{'alg': 'SHA-512', 'content': base64.b64decode(integrity[7:], validate=True).hex()}],
            'externalReferences': [{'type': 'distribution', 'url': item['tarball']}],
        })
    for key, name in [('bootstrap', 'bootstrap'), ('popper', '@popperjs/core')]:
        version = dependencies['bundled'][key]
        components.append({'type': 'library', 'bom-ref': name, 'name': name, 'version': version,
                           'purl': 'pkg:npm/' + name.replace('@', '%40', 1) + '@' + version,
                           'licenses': [{'license': {'id': 'MIT'}}]})
    modules = (args.source / 'vendor/modules.txt').read_text(encoding='utf-8')
    for name, version in re.findall(r'^# (golang\.org/x/(?:net|sys)) (v\S+)$', modules, re.M):
        item = {'type': 'library', 'bom-ref': name, 'name': name, 'version': version,
                'purl': 'pkg:golang/' + name + '@' + version,
                'licenses': [{'license': {'id': 'BSD-3-Clause'}}]}
        if name.endswith('/net'):
            item['properties'] = [{'name': 'portbridge:vendor-patched', 'value': 'true'}]
        components.append(item)
    for language in ('en-US', 'zh-CN'):
        for arch in ('amd64', 'arm64'):
            name = f'portbridge-v{args.version}-linux-{arch}-{language}.tar.gz'
            components.append({'type': 'file', 'bom-ref': name, 'name': name,
                               'hashes': [{'alg': 'SHA-256', 'content': sha256(args.root / name)}],
                               'properties': [{'name': 'portbridge:architecture', 'value': arch},
                                              {'name': 'portbridge:package-language', 'value': language}]})
    write_json(args.root / 'SBOM', {
        'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
        'metadata': {
            'component': {'type': 'application', 'bom-ref': 'portbridge', 'name': 'Go-nftables-portbridge', 'version': args.version},
            'properties': [{'name': 'portbridge:source-revision', 'value': args.revision},
                           {'name': 'portbridge:source-date-epoch', 'value': str(args.epoch)},
                           {'name': 'portbridge:go-toolchain', 'value': args.toolchain}],
        },
        'components': components,
        'dependencies': [{'ref': 'portbridge', 'dependsOn': ['@tabler/core', '@tabler/icons', 'golang.org/x/net', 'golang.org/x/sys']},
                         {'ref': '@tabler/core', 'dependsOn': ['bootstrap', '@popperjs/core']}],
    })


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['bundle', 'sbom'])
    parser.add_argument('root', type=pathlib.Path)
    parser.add_argument('version')
    parser.add_argument('revision')
    parser.add_argument('toolchain')
    parser.add_argument('--arch', choices=['amd64', 'arm64'])
    parser.add_argument('--language', choices=['en-US', 'zh-CN'])
    parser.add_argument('--source', type=pathlib.Path)
    parser.add_argument('--epoch', type=int, default=0)
    args = parser.parse_args()
    if not re.fullmatch(r'\d+\.\d+\.\d+', args.version) or not re.fullmatch(r'[0-9a-f]{40}', args.revision):
        parser.error('Invalid release version or source revision')
    if args.mode == 'bundle' and (args.arch is None or args.language is None):
        parser.error('Bundle metadata requires architecture and language')
    if args.mode == 'sbom' and args.source is None:
        parser.error('SBOM requires a source directory')
    (bundle if args.mode == 'bundle' else sbom)(args)
