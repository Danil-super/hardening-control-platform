#!/usr/bin/env python3
"""Install the pinned English/Russian Argos weights, without executing archive code."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import urllib.request
import zipfile

URL = 'https://argos-net.com/v1/translate-en_ru-1_9.argosmodel'
SHA256 = '591d743ae103752b88ffc38785c50421320f4eff93c8967e0d3d2e14d4e27811'
MAX_ARCHIVE = 256 * 1024 * 1024
PREFIX = 'translate-en_ru-1_9/'
FILES = ('README.md', 'metadata.json', 'sentencepiece.model',
         'model/shared_vocabulary.json', 'model/model.bin', 'model/config.json')


def install(archive, destination):
    archive = Path(archive)
    if not archive.is_file() or archive.stat().st_size > MAX_ARCHIVE:
        raise ValueError('Invalid model archive size')
    with archive.open('rb') as source:
        if hashlib.file_digest(source, 'sha256').hexdigest() != SHA256:
            raise ValueError('Translation model SHA-256 does not match')
    destination = Path(destination)
    if destination.exists():
        raise ValueError('Model destination already exists')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='hcp-language-', dir=destination.parent) as temporary:
        root = Path(temporary) / 'model'
        root.mkdir(mode=0o755)
        with zipfile.ZipFile(archive) as package:
            total = 0
            for relative in FILES:
                info = package.getinfo(PREFIX + relative)
                total += info.file_size
                if info.is_dir() or total > 320 * 1024 * 1024:
                    raise ValueError('Invalid model archive contents')
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                with package.open(info) as source, target.open('wb') as output:
                    shutil.copyfileobj(source, output)
                target.chmod(0o644)
        metadata = json.loads((root / 'metadata.json').read_text())
        if (metadata.get('from_code'), metadata.get('to_code'), metadata.get('package_version')) != ('en', 'ru', '1.9'):
            raise ValueError('Unexpected translation model language/version')
        (root / 'archive-sha256.txt').write_text(SHA256 + '\n')
        root.rename(destination)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive')
    parser.add_argument('--destination', required=True)
    args = parser.parse_args()
    if args.archive:
        install(args.archive, args.destination)
        return
    with tempfile.TemporaryDirectory(prefix='hcp-language-download-') as directory:
        archive = Path(directory) / 'model.zip'
        # Use the upstream Argos client's identity: the model CDN rejects the
        # default Python-urllib user agent with HTTP 403.
        request = urllib.request.Request(URL, headers={'User-Agent': 'ArgosTranslate'})
        with urllib.request.urlopen(request, timeout=900) as response, archive.open('wb') as output:
            size = 0
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                size += len(block)
                if size > MAX_ARCHIVE:
                    raise ValueError('Translation model archive exceeds size limit')
                output.write(block)
        install(archive, args.destination)


if __name__ == '__main__':
    main()
