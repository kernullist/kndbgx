"""Bounded publication checks. Diagnostics never include matched content."""

import json
import pathlib
import re
import struct
import subprocess
import zlib


TEXT_SUFFIXES = {'.md', '.txt', '.json', '.py', '.ps1', '.cpp', '.h', '.hpp', '.js',
                 '.mjs', '.cjs', '.css', '.html', '.xml', '.props', '.targets',
                 '.vcxproj', '.sln', '.yaml', '.yml', '.toml', '.ini', '.config', '.svg'}
RULES = {
    'private-key': r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----',
    'credential-token': r'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|glpat-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{20,}|sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,})\b',
    'credential-assignment': r'''(?i)(?:api[_-]?key|password|passwd|client[_-]?secret|access[_-]?token)\s*["']?\s*[:=]\s*["'][^"'\r\n]{8,}["']''',
    'authenticated-url': r'''(?i)https?://[^\s/<>"']+:[^\s/<>"']+@''',
    'user-profile': r'''(?:(?i:[a-z]:[\\/]+(?:users|documents and settings))|/(?:home|Users))[\\/]+[^\s"'<>\\/]+''',
    'machine-workspace': r'(?i)[a-z]:[\\/]+(?:kernullist|kn-live-dbg|worktrees|repos)[\\/]',
    'account-sid': r'\bS-1-5-21-(?:\d+-){2}\d+(?:-\d+)?\b',
    'debugger-key': r'(?i)\bkey=(?:[a-z0-9]{4,}\.){3}[a-z0-9]{4,}\b',
}
PATTERNS = {kind: re.compile(pattern) for kind, pattern in RULES.items()}
TARGET_ADDRESS = re.compile(r'(?i)\b(?:0x)?(?:ffff[0-9a-f]{4}|0000(?:7ff|00d)[0-9a-f])`?[0-9a-f]{8}\b')
SESSION_PID = re.compile(r'(?i)\b(?:PIDs?|TID)(?:\s+|:)`?(\d+)')
DOCUMENT_DRIVE_PATH = re.compile(r'''(?i)\b[a-z]:[\\/]+([^\\/\r\n`"'<>*|]+)''')
DOCUMENT_EXAMPLE_ROOTS = {'path', 'captures', 'evidence', 'lab', 'debuggers', 'dump', 'symbols',
                          'windows', 'program files', 'program files (x86)'}
PRIVATE_DIRS = {'.git', '.vs', '.ssh', '.aws', 'artifacts', 'do-not-commit',
                'node_modules', '__pycache__', 'secrets', 'credentials', 'private'}
PRIVATE_SUFFIXES = {'.pdb', '.dmp', '.mdmp', '.hdmp', '.etl', '.evtx', '.log',
                    '.pem', '.key', '.pfx', '.p12', '.jks', '.kdbx', '.user', '.aps', '.binlog'}


def private_path(name):
    path = pathlib.PurePosixPath(name.replace('\\', '/'))
    parts = [part.lower() for part in path.parts]
    if path.is_absolute() or any(part in ('..', '') or ':' in part for part in parts):
        return True
    if any(part in PRIVATE_DIRS for part in parts):
        return True
    if len(parts) >= 2 and parts[0] == 'docs' and parts[1] in ('images', 'videos'):
        return True
    leaf = path.name.lower()
    return (leaf in {'agents.md', 'agents.override.md', 'id_rsa', 'id_ed25519', '.netrc', '.npmrc'}
            or leaf == '.env' or leaf.startswith('.env.') or '.local.' in leaf
            or path.suffix.lower() in PRIVATE_SUFFIXES
            or (parts and parts[0] == 'x64'))


def read_public_file(root, name):
    """Refuse traversal, links and junctions before reading publication inputs."""
    relative = pathlib.PurePosixPath(name)
    if relative.is_absolute() or not relative.parts or any(part in ('..', '.') or ':' in part or '\\' in part for part in relative.parts):
        raise ValueError('Invalid publication path')
    root = root.resolve()
    path = root.joinpath(*relative.parts)
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink() or getattr(current.lstat(), 'st_file_attributes', 0) & 0x400:
            raise ValueError('Publication input is a link or reparse point')
    if not path.resolve().is_relative_to(root):
        raise ValueError('Publication input is outside the repository')
    return path.read_bytes()


def load_private_terms(path, optional=False):
    """Load local-only terms without including values or paths in diagnostics."""
    try:
        with pathlib.Path(path).open('rb') as stream:
            content = stream.read(65537)
    except FileNotFoundError:
        if optional and not pathlib.Path(path).is_symlink():
            return ()
        raise ValueError('Private term policy could not be read') from None
    except OSError:
        raise ValueError('Private term policy could not be read') from None
    try:
        if len(content) > 65536:
            raise ValueError('Size limit')
        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError('Duplicate policy key')
                result[key] = value
            return result
        policy = json.loads(content.decode('utf-8-sig'), object_pairs_hook=unique_object)
        if not isinstance(policy, dict) or set(policy) != {'terms'}:
            raise ValueError('Invalid schema')
        terms = policy['terms']
        if not isinstance(terms, list) or not 1 <= len(terms) <= 256:
            raise ValueError('Invalid term count')
        patterns = []
        for term in terms:
            if not isinstance(term, str) or not 2 <= len(term.strip()) <= 128 or any(ord(char) < 32 for char in term):
                raise ValueError('Invalid term')
            term.encode('utf-8')
            parts = [part for part in re.split(r'[\s_-]+', term.strip()) if part]
            if not parts or len(''.join(parts)) < 2:
                raise ValueError('Empty term')
            patterns.append(re.compile(r'[\s_-]*'.join(re.escape(part) for part in parts), re.I))
        return tuple(patterns)
    except (ValueError, UnicodeError):
        raise ValueError('Invalid private term policy') from None


def png_scanlines(header):
    """Return bounded PNG pass dimensions without decoding or retaining pixels."""
    width, height, depth, color, compression, filtering, interlace = struct.unpack('>IIBBBBB', header)
    depths = {0: (1, 2, 4, 8, 16), 2: (8, 16), 3: (1, 2, 4, 8), 4: (8, 16), 6: (8, 16)}
    if (not 0 < width < 2 ** 31 or not 0 < height < 2 ** 31 or depth not in depths.get(color, ())
            or compression or filtering or interlace not in (0, 1)):
        raise ValueError('Invalid PNG image layout')
    bits = depth * {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[color]
    passes = ((0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4),
              (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2)) if interlace else ((0, 0, 1, 1),)
    rows = []
    for x, y, dx, dy in passes:
        if width > x and height > y:
            columns, count = (width - x + dx - 1) // dx, (height - y + dy - 1) // dy
            rows.append((1 + (columns * bits + 7) // 8, count))
    if sum(stride * count for stride, count in rows) > 256 * 1024 * 1024:
        raise ValueError('PNG decoded image limit')
    return rows


def validate_png_pixels(chunks, rows):
    """Reject non-image payloads before exempting compressed raster bytes from text scans."""
    expected = sum(stride * count for stride, count in rows)
    decoder = zlib.decompressobj()
    pixels = decoder.decompress(b''.join(chunks), expected + 1)
    if len(pixels) != expected or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise ValueError('Invalid PNG image data')
    offset = 0
    for stride, count in rows:
        end = offset + stride * count
        if any(value > 4 for value in pixels[offset:end:stride]):
            raise ValueError('Invalid PNG scanline filter')
        offset = end


def png_metadata(content):
    """Scan PNG metadata, not compressed pixels. Visible text needs separate OCR review."""
    if not content.startswith(b'\x89PNG\r\n\x1a\n'):
        raise ValueError('Invalid PNG signature')
    offset = 8
    seen_header = False
    seen_data = False
    seen_palette = False
    data_closed = False
    remaining = 4 * 1024 * 1024
    parts = []
    image_chunks = []
    rows = []
    color = None
    depth = None

    def retain(data):
        nonlocal remaining
        if len(data) > remaining:
            raise ValueError('PNG metadata limit')
        remaining -= len(data)
        parts.append(data)

    def expand(data):
        decoder = zlib.decompressobj()
        decoded = decoder.decompress(data, remaining + 1)
        if len(decoded) > remaining or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
            raise ValueError('Invalid compressed PNG metadata')
        retain(decoded)

    while offset < len(content):
        if len(content) - offset < 12:
            raise ValueError('Truncated PNG chunk')
        length = int.from_bytes(content[offset:offset + 4], 'big')
        end = offset + length + 12
        if end > len(content):
            raise ValueError('PNG chunk boundary')
        kind = content[offset + 4:offset + 8]
        data = content[offset + 8:end - 4]
        crc = int.from_bytes(content[end - 4:end], 'big')
        if not re.fullmatch(b'[A-Za-z]{2}[A-Z][A-Za-z]', kind) or zlib.crc32(kind + data) != crc:
            raise ValueError('Invalid PNG chunk')
        if not seen_header and kind != b'IHDR':
            raise ValueError('Missing PNG header')
        if kind == b'IHDR':
            if seen_header or length != 13:
                raise ValueError('Invalid PNG header')
            rows = png_scanlines(data)
            depth, color = data[8:10]
            seen_header = True
        elif kind == b'PLTE':
            if seen_palette or seen_data or color in (0, 4) or not 0 < length <= 768 or length % 3:
                raise ValueError('Invalid PNG palette')
            if color == 3 and length // 3 > 2 ** depth:
                raise ValueError('PNG palette exceeds bit depth')
            seen_palette = True
        elif kind == b'IDAT':
            if data_closed or (color == 3 and not seen_palette):
                raise ValueError('Noncontiguous PNG image data')
            seen_data = True
            image_chunks.append(data)
        elif kind == b'IEND':
            if length or not seen_data or end != len(content):
                raise ValueError('Invalid PNG end')
            validate_png_pixels(image_chunks, rows)
            return parts
        elif kind[0] < ord('a') and kind != b'PLTE':
            raise ValueError('Unknown PNG critical chunk')
        if kind != b'IDAT':
            data_closed = seen_data
            retain(data)
            if kind in (b'zTXt', b'iCCP'):
                fields = data.split(b'\0', 1)
                if len(fields) != 2 or not 1 <= len(fields[0]) <= 79 or not fields[1].startswith(b'\0'):
                    raise ValueError('Invalid compressed PNG metadata')
                expand(fields[1][1:])
            elif kind == b'iTXt':
                fields = data.split(b'\0', 1)
                if len(fields) != 2 or not 1 <= len(fields[0]) <= 79 or len(fields[1]) < 4:
                    raise ValueError('Invalid PNG international text')
                flag, method = fields[1][:2]
                text_fields = fields[1][2:].split(b'\0', 2)
                if flag not in (0, 1) or method != 0 or len(text_fields) != 3:
                    raise ValueError('Invalid PNG international text')
                if flag:
                    expand(text_fields[2])
        offset = end
    raise ValueError('Missing PNG end')


def findings(name, content, root=None, private_patterns=()):
    """Return categories and line numbers only, including binary string encodings."""
    suffix = pathlib.PurePosixPath(name).suffix.lower()
    text_input = suffix in TEXT_SUFFIXES or name in ('.gitignore', '.clang-format')
    if text_input:
        try:
            texts = [content.decode('utf-8-sig')]
        except UnicodeDecodeError:
            return [('unreadable-text', 1)]
        if '\0' in texts[0]:
            return [('unreadable-text', 1)]
    else:
        blobs = [content]
        if suffix == '.png':
            try:
                blobs = png_metadata(content)
            except (ValueError, zlib.error):
                return [('unreadable-image', 0)]
        texts = []
        for blob in blobs:
            texts.extend((blob.decode('latin-1'), blob.decode('utf-16-le', errors='ignore'),
                          blob[1:].decode('utf-16-le', errors='ignore')))
            if suffix == '.png':
                texts.append(blob.decode('utf-8', errors='ignore'))
    result = set()
    for text in texts:
        for kind, pattern in PATTERNS.items():
            for match in pattern.finditer(text):
                result.add((kind, text.count('\n', 0, match.start()) + 1 if text_input else 0))
        for pattern in private_patterns:
            for match in pattern.finditer(text):
                result.add(('restricted-identifier', text.count('\n', 0, match.start()) + 1 if text_input else 0))
        if root is not None:
            normalized = text.lower().replace('\\\\', '/').replace('\\', '/')
            if str(root.resolve()).lower().replace('\\', '/') + '/' in normalized:
                result.add(('checkout-path', 0))
        if name.lower().endswith('.md'):
            for match in DOCUMENT_DRIVE_PATH.finditer(text):
                if match.group(1).strip().lower() not in DOCUMENT_EXAMPLE_ROOTS:
                    result.add(('machine-path-in-document', text.count('\n', 0, match.start()) + 1))
            for match in TARGET_ADDRESS.finditer(text):
                result.add(('target-address-in-document', text.count('\n', 0, match.start()) + 1))
            for match in SESSION_PID.finditer(text):
                if match.group(1) not in ('0', '4', '4294967295'):
                    result.add(('session-process-id', text.count('\n', 0, match.start()) + 1))
    return sorted(result)


def require_public(name, content, root=None, private_patterns=()):
    """Use None only for a path preflight; empty file content still receives format checks."""
    if private_path(name):
        raise ValueError('Private file is not a publication input')
    issues = findings('path.txt', name.encode('utf-8'), root, private_patterns)
    if content is not None:
        issues += findings(name, content, root, private_patterns)
    if issues:
        # Do not echo a possibly sensitive file name or matched value.
        raise ValueError('Publication privacy check failed: ' + ', '.join(sorted({kind for kind, _ in issues})))


def require_pdb_basename(record):
    try:
        name = record.split(b'\0', 1)[0].decode('utf-8')
    except UnicodeDecodeError as error:
        raise ValueError('Invalid CodeView PDB name') from error
    if not record.endswith(b'\0') or not name.lower().endswith('.pdb') or any(char in name for char in ('/', '\\', ':')):
        raise ValueError('CodeView PDB reference must contain only a file name')


def git_names(root, include_untracked=False):
    args = ['git', 'ls-files', '--cached', '-z']
    if include_untracked:
        args.extend(['--others', '--exclude-standard'])
    data = subprocess.check_output(args, cwd=root).decode('utf-8')
    return sorted(set(name for name in data.split('\0') if name))


def check_repository(root, private_patterns=()):
    names = git_names(root, include_untracked=True)
    count = 0
    for name in names:
        # Agent instructions are local context and never publication metadata.
        if pathlib.PurePosixPath(name).name.lower() in ('agents.md', 'agents.override.md'):
            continue
        require_public(name, None, root, private_patterns)
        if not (root / name).exists():
            continue
        require_public(name, read_public_file(root, name), root, private_patterns)
        count += 1
    return count
