"""Bounded publication checks. Diagnostics never include matched content."""

import json
import pathlib
import re
import subprocess


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
        texts = [content.decode('latin-1'), content.decode('utf-16-le', errors='ignore'),
                 content[1:].decode('utf-16-le', errors='ignore')]
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
    if private_path(name):
        raise ValueError('Private file is not a publication input')
    issues = findings(name, content, root, private_patterns) + findings('path.txt', name.encode('utf-8'), root, private_patterns)
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
        require_public(name, b'', root, private_patterns)
        if not (root / name).exists():
            continue
        require_public(name, read_public_file(root, name), root, private_patterns)
        count += 1
    return count
