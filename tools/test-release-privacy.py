"""Regression tests for the publication boundary; no debugger or network use."""

import contextlib
import io
import json
import pathlib
import posixpath
import re
import struct
import subprocess
import tempfile
import unittest
import zlib
import zipfile
from types import SimpleNamespace
from unittest import mock

import privacy
import release


class PrivacyTests(unittest.TestCase):
    @staticmethod
    def png_chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))

    def png(self, metadata=()):
        header = struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)
        pixels = zlib.compress(b'\0abc', level=0)
        return (b'\x89PNG\r\n\x1a\n' + self.png_chunk(b'IHDR', header) + b''.join(metadata)
                + self.png_chunk(b'IDAT', pixels) + self.png_chunk(b'IEND', b''))

    def test_png_compressed_pixels_do_not_become_identifier_strings(self):
        raw = self.png()
        self.assertIn(b'abc', raw)
        patterns = (re.compile('abc', re.I),)
        self.assertFalse(privacy.findings('docs/screenshots/example.png', raw, private_patterns=patterns))
        self.assertIn(('restricted-identifier', 0), privacy.findings('module.dll', raw, private_patterns=patterns))

    def test_png_metadata_is_scanned_including_compressed_and_unicode_text(self):
        value = ('C:' + '/Users/' + 'private-account/source').encode()
        chunks = (
            self.png_chunk(b'tEXt', b'Comment\0' + value),
            self.png_chunk(b'zTXt', b'Comment\0\0' + zlib.compress(value)),
            self.png_chunk(b'iTXt', b'Comment\0\1\0en\0Description\0' + zlib.compress(value)),
            self.png_chunk(b'iCCP', b'Profile\0\0' + zlib.compress(value)),
            self.png_chunk(b'eXIf', b'X' + value.decode().encode('utf-16-le')),
        )
        for chunk in chunks:
            with self.subTest(kind=chunk[4:8]):
                self.assertIn(('user-profile', 0), privacy.findings('example.png', self.png((chunk,))))
        private = '\uac00\ub098\ub2e4'
        chunk = self.png_chunk(b'iTXt', b'Comment\0\0\0\0\0' + private.encode())
        self.assertIn(('restricted-identifier', 0), privacy.findings('example.png', self.png((chunk,)),
                      private_patterns=(re.compile(private),)))

    def test_png_malformed_or_oversized_metadata_fails_closed(self):
        raw = self.png()
        corrupt_crc = bytearray(raw)
        corrupt_crc[-1] ^= 1
        bad_metadata = (
            self.png_chunk(b'zTXt', b'Comment\0\0broken'),
            self.png_chunk(b'iTXt', b'Comment\0\2\0\0\0data'),
            self.png_chunk(b'zTXt', b'Comment\0\0' + zlib.compress(b'x' * (4 * 1024 * 1024 + 1))),
            self.png_chunk(b'zTXt', b'Comment\0\0' + zlib.compress(b'fine') + b'trailing'),
        )
        samples = [raw[:-1], bytes(corrupt_crc), raw + b'trailing', b'not a PNG']
        samples.extend(self.png((chunk,)) for chunk in bad_metadata)
        for sample in samples:
            with self.subTest(length=len(sample)):
                self.assertEqual(privacy.findings('example.png', sample), [('unreadable-image', 0)])
                with self.assertRaises(ValueError):
                    privacy.require_public('example.png', sample)

    def test_png_idat_cannot_hide_plaintext_or_bytes_outside_the_raster(self):
        header = self.png()[:33]
        end = self.png_chunk(b'IEND', b'')
        token = ('ghp_' + 'a1B2' * 10).encode()
        cases = (token, zlib.compress(b'\0abc') + token, zlib.compress(b'\0abc' + token),
                 zlib.compress(b'\0abc') + zlib.compress(token), zlib.compress(b'\0ab'),
                 zlib.compress(b'\5abc'), zlib.compress(b'\0abc')[:-1], b'')
        for data in cases:
            raw = header + self.png_chunk(b'IDAT', data) + end
            with self.subTest(size=len(data)):
                self.assertEqual(privacy.findings('example.png', raw), [('unreadable-image', 0)])
                with self.assertRaises(ValueError) as caught:
                    privacy.require_public('example.png', raw)
                self.assertNotIn(token.decode(), str(caught.exception))

    def test_empty_png_is_distinct_from_path_preflight(self):
        privacy.require_public('docs/screenshots/example.png', None)
        with self.assertRaises(ValueError):
            privacy.require_public('docs/screenshots/example.png', b'')
        patterns = (re.compile('private_name'),)
        with self.assertRaises(ValueError):
            privacy.require_public('docs/screenshots/private_name.png', None, private_patterns=patterns)
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'empty.png').write_bytes(b'')
            with mock.patch.object(privacy, 'git_names', return_value=['empty.png']):
                with self.assertRaises(ValueError):
                    privacy.check_repository(root)
            with mock.patch.object(release, 'ROOT', root), mock.patch.object(release, 'git_names', return_value=['empty.png']):
                with self.assertRaises(ValueError):
                    release.source_manifest()

    def test_png_layout_is_validated_before_decompression(self):
        for width, height, depth, color, compression, filtering, interlace in (
                (0, 1, 8, 2, 0, 0, 0), (1, 1, 4, 2, 0, 0, 0), (1, 1, 8, 1, 0, 0, 0),
                (1, 1, 8, 2, 1, 0, 0), (1, 1, 8, 2, 0, 1, 0), (1, 1, 8, 2, 0, 0, 2),
                (2 ** 31, 1, 8, 2, 0, 0, 0), (100000, 100000, 8, 2, 0, 0, 0)):
            header = struct.pack('>IIBBBBB', width, height, depth, color, compression, filtering, interlace)
            raw = self.png()[:8] + self.png_chunk(b'IHDR', header) + self.png()[33:]
            with self.subTest(layout=(width, height, depth, color, compression, filtering, interlace)):
                with mock.patch.object(privacy.zlib, 'decompressobj') as decoder:
                    self.assertEqual(privacy.findings('example.png', raw), [('unreadable-image', 0)])
                    decoder.assert_not_called()

    def test_png_interlaced_and_split_image_streams_are_supported(self):
        header = struct.pack('>IIBBBBB', 3, 3, 8, 2, 0, 0, 1)
        # The nonempty Adam7 passes contain 1, 1, 2, 2 and 3 pixels, in six scanlines.
        pixels = b'\0abc\0def\0ghijkl\0mno\0pqr\0stuvwxyza'
        data = zlib.compress(pixels)
        chunks = b''.join(self.png_chunk(b'IDAT', data[i:i + 1]) for i in range(len(data)))
        raw = self.png()[:8] + self.png_chunk(b'IHDR', header) + chunks + self.png_chunk(b'IEND', b'')
        self.assertFalse(privacy.findings('example.png', raw))
        for changed in (pixels[:-1], pixels + b'extra'):
            raw = self.png()[:8] + self.png_chunk(b'IHDR', header) + self.png_chunk(b'IDAT', zlib.compress(changed)) + self.png_chunk(b'IEND', b'')
            self.assertEqual(privacy.findings('example.png', raw), [('unreadable-image', 0)])

    def test_png_palette_and_chunk_order_fail_closed(self):
        header = struct.pack('>IIBBBBB', 1, 1, 1, 3, 0, 0, 0)
        prefix = self.png()[:8] + self.png_chunk(b'IHDR', header)
        data = self.png_chunk(b'IDAT', zlib.compress(b'\0\0'))
        palette = self.png_chunk(b'PLTE', b'\xff\0\0\0\xff\0')
        end = self.png_chunk(b'IEND', b'')
        self.assertFalse(privacy.findings('example.png', prefix + palette + data + end))
        cases = (prefix + data + end, prefix + palette + palette + data + end,
                 prefix + self.png_chunk(b'PLTE', b'\0' * 9) + data + end,
                 prefix + palette + data + palette + end,
                 prefix + palette + data + self.png_chunk(b'tEXt', b'Comment\0public') + data + end,
                 prefix + self.png_chunk(b'abcd', b'public') + palette + data + end)
        for raw in cases:
            with self.subTest(size=len(raw)):
                self.assertEqual(privacy.findings('example.png', raw), [('unreadable-image', 0)])

    def test_credentials_report_only_categories(self):
        token = 'ghp_' + 'a1B2' * 10
        issues = privacy.findings('src/example.cpp', token.encode())
        self.assertEqual(issues, [('credential-token', 1)])
        with self.assertRaises(ValueError) as caught:
            privacy.require_public('README.md', token.encode())
        self.assertNotIn(token, str(caught.exception))

    def test_private_key_and_authenticated_url(self):
        key = '-----BEGIN ' + 'PRIVATE KEY-----'
        url = 'https://' + 'account:password' + '@example.invalid'
        self.assertIn(('private-key', 1), privacy.findings('test.txt', key.encode()))
        self.assertIn(('authenticated-url', 1), privacy.findings('test.txt', url.encode()))

    def test_quoted_json_credentials(self):
        content = ('{"api_key": "' + 'abc123XYZ789' + '"}').encode()
        self.assertIn(('credential-assignment', 1), privacy.findings('settings.json', content))

    def test_binary_paths_in_ascii_and_both_utf16_alignments(self):
        value = 'C:' + '/Users/' + 'private-account/source'
        for raw in (value.encode(), value.encode('utf-16-le'), b'X' + value.encode('utf-16-le')):
            with self.subTest(raw_length=len(raw)):
                self.assertIn(('user-profile', 0), privacy.findings('module.dll', raw))

    def test_actual_checkout_path_in_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            value = str(root / 'source.cpp').encode('utf-16-le')
            self.assertIn(('checkout-path', 0), privacy.findings('module.dll', value, root))

    def test_keyboard_navigation_prose_is_not_a_user_profile(self):
        self.assertFalse(privacy.findings('docs/UX.md', b'arrows/Home/End/Enter'))

    def test_document_paths_use_example_roots(self):
        self.assertIn(('machine-path-in-document', 1),
                      privacy.findings('docs/history.md', br'Z:\private-machine\capture'))
        for path in (br'C:\evidence\sample.json', b'C:/path/to/module.dll',
                     br'C:\Program Files\Debugger', br'C:\Windows\System32'):
            with self.subTest(path=path):
                self.assertFalse(privacy.findings('docs/guide.md', path))

    def test_local_capture_paths_are_not_publication_inputs(self):
        for name in ('docs/images/session.jpg', 'docs/videos/session.mp4',
                     'DOCS/IMAGES/nested/capture.png', '.publication-terms.local.json'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                privacy.require_public(name, b'innocent')

    def test_ignored_media_cannot_bypass_publication_checks_by_forced_add(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            subprocess.run(['git', 'init', '-q', directory], check=True)
            (root / '.gitignore').write_bytes((release.ROOT / '.gitignore').read_bytes())
            image = root / 'docs/images/session.jpg'
            image.parent.mkdir(parents=True)
            image.write_bytes(b'local image')
            subprocess.run(['git', 'check-ignore', '-q', '--', 'docs/images/session.jpg'], cwd=root, check=True)
            self.assertEqual(privacy.check_repository(root), 1)
            subprocess.run(['git', 'add', '-f', '--', 'docs/images/session.jpg'], cwd=root, check=True)
            with self.assertRaises(ValueError):
                privacy.check_repository(root)
            image.unlink()
            with self.assertRaises(ValueError):
                privacy.check_repository(root)
            with mock.patch.object(release, 'ROOT', root), self.assertRaises(ValueError):
                release.source_manifest()

    def test_private_terms_cover_variants_file_names_and_binary_strings(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = pathlib.Path(directory) / 'terms.local.json'
            policy.write_text(json.dumps({'terms': ['Example Client']}), encoding='utf-8')
            patterns = privacy.load_private_terms(policy)
            for value in ('exampleclient', 'EXAMPLE_CLIENT', 'Example-Client', 'Example Client'):
                for name, raw, line in (('src/example.cpp', value.encode(), 1),
                                        ('module.dll', value.encode(), 0),
                                        ('module.dll', value.encode('utf-16-le'), 0),
                                        ('module.dll', b'X' + value.encode('utf-16-le'), 0)):
                    with self.subTest(value=value, name=name, size=len(raw)):
                        self.assertIn(('restricted-identifier', line),
                                      privacy.findings(name, raw, private_patterns=patterns))
            with self.assertRaises(ValueError) as caught:
                privacy.require_public('src/ExampleClient.cpp', b'innocent', private_patterns=patterns)
            self.assertNotIn('ExampleClient', str(caught.exception))
            self.assertFalse(privacy.findings('src/public.cpp', b'public component', private_patterns=patterns))

    def test_private_policy_errors_fail_closed_without_echo(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = pathlib.Path(directory) / 'private-policy.local.json'
            self.assertEqual(privacy.load_private_terms(policy, optional=True), ())
            with self.assertRaises(ValueError):
                privacy.load_private_terms(policy)
            invalid = (b'{private text', b'\xff', b'[]', b'{"terms":[]}',
                       b'{"terms":[1]}', b'{"terms":["a_"]}', b'{"terms":["--"]}',
                       b'{"terms":["Example Client"],"terms":["Harmless"]}',
                       json.dumps({'terms': ['invalid' + chr(0xd800)]}).encode(),
                       json.dumps({'terms': ['x' * 129]}).encode(),
                       json.dumps({'terms': ['valid'] * 257}).encode(), b' ' * 65537)
            for raw in invalid:
                policy.write_bytes(raw)
                with self.subTest(size=len(raw)), self.assertRaises(ValueError) as caught:
                    privacy.load_private_terms(policy, optional=True)
                self.assertEqual(str(caught.exception), 'Invalid private term policy')
                self.assertNotIn(str(policy), str(caught.exception))

    def test_private_terms_apply_to_manifest_and_packaging_before_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            subprocess.run(['git', 'init', '-q', directory], check=True)
            policy = root / 'terms.local.json'
            policy.write_text(json.dumps({'terms': ['Example Client']}), encoding='utf-8')
            patterns = privacy.load_private_terms(policy)
            (root / '.gitignore').write_text('*.local.*\n', encoding='utf-8')
            (root / 'README.md').write_text('ExampleClient', encoding='utf-8')
            subprocess.run(['git', 'add', '--', 'README.md'], cwd=root, check=True)
            output = root / 'package.zip'
            with mock.patch.object(release, 'ROOT', root):
                with self.assertRaises(ValueError):
                    release.source_manifest(patterns)
                with self.assertRaises(ValueError):
                    release.package('Release', output, patterns)
            self.assertFalse(output.exists())

    def test_packaged_support_profile_links_resolve_to_exact_profile_bytes(self):
        def content(root, name):
            if name == 'docs/SUPPORT.md' or name.startswith('profiles/'):
                return (root / name).read_bytes()
            if name.endswith('.png'):
                return self.png()
            return b'public package fixture\n'

        lock = {'package': 'Fixture', 'version': '1.0', 'packageSha256': '0' * 64}
        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as patches:
            for name, value in (('check_repository', None), ('generated_docs', []), ('dependencies', lock),
                                ('binary_evidence', {}), ('source_manifest', {}), ('run', '')):
                patches.enter_context(mock.patch.object(release, name, return_value=value))
            patches.enter_context(mock.patch.object(release, 'read_public_file', side_effect=content))
            patches.enter_context(contextlib.redirect_stdout(io.StringIO()))
            output = pathlib.Path(directory) / 'package.zip'
            release.package('Release', output)
            with zipfile.ZipFile(output) as archive:
                support = archive.read('docs/SUPPORT.md').decode('utf-8')
                links = re.findall(r'\]\((\.\./profiles/[^)#]+\.json)\)', support)
                self.assertTrue(links)
                manifest = json.loads(archive.read('release-manifest.json'))
                for link in links:
                    name = posixpath.normpath('docs/' + link)
                    with self.subTest(profile=name):
                        self.assertIn(name, archive.namelist())
                        self.assertEqual(archive.read(name), (release.ROOT / name).read_bytes())
                        self.assertEqual(manifest['files'][name], release.digest(archive.read(name)))

    def test_release_cli_loads_default_policy_and_rejects_missing_explicit_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            subprocess.run(['git', 'init', '-q', directory], check=True)
            (root / '.gitignore').write_text('*.local.*\n', encoding='utf-8')
            policy = root / '.publication-terms.local.json'
            policy.write_text(json.dumps({'terms': ['Example Client']}), encoding='utf-8')
            document = root / 'README.md'
            document.write_text('ExampleClient', encoding='utf-8')
            with mock.patch.object(release, 'ROOT', root):
                with mock.patch('sys.argv', ['release.py', 'check-privacy']), self.assertRaises(ValueError):
                    release.main()
                document.write_text('public example', encoding='utf-8')
                output = io.StringIO()
                with mock.patch('sys.argv', ['release.py', 'check-privacy']), contextlib.redirect_stdout(output):
                    release.main()
                self.assertIn('private term rules: 1', output.getvalue())
                self.assertNotIn('Example Client', output.getvalue())
                with mock.patch('sys.argv', ['release.py', 'package']), mock.patch.object(release, 'package') as package:
                    release.main()
                self.assertIsNotNone(package.call_args.args[2][0].search('ExampleClient'))
                with mock.patch('sys.argv', ['release.py', 'check-privacy', '--private-terms-file', str(root / 'missing.local.json')]), self.assertRaises(ValueError):
                    release.main()

    def test_release_policy_cannot_reside_in_a_publishable_checkout_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / 'checkout'
            root.mkdir()
            public_policy = root / 'review-policy.json'
            content = r'{"terms":["Example\u0043lient"]}'
            public_policy.write_text(content, encoding='utf-8')
            local_policy = root / 'terms.local.json'
            local_policy.write_text(content, encoding='utf-8')
            external_policy = pathlib.Path(directory) / 'policy.json'
            external_policy.write_text(content, encoding='utf-8')
            with mock.patch.object(release, 'ROOT', root):
                for mode in ('check-privacy', 'package'):
                    args = ['release.py', mode, '--private-terms-file', str(public_policy)]
                    with self.subTest(mode=mode), mock.patch('sys.argv', args):
                        with mock.patch.object(release, 'check_repository') as scan, mock.patch.object(release, 'package') as package:
                            with self.assertRaises(ValueError) as caught:
                                release.main()
                            self.assertEqual(str(caught.exception), 'Private term policy must use a local-only path')
                            self.assertNotIn(str(public_policy), str(caught.exception))
                            scan.assert_not_called()
                            package.assert_not_called()
                for policy in (local_policy, external_policy):
                    self.assertIsNotNone(release.publication_terms(policy)[0].search('ExampleClient'))
                with mock.patch.object(pathlib.Path, 'resolve', autospec=True, side_effect=lambda path: public_policy if path == local_policy else path):
                    with self.assertRaises(ValueError):
                        release.publication_terms(local_policy)

    def test_session_pids_require_redaction_except_well_known_controls(self):
        self.assertIn(('session-process-id', 1), privacy.findings('docs/history.md', b'engine PID 1234'))
        self.assertFalse(privacy.findings('docs/history.md', b'System PID 4; Idle TID 0; invalid pid:4294967295'))

    def test_documents_reject_target_addresses_but_code_fixtures_remain(self):
        address = ('0x' + 'ffff8000' + '00001000').encode()
        self.assertTrue(privacy.findings('docs/history.md', address))
        self.assertFalse(privacy.findings('src/selftest/Test.cpp', address))
        self.assertFalse(privacy.findings('docs/history.md', b'`TARGET_ADDRESS_01`'))

    def test_private_inputs_and_agent_files_at_any_depth(self):
        for name in ('kndbgx.pdb', 'docs/AGENTS.override.md', 'src/agents.md', '.env',
                     '.env.production', 'keys/client.pfx', 'target.dmp', 'capture.etl',
                     'docs/do-not-commit/session.json', 'profiles/test.local.json',
                     'artifacts/evidence.json', 'x64/Release/build.json', '../outside.txt',
                     'file.txt:stream', '/outside.txt'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                privacy.require_public(name, b'innocent')

    def test_sensitive_file_name_is_rejected_without_echo(self):
        name = 'ghp_' + 'a1B2' * 10 + '.cpp'
        with self.assertRaises(ValueError) as caught:
            privacy.require_public(name, b'innocent')
        self.assertNotIn(name, str(caught.exception))

    def test_codeview_requires_basename_even_for_unknown_build_directories(self):
        privacy.require_pdb_basename(b'kndbgx.pdb\0')
        for record in (b'X:/build/project.pdb\0', b'../project.pdb\0', b'project.pdb', b'project.pdb:stream\0'):
            with self.subTest(record=record), self.assertRaises(ValueError):
                privacy.require_pdb_basename(record)

    def test_public_profile_and_copyright_identity_are_preserved(self):
        privacy.require_public('profiles/nt-example.json', b'{"rva":"0x1234","age":1}')
        privacy.require_public('THIRD_PARTY_NOTICES.md', b'Copyright Microsoft Corporation')

    def test_invalid_text_fails_closed(self):
        for name in ('docs/test.md', 'src/example.cpp', 'settings.json'):
            for raw in (b'\xff\xfe', 'ExampleClient'.encode('utf-16-le'), b'prefix\0suffix'):
                with self.subTest(name=name, size=len(raw)):
                    self.assertEqual(privacy.findings(name, raw), [('unreadable-text', 1)])
                    with self.assertRaises(ValueError):
                        privacy.require_public(name, raw)

    def test_traversal_and_links_fail_before_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'README.md').write_text('safe', encoding='utf-8')
            for name in ('../secret.txt', 'C:/secret.txt', 'README.md:stream', 'sub\\file.md'):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    privacy.read_public_file(root, name)
            with mock.patch.object(pathlib.Path, 'is_symlink', return_value=True):
                with self.assertRaises(ValueError):
                    privacy.read_public_file(root, 'README.md')

    def test_junction_attributes_are_read_without_following_the_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'README.md').write_text('safe', encoding='utf-8')
            attributes = SimpleNamespace(st_file_attributes=0x400)
            with mock.patch.object(pathlib.Path, 'is_symlink', return_value=False), mock.patch.object(pathlib.Path, 'lstat', return_value=attributes):
                with self.assertRaises(ValueError):
                    privacy.read_public_file(root, 'README.md')

    def test_manifest_never_enumerates_untracked_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            subprocess.run(['git', 'init', '-q', directory], check=True)
            (root / 'README.md').write_text('public', encoding='utf-8')
            (root / 'internal-customer-notes.txt').write_text('private', encoding='utf-8')
            subprocess.run(['git', 'add', '--', 'README.md'], cwd=root, check=True)
            with mock.patch.object(release, 'ROOT', root):
                self.assertEqual(set(release.source_manifest()), {'README.md'})

    def test_manifest_excludes_nested_agent_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'README.md').write_text('public', encoding='utf-8')
            with mock.patch.object(release, 'ROOT', root), mock.patch.object(release, 'git_names', return_value=['README.md', 'docs/AGENTS.md', 'AGENTS.override.md']):
                self.assertEqual(set(release.source_manifest()), {'README.md'})

    def test_tracked_private_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'capture.dmp').write_bytes(b'private')
            with mock.patch.object(release, 'ROOT', root), mock.patch.object(release, 'git_names', return_value=['capture.dmp']):
                with self.assertRaises(ValueError):
                    release.source_manifest()

    def test_repository_scan_includes_untracked_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'new.cpp').write_text('ghp_' + 'a1B2' * 10, encoding='utf-8')
            with mock.patch.object(privacy, 'git_names', return_value=['new.cpp']) as names:
                with self.assertRaises(ValueError):
                    privacy.check_repository(root)
                names.assert_called_once_with(root, include_untracked=True)


if __name__ == '__main__':
    unittest.main()
