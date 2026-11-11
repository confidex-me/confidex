"""Check the shared release-name examples and reject unknown packages."""
import json
import unittest
from pathlib import Path

from artifacts import filename, parse


class ArtifactTests(unittest.TestCase):
    def test_shared_examples(self):
        examples = json.loads(Path(__file__).with_name('fixtures').joinpath('artifacts.json').read_text())
        for example in examples:
            with self.subTest(name=example['name']):
                self.assertEqual(parse(example['name']), example['expected'])
                if example['expected']:
                    self.assertIsNone(parse(example['name'] + '\n'))

    def test_builder_rejects_unpublished_formats(self):
        self.assertEqual(filename('confidex', '1.2.3+gabcdef', 'arm64-macos', 'dmg'),
                         'confidex-1.2.3+gabcdef-arm64-macos.dmg')
        for product, target, extension in [('cfdex', 'arm64-macos', 'dmg'),
                                            ('confidex', 'x86_64-macos', 'dmg'),
                                            ('confidex', 'amd64-linux', 'tar.gz')]:
            with self.assertRaises(ValueError):
                filename(product, '1.2.3+gabcdef', target, extension)


if __name__ == '__main__':
    unittest.main()
