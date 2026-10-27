"""Translation guards do not require a model and never change audit findings."""
import importlib.util
from pathlib import Path
import unittest

script = Path(__file__).resolve().parents[1] / 'scripts' / 'hcp-description-translate.py'
spec = importlib.util.spec_from_file_location('description_translation', script)
translation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(translation)


class TranslationTests(unittest.TestCase):
    def test_standard_advisory_retains_component_version_and_attacker_preconditions(self):
        original = 'Use after free in Serviceworker in Google Chrome on Desktop prior to 140.0.7339.127 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Critical)'
        result = translation.translate(original, '/not-needed-for-standard-prose')
        self.assertIn('Использование памяти после освобождения', result)
        self.assertIn('Serviceworker', result)
        self.assertIn('настольной версии Google Chrome', result)
        self.assertIn('140.0.7339.127', result)
        self.assertIn('позволяло удалённому злоумышленнику потенциально', result)
        self.assertIn('повреждение памяти в куче', result)
        translation.verify_identifiers(original, result)
        self.assertIsNone(translation.chromium_description(original.replace('a remote attacker', 'an attacker with a different precondition')))
        self.assertIsNone(translation.chromium_description(original + ' Additional caveat.'))

    def test_technical_terms_and_component_names_cannot_disappear(self):
        original = 'Use after free in Serviceworker in Google Chrome allowed heap corruption.'
        masked, terms = translation.protect_terms(original)
        self.assertNotIn('Use after free', masked)
        self.assertNotIn('Serviceworker', masked)
        self.assertNotIn('heap corruption', masked)
        result = translation.restore_terms(masked, terms)
        self.assertIn('Использование памяти после освобождения', result)
        self.assertIn('Serviceworker', result)
        self.assertIn('повреждение памяти в куче', result)
        with self.assertRaises(ValueError):
            translation.restore_terms(masked.replace('HCPTERM000', ''), terms)
        with self.assertRaises(ValueError):
            translation.restore_terms(masked + ' HCPTERM000', terms)

    def test_identifiers_and_versions_must_survive_unchanged(self):
        original = 'CVE-2024-10487 affects 130.0.6723.92 (CWE-787).'
        translation.verify_identifiers(original, 'CVE-2024-10487 затрагивает 130.0.6723.92 (CWE-787).')
        for bad in ('CVE-2024-10487 затрагивает 131.0.6723.92 (CWE-787).', 'Уязвимость затрагивает 130.0.6723.92 (CWE-787).', original):
            with self.assertRaises(ValueError):
                translation.verify_identifiers(original, bad)

    def test_oversized_text_fails_before_loading_a_model(self):
        for text in (None, '', 'x' * 20001):
            with self.assertRaises(ValueError):
                translation.translate(text, '/unavailable')

    def test_greenbone_versions_ports_and_ssh_algorithms_are_preserved(self):
        original = 'Installed version: 8.4p1; Fixed version: 9.3p2; 22/tcp; diffie-hellman-group14-sha256'
        masked, terms = translation.protect_terms(original)
        for token in ('8.4p1', '9.3p2', '22/tcp', 'diffie-hellman-group14-sha256'):
            self.assertNotIn(token, masked)
            self.assertIn(token, translation.restore_terms(masked, terms))
        with self.assertRaises(ValueError):
            translation.verify_identifiers(original, 'Установлено: 8.4p2; исправлено: 9.3p2; 22/tcp; diffie-hellman-group14-sha256')


if __name__ == '__main__':
    unittest.main()
