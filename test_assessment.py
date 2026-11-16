import csv
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
from assessment import assess, context_for, CATALOG, SOURCES, REVIEWED
from portscanner import App


class AssessmentTests(unittest.TestCase):
    def test_inventory_never_claims_reachability(self):
        item = assess(3389, local=True, address='127.0.0.1')
        self.assertEqual(item['review_priority'], 'Local review')
        self.assertIn('Remote reachability is not assessed', item['evidence'])
        self.assertIn('port-based guess', item['service_inference'])
        self.assertTrue(item['vulnerabilities'].startswith('Not assessed'))

    def test_external_is_not_worldwide_exposure(self):
        item = assess(445, address='8.8.8.8')  # Synthetic input; never contacted.
        self.assertEqual(item['context'], 'Globally addressed endpoint')
        self.assertIn('from this computer', item['evidence'])
        self.assertIn('other networks is not assessed', item['evidence'])
        self.assertTrue(item['condition'].startswith('If this is'))
        self.assertEqual(item['review_priority'], 'Restrict access')

    def test_unknown_is_not_safe_and_sources_present(self):
        item = assess(65000, address='192.168.1.2')
        self.assertEqual(item['review_priority'], 'Identify service')
        self.assertEqual(item['context'], 'Non-global endpoint')
        self.assertEqual(context_for('unresolved.example'), 'Unclassified endpoint')
        self.assertIn('unknown', item['confidence'])
        for ports, *_ in CATALOG:
            result = assess(ports[0])
            self.assertIn(result['source'], SOURCES.values())
            self.assertEqual(result['reviewed'], REVIEWED)
            self.assertNotIn('CVE-', str(result))

    def test_dashboard_selection_and_csv(self):
        app = App()
        try:
            app.rows = [(5432, 'postgresql', None)]
            app.local_mode = True
            app.scan_target = app.resolved_address = '127.0.0.1'
            app.status.set('Stopped · partial results')
            app.review.refresh(app.assessments(), app.status.get())
            app.review.table.selection_set('5432')
            app.review.select()
            detail = app.review.detail.get('1.0', 'end')
            self.assertIn('pg_hba.conf', detail)
            self.assertIn('Not assessed', detail)
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'result.csv'
                with patch('portscanner.filedialog.asksaveasfilename', return_value=str(path)):
                    app.export()
                with path.open(encoding='utf-8-sig', newline='') as handle:
                    result = next(csv.DictReader(handle))
                self.assertEqual(result['method'], 'local_inventory_no_probes')
                self.assertEqual(result['state'], 'listening')
                self.assertEqual(result['connect_ms'], '')
                self.assertIn('partial', result['scan_status'])
                self.assertIn('Not assessed', result['vulnerabilities'])
                self.assertIn('not assessed', result['evidence'])
        finally:
            app.close()

if __name__ == '__main__':
    unittest.main()
