import unittest
import numpy as np
from scanners.risk_quantification import FAIRQuantifier

class TestFAIRQuantifier(unittest.TestCase):
    def setUp(self):
        self.threat_intel = {'base_rate': 0.1, 'activity_factor': 1.2}
        self.quantifier = FAIRQuantifier(self.threat_intel)

    def test_tef_calculation(self):
        tef = self.quantifier.threat_event_frequency(500000)
        self.assertAlmostEqual(tef, 0.1 * 1.2 * 0.5, places=4)

    def test_probabilistic_risk_output(self):
        results = self.quantifier.probabilistic_risk(iterations=1000)
        self.assertTrue(results['mean'] > 0)
        self.assertTrue(results['percentile_95'] > results['mean'])

    def test_cvar_calculation(self):
        cvar = self.quantifier.calculate_cvar(iterations=1000)
        self.assertTrue(cvar >= np.mean(self.quantifier.probabilistic_risk()['losses']))

if __name__ == '__main__':
    unittest.main()