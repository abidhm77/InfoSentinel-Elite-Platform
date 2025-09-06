import numpy as np
from scipy.stats import lognorm, pareto

class FAIRQuantifier:
    def __init__(self, threat_intel):
        self.threat_intel = threat_intel

    def threat_event_frequency(self, asset_value: float) -> float:
        """Calculate TEF using threat intelligence and asset attractiveness"""
        base_rate = self.threat_intel.get('base_rate', 0.05)
        threat_activity = self.threat_intel.get('activity_factor', 1.0)
        return base_rate * threat_activity * (asset_value / 1000000)

    @staticmethod
    def validate_simulation(results: dict) -> bool:
        """Ensure risk distribution meets FAIR validation criteria"""
        return results['percentile_95'] > results['mean'] > 0

    def calculate_cvar(self, iterations=10000, alpha=0.95) -> float:
        """Calculate Conditional Value-at-Risk for extreme loss scenarios"""
        losses = self.probabilistic_risk(iterations)['losses']
        var = np.percentile(losses, 100 * alpha)
        return losses[losses >= var].mean()

    def loss_magnitude(self, vuln_score: float) -> float:
        """Calculate loss magnitude using lognormal distribution"""
        return lognorm.ppf(0.95, s=vuln_score) * 1000

    def probabilistic_risk(self, iterations=10000) -> dict:
        """Monte Carlo simulation for risk distribution analysis"""
        tef_samples = np.random.poisson(lam=self.threat_event_frequency(), size=iterations)
        loss_samples = lognorm.rvs(s=0.5, scale=1000, size=iterations)
        return {
            'mean': np.mean(loss_samples * tef_samples),
            'percentile_95': np.percentile(loss_samples * tef_samples, 95)
        }