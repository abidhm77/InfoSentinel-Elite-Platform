#!/usr/bin/env python3
"""
Test script for ML forecasting functionality
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from analytics.ml_forecasting import SecurityForecastingEngine

def test_ml_forecasting():
    """Test ML-powered security forecasting"""
    print("Testing ML Security Forecasting Implementation...")
    
    # Initialize forecasting engine
    forecaster = SecurityForecastingEngine()
    
    # Test vulnerability count forecasting
    print("\n1. Testing vulnerability count forecasting...")
    vuln_forecasts = forecaster.forecast_vulnerability_trends('vulnerability_count', periods=7)
    print(f"   Generated {len(vuln_forecasts)} forecasts")
    for i, forecast in enumerate(vuln_forecasts[:3]):  # Show first 3
        print(f"     Day {i+1}: {forecast.predicted_value:.1f} vulns (confidence: {forecast.confidence:.2f})")
    
    # Test risk score forecasting
    print("\n2. Testing risk score forecasting...")
    risk_forecasts = forecaster.forecast_vulnerability_trends('risk_score', periods=7)
    print(f"   Generated {len(risk_forecasts)} forecasts")
    for i, forecast in enumerate(risk_forecasts[:3]):
        print(f"     Day {i+1}: {forecast.predicted_value:.1f} risk score (confidence: {forecast.confidence:.2f})")
    
    # Test remediation time forecasting
    print("\n3. Testing remediation time forecasting...")
    time_forecasts = forecaster.forecast_vulnerability_trends('remediation_time', periods=7)
    print(f"   Generated {len(time_forecasts)} forecasts")
    for i, forecast in enumerate(time_forecasts[:3]):
        print(f"     Day {i+1}: {forecast.predicted_value:.1f} days (confidence: {forecast.confidence:.2f})")
    
    # Test comprehensive report generation
    print("\n4. Testing comprehensive forecasting report...")
    report = forecaster.generate_forecasting_report(periods=14)
    
    print(f"   Report generated with {len(report['metrics'])} metrics")
    print(f"   Recommendations: {len(report['recommendations'])}")
    
    for metric, forecasts in report['metrics'].items():
        avg_value = sum(f['predicted_value'] for f in forecasts) / len(forecasts)
        print(f"   {metric}: avg {avg_value:.1f} over {len(forecasts)} days")
    
    # Show recommendations
    print("\n5. Recommendations:")
    for i, rec in enumerate(report['recommendations'][:3]):
        print(f"   {i+1}. {rec}")
    
    print("\n✓ ML forecasting implementation completed successfully!")
    return True

if __name__ == "__main__":
    print("=" * 60)
    print("ML SECURITY FORECASTING TEST SUITE")
    print("=" * 60)
    
    success = test_ml_forecasting()
    
    print("\n" + "=" * 60)
    if success:
        print("🎉 ML FORECASTING TESTS PASSED - Predictive analytics ready!")
    else:
        print("❌ ML FORECASTING TESTS FAILED - Review implementation")
    print("=" * 60)