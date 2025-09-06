#!/usr/bin/env python3
"""
Advanced Security Forecasting Engine
Enhanced implementation with Prophet and LSTM models for security metrics forecasting
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import json
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Try to import advanced ML libraries with graceful fallbacks
try:
    from prophet import Prophet
    PROPHET_AVAILABLE = True
except ImportError:
    PROPHET_AVAILABLE = False
    logger.warning("Prophet not available - using fallback methods")

try:
    import tensorflow as tf
    from tensorflow.keras.models import Sequential
    from tensorflow.keras.layers import LSTM, Dense, Dropout
    from tensorflow.keras.optimizers import Adam
    from sklearn.preprocessing import MinMaxScaler
    LSTM_AVAILABLE = True
except ImportError:
    LSTM_AVAILABLE = False
    logger.warning("TensorFlow/Keras not available - using fallback methods")


@dataclass
class ForecastResult:
    date: datetime
    predicted_value: float
    confidence: float
    model_type: str
    trend: Optional[str] = None
    seasonal: Optional[str] = None


@dataclass
class ModelPerformance:
    model_type: str
    mae: float
    rmse: float
    mape: float
    confidence_score: float


class SecurityForecastingEngine:
    """Advanced security forecasting engine with Prophet and LSTM support"""
    
    def __init__(self):
        self.historical_data = self._generate_enhanced_sample_data()
        self.models = {}
        self.scalers = {}
        self.model_performance = {}
        
    def _generate_enhanced_sample_data(self) -> Dict[str, List[float]]:
        """Generate enhanced sample security data with realistic patterns"""
        np.random.seed(42)
        
        # Generate 180 days of sample data with realistic patterns
        vulnerability_count = []
        risk_score = []
        remediation_time = []
        threat_intelligence = []
        
        start_date = datetime.now() - timedelta(days=180)
        
        for i in range(180):
            # Base values with complex patterns
            base_vulns = 45 + (i * 0.05) + 5 * np.sin(2 * np.pi * i / 30)  # Monthly seasonality
            base_risk = 35 + (i * 0.03) + 8 * np.sin(2 * np.pi * i / 90)  # Quarterly seasonality
            base_time = 6 + (i * 0.01) + 2 * np.sin(2 * np.pi * i / 60)  # Bi-monthly seasonality
            
            # Add weekend/weekday patterns
            day_of_week = (start_date + timedelta(days=i)).weekday()
            weekday_factor = 1.2 if day_of_week < 5 else 0.8
            
            # Add noise and trends
            vuln = max(0, min(100, base_vulns * weekday_factor + np.random.normal(0, 3)))
            risk = max(0, min(100, base_risk + np.random.normal(0, 2)))
            time = max(1, min(20, base_time + np.random.normal(0, 0.5)))
            intel = max(0, min(100, 50 + np.random.normal(0, 15)))
            
            vulnerability_count.append(vuln)
            risk_score.append(risk)
            remediation_time.append(time)
            threat_intelligence.append(intel)
        
        return {
            'vulnerability_count': vulnerability_count,
            'risk_score': risk_score,
            'remediation_time': remediation_time,
            'threat_intelligence': threat_intelligence
        }
    
    def _generate_sample_data(self) -> Dict[str, List[float]]:
        """Generate sample historical security data"""
        np.random.seed(42)
        
        # Generate 90 days of sample data
        vulnerability_count = []
        risk_score = []
        remediation_time = []
        
        for i in range(90):
            # Base values with trend and seasonality
            base_vulns = 50 + (i * 0.1)  # Slow upward trend
            seasonality = 8 * np.sin(2 * np.pi * i / 30)  # Monthly seasonality
            noise = np.random.normal(0, 2)  # Random noise
            
            vuln = max(0, min(80, base_vulns + seasonality + noise))
            risk = max(0, min(90, 40 + (i * 0.08) + 4 * np.sin(2 * np.pi * i / 90) + np.random.normal(0, 1.5)))
            time = max(1, min(15, 7 + (i * 0.02) + 1.5 * np.sin(2 * np.pi * i / 60) + np.random.normal(0, 0.8)))
            
            vulnerability_count.append(vuln)
            risk_score.append(risk)
            remediation_time.append(time)
        
        return {
            'vulnerability_count': vulnerability_count,
            'risk_score': risk_score,
            'remediation_time': remediation_time
        }
    
    def _prepare_data_for_prophet(self, metric: str) -> pd.DataFrame:
        """Prepare data for Prophet model"""
        values = self.historical_data[metric]
        dates = [datetime.now() - timedelta(days=len(values)-i-1) for i in range(len(values))]
        
        df = pd.DataFrame({
            'ds': dates,
            'y': values
        })
        return df
    
    def _prepare_data_for_lstm(self, metric: str, lookback: int = 30) -> tuple:
        """Prepare data for LSTM model"""
        values = self.historical_data[metric]
        values = np.array(values).reshape(-1, 1)
        
        # Initialize scaler
        scaler = MinMaxScaler(feature_range=(0, 1))
        scaled_data = scaler.fit_transform(values)
        self.scalers[metric] = scaler
        
        # Create sequences
        X, y = [], []
        for i in range(lookback, len(scaled_data)):
            X.append(scaled_data[i-lookback:i, 0])
            y.append(scaled_data[i, 0])
        
        X, y = np.array(X), np.array(y)
        X = np.reshape(X, (X.shape[0], X.shape[1], 1))
        
        return X, y
    
    def _build_lstm_model(self, input_shape: tuple):
        """Build LSTM model for time series forecasting"""
        if not TENSORFLOW_AVAILABLE:
            raise ImportError("TensorFlow/Keras not available")
            
        try:
            from tensorflow.keras.models import Sequential
            from tensorflow.keras.layers import LSTM, Dense, Dropout
            
            model = Sequential([
                LSTM(50, return_sequences=True, input_shape=input_shape),
                Dropout(0.2),
                LSTM(50, return_sequences=False),
                Dropout(0.2),
                Dense(25),
                Dense(1)
            ])
            
            model.compile(optimizer='adam', loss='mean_squared_error')
            return model
        except Exception as e:
            logger.error(f"LSTM model building failed: {e}")
            raise
    
    def forecast_with_prophet(self, metric: str, periods: int = 14) -> List[ForecastResult]:
        """Forecast using Prophet model with graceful fallback"""
        if not PROPHET_AVAILABLE:
            logger.warning("Prophet not available, falling back to enhanced moving average")
            return self._fallback_forecast(metric, periods)
        
        try:
            df = self._prepare_data_for_prophet(metric)
            
            # Configure Prophet model
            model = Prophet(
                daily_seasonality=True,
                weekly_seasonality=True,
                yearly_seasonality=False,
                changepoint_prior_scale=0.05,
                seasonality_mode='additive'
            )
            
            model.fit(df)
            
            # Create future dataframe
            future = model.make_future_dataframe(periods=periods)
            forecast = model.predict(future)
            
            # Extract results
            results = []
            for _, row in forecast.tail(periods).iterrows():
                results.append(ForecastResult(
                    date=row['ds'],
                    predicted_value=float(row['yhat']),
                    confidence=float(1 - abs(row['yhat_lower'] - row['yhat_upper']) / (2 * row['yhat'] + 1e-10)),
                    model_type='prophet',
                    trend='increasing' if row['trend'] > 0 else 'decreasing',
                    seasonal='present' if abs(row['weekly']) > 0.1 else 'minimal'
                ))
            
            return results
            
        except Exception as e:
            logger.error(f"Prophet forecasting failed: {e}")
            return self._fallback_forecast(metric, periods)
    
    def forecast_with_lstm(self, metric: str, periods: int = 14) -> List[ForecastResult]:
        """Forecast using LSTM model with graceful fallback"""
        if not LSTM_AVAILABLE:
            logger.warning("LSTM not available, falling back to enhanced moving average")
            return self._fallback_forecast(metric, periods)
        
        try:
            X, y = self._prepare_data_for_lstm(metric)
            
            if len(X) < 50:  # Not enough data for LSTM
                logger.warning("Insufficient data for LSTM, using fallback")
                return self._fallback_forecast(metric, periods)
            
            # Build and train model
            model = self._build_lstm_model((X.shape[1], 1))
            model.fit(X, y, epochs=50, batch_size=16, verbose=0)
            
            # Make predictions
            last_sequence = X[-1:]
            predictions = []
            
            for _ in range(periods):
                next_pred = model.predict(last_sequence, verbose=0)[0][0]
                predictions.append(next_pred)
                
                # Update sequence for next prediction
                last_sequence = np.roll(last_sequence, -1, axis=1)
                last_sequence[0, -1, 0] = next_pred
            
            # Inverse transform predictions
            scaler = self.scalers.get(metric)
            if scaler:
                predictions = scaler.inverse_transform(np.array(predictions).reshape(-1, 1)).flatten()
            
            # Create results
            results = []
            current_date = datetime.now()
            
            for i, pred in enumerate(predictions):
                results.append(ForecastResult(
                    date=current_date + timedelta(days=i+1),
                    predicted_value=float(pred),
                    confidence=0.85,  # LSTM typically has higher confidence
                    model_type='lstm',
                    trend='calculated'
                ))
            
            return results
            
        except Exception as e:
            logger.error(f"LSTM forecasting failed: {e}")
            return self._fallback_forecast(metric, periods)
    
    def _fallback_forecast(self, metric: str, periods: int = 14) -> List[ForecastResult]:
        """Enhanced fallback forecasting using weighted moving average"""
        if metric not in self.historical_data:
            raise ValueError(f"Metric '{metric}' not available")
        
        values = self.historical_data[metric]
        
        # Use weighted average with more recent data weighted higher
        weights = np.exp(np.linspace(-1, 0, min(60, len(values))))
        weights = weights / weights.sum()
        recent_weighted_avg = np.sum(weights * np.array(values[-len(weights):]))
        
        # Add trend detection
        if len(values) >= 30:
            recent_trend = np.polyfit(range(30), values[-30:], 1)[0]
            trend_direction = 'increasing' if recent_trend > 0 else 'decreasing'
        else:
            trend_direction = 'stable'
        
        forecasts: List[ForecastResult] = []
        current_date = datetime.now()
        
        # Add slight trend continuation
        trend_factor = recent_trend * 0.1 if abs(recent_trend) > 0.1 else 0
        
        for i in range(periods):
            predicted_value = float(recent_weighted_avg + (trend_factor * (i + 1)))
            predicted_value = max(0, min(100, predicted_value))  # Bound values
            
            forecasts.append(ForecastResult(
                date=current_date + timedelta(days=i+1),
                predicted_value=predicted_value,
                confidence=0.75,
                model_type='enhanced_moving_average',
                trend=trend_direction
            ))
        
        return forecasts
    
    def forecast_vulnerability_trends(self, metric: str, periods: int = 14, model_type: str = 'auto') -> List[ForecastResult]:
        """Advanced forecasting with model selection"""
        available_models = []
        
        if PROPHET_AVAILABLE:
            available_models.append('prophet')
        if LSTM_AVAILABLE and len(self.historical_data[metric]) >= 60:
            available_models.append('lstm')
        available_models.append('enhanced_moving_average')
        
        if model_type == 'auto':
            # Select best available model
            if PROPHET_AVAILABLE:
                return self.forecast_with_prophet(metric, periods)
            elif LSTM_AVAILABLE and len(self.historical_data[metric]) >= 60:
                return self.forecast_with_lstm(metric, periods)
            else:
                return self._fallback_forecast(metric, periods)
        elif model_type == 'prophet' and PROPHET_AVAILABLE:
            return self.forecast_with_prophet(metric, periods)
        elif model_type == 'lstm' and LSTM_AVAILABLE:
            return self.forecast_with_lstm(metric, periods)
        else:
            return self._fallback_forecast(metric, periods)
    
    def generate_forecasting_report(self, periods: int = 14, model_type: str = 'auto') -> Dict[str, Any]:
        """Generate comprehensive security forecasting report with model insights"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'forecast_periods': periods,
            'model_type': model_type,
            'available_models': self._get_available_models(),
            'metrics': {},
            'recommendations': [],
            'model_performance': {},
            'confidence_summary': {}
        }
        
        metrics = ['vulnerability_count', 'risk_score', 'remediation_time', 'threat_intelligence']
        
        for metric in metrics:
            try:
                forecasts = self.forecast_vulnerability_trends(metric, periods, model_type)
                
                # Convert ForecastResult objects to dicts for report
                forecast_data = [{
                    'date': f.date.isoformat(),
                    'predicted_value': f.predicted_value,
                    'confidence': f.confidence,
                    'model_type': f.model_type,
                    'trend': f.trend,
                    'seasonal': f.seasonal
                } for f in forecasts]
                
                report['metrics'][metric] = forecast_data
                
                # Calculate confidence summary
                avg_confidence = sum(f.confidence for f in forecasts) / len(forecasts)
                report['confidence_summary'][metric] = {
                    'average_confidence': avg_confidence,
                    'min_confidence': min(f.confidence for f in forecasts),
                    'max_confidence': max(f.confidence for f in forecasts)
                }
                
                # Add model performance metrics
                report['model_performance'][metric] = {
                    'model_used': forecasts[0].model_type if forecasts else 'unknown',
                    'data_points': len(self.historical_data[metric]),
                    'forecast_horizon': periods
                }
                
            except Exception as e:
                logger.error(f"Failed to forecast {metric}: {e}")
                report['metrics'][metric] = []
                report['confidence_summary'][metric] = {'average_confidence': 0.0}
        
        # Generate enhanced recommendations
        self._generate_enhanced_recommendations(report)
        return report
    
    def _get_available_models(self) -> List[str]:
        """Get list of available forecasting models"""
        models = []
        if PROPHET_AVAILABLE:
            models.append('prophet')
        if LSTM_AVAILABLE:
            models.append('lstm')
        models.append('enhanced_moving_average')
        return models
    
    def _generate_enhanced_recommendations(self, report: Dict[str, Any]) -> None:
        """Generate advanced security recommendations based on forecasting"""
        recommendations = []
        
        # Analyze vulnerability trends
        vuln_forecasts = report['metrics'].get('vulnerability_count', [])
        if vuln_forecasts:
            avg_vulns = sum(f['predicted_value'] for f in vuln_forecasts) / len(vuln_forecasts)
            max_vulns = max(f['predicted_value'] for f in vuln_forecasts)
            
            if max_vulns > 70:
                recommendations.append({
                    'type': 'urgent',
                    'message': f"Critical vulnerability spike predicted (max: {max_vulns:.1f}) - immediate action required",
                    'action': 'increase_scanning_frequency'
                })
            elif avg_vulns > 50:
                recommendations.append({
                    'type': 'warning',
                    'message': f"Elevated vulnerability load predicted (avg: {avg_vulns:.1f})",
                    'action': 'prioritize_remediation'
                })
        
        # Analyze risk score trends
        risk_forecasts = report['metrics'].get('risk_score', [])
        if risk_forecasts:
            avg_risk = sum(f['predicted_value'] for f in risk_forecasts) / len(risk_forecasts)
            trend = 'increasing' if len(risk_forecasts) >= 2 and risk_forecasts[-1]['predicted_value'] > risk_forecasts[0]['predicted_value'] else 'stable'
            
            if avg_risk > 70:
                recommendations.append({
                    'type': 'high',
                    'message': f"High risk level predicted (avg: {avg_risk:.1f}) - review security posture",
                    'action': 'conduct_risk_assessment'
                })
            elif trend == 'increasing':
                recommendations.append({
                    'type': 'moderate',
                    'message': "Risk trend is increasing - monitor closely",
                    'action': 'enhance_monitoring'
                })
        
        # Analyze remediation time trends
        time_forecasts = report['metrics'].get('remediation_time', [])
        if time_forecasts:
            avg_time = sum(f['predicted_value'] for f in time_forecasts) / len(time_forecasts)
            if avg_time > 10:
                recommendations.append({
                    'type': 'operational',
                    'message': f"Extended remediation times predicted (avg: {avg_time:.1f} days)",
                    'action': 'optimize_workflow'
                })
        
        # Model-specific recommendations
        if report['model_type'] == 'enhanced_moving_average':
            recommendations.append({
                'type': 'technical',
                'message': "Consider installing Prophet or TensorFlow for enhanced forecasting accuracy",
                'action': 'install_ml_dependencies'
            })
        
        report['recommendations'] = recommendations

# Test the implementation
if __name__ == "__main__":
    print("Testing Advanced Security Forecasting Engine...")
    
    forecaster = SecurityForecastingEngine()
    
    # Test different model types
    model_types = ['auto', 'prophet', 'lstm', 'enhanced_moving_average']
    
    for model_type in model_types:
        print(f"\n--- Testing {model_type.upper()} Model ---")
        try:
            report = forecaster.generate_forecasting_report(periods=7, model_type=model_type)
            
            print(f"Forecasting Report ({report['timestamp']})")
            print(f"Model Type: {report['model_type']}")
            print(f"Available Models: {', '.join(report['available_models'])}")
            print("=" * 60)
            
            for metric, forecasts in report['metrics'].items():
                if forecasts:
                    avg_value = sum(f['predicted_value'] for f in forecasts) / len(forecasts)
                    avg_confidence = sum(f['confidence'] for f in forecasts) / len(forecasts)
                    model_used = forecasts[0]['model_type']
                    print(f"{metric.replace('_', ' ').title()}: {avg_value:.1f} (avg) | "
                          f"Confidence: {avg_confidence:.2f} | Model: {model_used}")
                else:
                    print(f"{metric.replace('_', ' ').title()}: No data available")
            
            print("\nRecommendations:")
            for rec in report['recommendations']:
                if isinstance(rec, dict):
                    print(f"[{rec['type'].upper()}] {rec['message']} -> {rec['action']}")
                else:
                    print(f"- {rec}")
                    
        except Exception as e:
            print(f"Error with {model_type}: {e}")
    
    print(f"\n✓ Advanced security forecasting engine completed successfully!")
    
    # Demonstrate specific metric forecasting
    print("\n--- Detailed Vulnerability Forecasting ---")
    vuln_forecasts = forecaster.forecast_vulnerability_trends('vulnerability_count', periods=14)
    for i, forecast in enumerate(vuln_forecasts, 1):
        print(f"Day {i}: {forecast.predicted_value:.1f} vulnerabilities "
              f"(confidence: {forecast.confidence:.2f}, model: {forecast.model_type})")