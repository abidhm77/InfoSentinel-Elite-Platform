"""
Forecast Controller for exposing security forecasting metrics
"""
from flask_restful import Resource
from flask import request, jsonify

from analytics.ml_forecasting import SecurityForecastingEngine


class ForecastController(Resource):
    """Expose ML-based security forecasting via API"""

    def __init__(self):
        # Instantiate forecasting engine per request context
        self.engine = SecurityForecastingEngine()
        # Determine available metrics from engine
        self.available_metrics = list(self.engine.historical_data.keys())

    def get(self, metric=None):
        """
        GET /api/forecast -> full forecasting report
        GET /api/forecast/<metric> -> forecast series for a specific metric
        GET /api/forecast/metrics -> list available metrics
        Query params:
          - periods (int): number of periods to forecast (default 14)
          - model_type (str): forecasting model to use ('auto', 'prophet', 'lstm', 'enhanced_moving_average')
        """
        try:
            periods = int(request.args.get("periods", 14))
            model_type = request.args.get("model_type", "auto")
        except ValueError:
            return {"error": "Invalid parameters; 'periods' must be integer"}, 400

        # List available metrics
        if metric == "metrics":
            return jsonify({"metrics": self.available_metrics})

        # Full report
        if metric is None:
            try:
                report = self.engine.generate_forecasting_report(periods=periods, model_type=model_type)
                return jsonify(report)
            except Exception as e:
                return {"error": f"Failed to generate forecasting report: {str(e)}"}, 500

        # Specific metric forecast
        if metric not in self.available_metrics:
            return {
                "error": f"Unknown metric '{metric}'",
                "metrics": self.available_metrics,
            }, 400

        try:
            forecasts = self.engine.forecast_vulnerability_trends(metric, periods, model_type=model_type)
            # Normalize ForecastResult objects to serializable dicts
            normalized = [
                {
                    "date": getattr(f, "date", None).isoformat() if getattr(f, "date", None) else f.get("date"),
                    "predicted_value": getattr(f, "predicted_value", None) if hasattr(f, "predicted_value") else f.get("predicted_value"),
                    "confidence": getattr(f, "confidence", None) if hasattr(f, "confidence") else f.get("confidence"),
                    "model_type": getattr(f, "model_type", None) if hasattr(f, "model_type") else f.get("model_type"),
                    "trend": getattr(f, "trend", None) if hasattr(f, "trend") else f.get("trend"),
                    "seasonal": getattr(f, "seasonal", None) if hasattr(f, "seasonal") else f.get("seasonal"),
                }
                for f in forecasts
            ]
            return jsonify({
                "metric": metric,
                "periods": periods,
                "model_type": model_type,
                "forecasts": normalized,
            })
        except ValueError as e:
            return {"error": str(e)}, 400
        except Exception as e:
            return {"error": f"Forecasting failed: {str(e)}"}, 500