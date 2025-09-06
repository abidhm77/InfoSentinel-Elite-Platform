#!/usr/bin/env python3
"""
Minimal Flask app for testing the forecasting API.
"""
from flask import Flask, jsonify
from flask_cors import CORS
from flask_restful import Api

# Import the forecast controller
from api.controllers.forecast_controller import ForecastController

def create_minimal_app():
    """Create a minimal Flask app with only the forecast API."""
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'dev-secret-key'
    CORS(app)
    
    # Create API instance
    api = Api(app)
    
    # Register forecast routes
    api.add_resource(ForecastController, '/api/forecast', '/api/forecast/<string:metric>')
    
    @app.route('/health', methods=['GET'])
    def health_check():
        return jsonify({'status': 'healthy', 'service': 'forecast-api'})
    
    return app

if __name__ == '__main__':
    app = create_minimal_app()
    app.run(host='0.0.0.0', port=5000, debug=True)