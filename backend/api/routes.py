"""
API routes configuration for the Penetration Testing Platform.
"""
import os
from flask import Blueprint, request, jsonify
from flask_restful import Api, Resource

# Import only lightweight controllers at module load
from api.controllers.forecast_controller import ForecastController

# Create API blueprints
api_bp = Blueprint('api', __name__, url_prefix='/api/v1')
api = Api(api_bp)

# Create modern API blueprint for the frontend
modern_api_bp = Blueprint('modern_api', __name__, url_prefix='/api')
modern_api = Api(modern_api_bp)

def register_routes(app):
    """
    Register all API routes with the Flask application.
    
    Args:
        app: Flask application instance
    """
    # Determine if DB-dependent routes should be disabled
    disable_db = os.getenv('DISABLE_DB', 'false').lower() == 'true' or app.config.get('DB_DISABLED', False)

    if not disable_db:
        # Import DB/heavy controllers lazily to avoid import-time side effects
        from api.controllers.scan_controller import ScanController
        from api.controllers.report_controller import ReportController
        from api.controllers.user_controller import UserController
        from api.controllers.pentest_controller import PentestController
        from api.controllers.scan_progress_controller import ScanProgressController
        from api.controllers.schedule_controller import ScheduleController
        from api.controllers.task_controller import TaskController

        # Register API resources for v1 API
        api.add_resource(ScanController, '/scans', '/scans/<scan_id>')
        api.add_resource(ReportController, '/reports', '/reports/<report_id>')
        api.add_resource(UserController, '/users', '/users/<user_id>')
        
        # Register modern API resources for frontend
        modern_api.add_resource(PentestController, '/scans', '/scans/<scan_id>')
        modern_api.add_resource(ScanProgressController, '/scans/<scan_id>/progress')
        modern_api.add_resource(ScheduleController, '/schedules', '/schedules/<schedule_id>')
        modern_api.add_resource(TaskController, '/tasks')
    else:
        # In DB-disabled mode, provide a minimal v1 placeholder route for status
        class Status(Resource):
            def get(self):
                return {"status": "ok", "db_disabled": True}
        api.add_resource(Status, '/status')

    # Forecasting endpoints are always available
    modern_api.add_resource(ForecastController, '/forecast', '/forecast/<string:metric>')

    # Register the blueprints with the app
    app.register_blueprint(api_bp)
    app.register_blueprint(modern_api_bp)
    
    # Register error handlers
    register_error_handlers(app)
    
    return app

def register_error_handlers(app):
    """
    Register custom error handlers.
    
    Args:
        app: Flask application instance
    """
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({"error": "Resource not found"}), 404
    
    @app.errorhandler(500)
    def server_error(error):
        return jsonify({"error": "Internal server error"}), 500
    
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({"error": "Bad request"}), 400