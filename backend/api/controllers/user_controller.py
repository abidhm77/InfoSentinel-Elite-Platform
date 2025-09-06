"""
User controller for managing platform users.
"""
from flask import request, jsonify
from flask_restful import Resource
from datetime import datetime
import uuid
import hashlib
import os

from database.db import get_db

class UserController(Resource):
    """Controller for user operations."""
    
    def get(self, user_id=None):
        """
        Get user information.
        
        Args:
            user_id: Optional ID of specific user to retrieve
            
        Returns:
            JSON response with user data
        """
        db = get_db()
        
        if user_id:
            # Get specific user
            user = db.users.find_one({"_id": user_id})
            if not user:
                return {"error": "User not found"}, 404
            
            # Remove sensitive information
            if "password" in user:
                del user["password"]
            
            # Convert ObjectId to string for JSON serialization
            user["_id"] = str(user["_id"])
            return user
        else:
            # Get all users with pagination
            page = int(request.args.get('page', 1))
            per_page = int(request.args.get('per_page', 10))
            
            users = list(db.users.find().sort("username", 1)
                        .skip((page - 1) * per_page)
                        .limit(per_page))
            
            # Remove sensitive information and convert ObjectId
            for user in users:
                if "password" in user:
                    del user["password"]
                user["_id"] = str(user["_id"])
                
            return {"users": users, "page": page, "per_page": per_page}
    
    def post(self):
        """
        Create a new user.
        
        Returns:
            JSON response with user ID and status
        """
        data = request.get_json()
        
        # Validate required fields
        required_fields = ["username", "email", "password"]
        for field in required_fields:
            if field not in data:
                return {"error": f"Missing required field: {field}"}, 400
        
        db = get_db()
        
        # Check if username or email already exists
        if db.users.find_one({"username": data["username"]}):
            return {"error": "Username already exists"}, 400
        
        if db.users.find_one({"email": data["email"]}):
            return {"error": "Email already exists"}, 400
        
        # Hash password
        salt = os.urandom(32).hex()
        hashed_password = self._hash_password(data["password"], salt)
        
        # Create user
        user_id = str(uuid.uuid4())
        user = {
            "_id": user_id,
            "username": data["username"],
            "email": data["email"],
            "password": hashed_password,
            "salt": salt,
            "role": data.get("role", "user"),
            "created_at": datetime.utcnow(),
            "last_login": None
        }
        
        # Save to database
        db.users.insert_one(user)
        
        # Remove sensitive information for response
        del user["password"]
        del user["salt"]
        
        return user, 201
    
    def put(self, user_id):
        """
        Update a user.
        
        Args:
            user_id: ID of user to update
            
        Returns:
            JSON response with updated user data
        """
        if not user_id:
            return {"error": "User ID is required"}, 400
        
        data = request.get_json()
        db = get_db()
        
        # Get existing user
        user = db.users.find_one({"_id": user_id})
        if not user:
            return {"error": "User not found"}, 404
        
        # Update fields
        update_data = {}
        
        if "username" in data and data["username"] != user["username"]:
            # Check if new username already exists
            if db.users.find_one({"username": data["username"]}):
                return {"error": "Username already exists"}, 400
            update_data["username"] = data["username"]
        
        if "email" in data and data["email"] != user["email"]:
            # Check if new email already exists
            if db.users.find_one({"email": data["email"]}):
                return {"error": "Email already exists"}, 400
            update_data["email"] = data["email"]
        
        if "password" in data:
            # Hash new password
            salt = os.urandom(32).hex()
            hashed_password = self._hash_password(data["password"], salt)
            update_data["password"] = hashed_password
            update_data["salt"] = salt
        
        if "role" in data:
            update_data["role"] = data["role"]
        
        # Update user
        if update_data:
            db.users.update_one(
                {"_id": user_id},
                {"$set": update_data}
            )
        
        # Get updated user
        updated_user = db.users.find_one({"_id": user_id})
        
        # Remove sensitive information
        if "password" in updated_user:
            del updated_user["password"]
        if "salt" in updated_user:
            del updated_user["salt"]
        
        # Convert ObjectId to string for JSON serialization
        updated_user["_id"] = str(updated_user["_id"])
        
        return updated_user
    
    def delete(self, user_id):
        """
        Delete a user.
        
        Args:
            user_id: ID of user to delete
            
        Returns:
            JSON response with deletion status
        """
        if not user_id:
            return {"error": "User ID is required"}, 400
        
        db = get_db()
        result = db.users.delete_one({"_id": user_id})
        
        if result.deleted_count == 0:
            return {"error": "User not found"}, 404
        
        return {"message": "User deleted successfully"}, 200
    
    def _hash_password(self, password, salt):
        """
        Hash a password with salt.
        
        Args:
            password: Password to hash
            salt: Salt to use
            
        Returns:
            Hashed password
        """
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000
        ).hex()