#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api, bcrypt
from models import User, Recipe

class Signup(Resource):
    def post(self):
        data = request.get_json()

        if not data.get('username') or not data.get('password'):
            return {'error': 'Username and password are required'}, 422  #unprocessable entity
        
        if User.query.filter_by(username=data['username']).first():
            return {'error': 'Username already exists'}, 422 #conflict
        
        new_user = User(
            username=data['username'],
            image_url=data.get('image_url'),
            bio=data.get('bio')
        )
        new_user.password_hash = data['password']  #setting password using setter   
        db.session.add(new_user)
        db.session.commit()

        session['user_id'] = new_user.id  #log the user in by setting session

        return new_user.to_dict(), 201
    




        
class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = User.query.get(user_id)
            if user:
                return user.to_dict(), 200
        return {'error': 'No active session'}, 401

class Login(Resource):
    def post(self):
        data = request.get_json()
        user = User.query.filter_by(username=data['username']).first()
        if user and bcrypt.check_password_hash(user._password_hash, data['password']):
            session['user_id'] = user.id
            return user.to_dict(), 200
        return {'error': 'Invalid username or password'}, 401

class Logout(Resource):
    def delete(self):
        if session.get('user_id'):  #check if user is logged in
            session.pop('user_id')  #remove user_id from session
            return {}, 204   #no content
        return {'error': 'No active session'}, 401  #unauthorized

class RecipeIndex(Resource):
    def get(self):
        if not session.get('user_id'):
            return {'error': 'Unauthorized'}, 401
        recipes = Recipe.query.all()
        return [recipe.to_dict() for recipe in recipes], 200
    
    def post(self):
        if not session.get('user_id'):
            return {'error': 'Unauthorized'}, 401
        data = request.get_json()
        try:
            new_recipe = Recipe(
                title=data['title'],
                instructions=data['instructions'],
                minutes_to_complete=data.get('minutes_to_complete'),
                user_id=session['user_id']
            )
            db.session.add(new_recipe)
            db.session.commit()
            return new_recipe.to_dict(), 201
        except ValueError as e: #catching validation errors
            return {'error': str(e)}, 422 #

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)