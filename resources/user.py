from task import send_user_registration_email
from flask.views import MethodView
import os
import redis
from flask_smorest import Blueprint, abort
from flask import current_app
from sqlalchemy import or_
from passlib.hash import pbkdf2_sha256
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt_identity,
    get_jwt,
    jwt_required,
) 
from db import db
from models import UserModel
from schemas import UserSchema, UserRegisterSchema
from blocklist import BLOCKLIST

def roles_required(user_role):
    def decorator(fn):
        def wrapper(self):
            claims = get_jwt()
            role=claims["role"]
            if role == user_role:
                return fn(self)
            else:
                return {'message': 'Access denied. Unauthorize User.'}, 403

        return wrapper

    return decorator


blp = Blueprint("Users", "users", description="Operation of users")

@blp.route("/register")
class UserRegister(MethodView):
    @blp.arguments(UserRegisterSchema)
    def post(self, user_data):
         if UserModel.query.filter(or_(
             UserModel.username == user_data["username"],
             UserModel.email == user_data["email"]
         )).first():
            abort(409, message="A user with that username or email already exists.")

         user = UserModel(
            username=user_data["username"],
            email=user_data["email"],
            password=pbkdf2_sha256.hash(user_data["password"]),
            role=user_data["role"]
         )
         db.session.add(user)
         db.session.commit()

        #  connection = redis.from_url(
        #  os.getenv("REDIS_URL")
        #  )  # Get this from Render.com or run in Docker
        #  queue = Queue("emails", connection=connection)

         current_app.queue.enqueue(send_user_registration_email, user.email, user.username)
         
         return {"message": "User created successfully."}, 201
         


@blp.route("/login")
class UserLogin(MethodView):
    @blp.arguments(UserSchema)
    def post(self, user_data):
        user = UserModel.query.filter(UserModel.username == user_data["username"]).first()
        user_input_password = user_data["password"]
        stored_hashed_password = user.password
        # Verify the user's input password against the stored hashed password 

        if user and pbkdf2_sha256.verify(user_input_password, stored_hashed_password):
            #create a access token with jwt seceret key and user's id
            access_token = create_access_token(identity=user.id, additional_claims={"role": user.role}, fresh=True)
            #It only required when client hit /refresh end point and it refreshed
            refresh_token = create_refresh_token(identity=user.id, additional_claims={"role": user.role})
            return {"access_token":access_token, "refresh_token":refresh_token}


@blp.route("/user/<int:user_id>")
class User(MethodView):
    
    @blp.response(200, UserSchema)
    def get(self, user_id):
        user = UserModel.query.get_or_404(user_id)
        return user

    def delete(self, user_id):
        user = UserModel.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        return {"message": "User deleted."}, 200
    
@blp.route("/logout")
class UserLogout(MethodView):
    @jwt_required()
    def post(self):
        jti = get_jwt()["jti"] #get jwt unique identifier
        BLOCKLIST.add(jti)
        return {"message":"User logout"}
    
@blp.route("/refresh")
class TokenRefresh(MethodView):
    @jwt_required(refresh=True)
    def post(self):
        current_user = get_jwt_identity()
        #This create new token (not refresh)
        new_token = create_access_token(identity=current_user, fresh=False)
        return {"access_token":new_token}


@blp.route("/manager")
class Manager(MethodView):
    @jwt_required()
    @roles_required("manager")
    def get(self):
      return {"message":"User authorized"}
      
