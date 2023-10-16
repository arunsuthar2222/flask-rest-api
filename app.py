from flask import Flask, jsonify
from flask_smorest import Api
from flask_jwt_extended import JWTManager
from db import db
import redis
from rq import Queue
from task import send_user_registration_email
from dotenv import load_dotenv
import os
import models
from blocklist import BLOCKLIST
from flask_migrate import Migrate
from resources.user import blp as UserBlueprint
from resources.item import blp as ItemBlueprint
from resources.store import blp as StoreBlueprint
from resources.tag import blp as TagBlueprint

def create_app(db_url=None):
    app = Flask(__name__)
    
    #Find .env file and load it's content
    load_dotenv()

    connection = redis.from_url(
    os.getenv("REDIS_URL")
    )  # Get this from Render.com or run in Docker

    app.queue = Queue("emails", connection=connection)
    app.config["PROPAGATE_EXCEPTIONS"] = True
    app.config["API_TITLE"] = "Stores REST API"
    app.config["API_VERSION"] = "v1"
    app.config["OPENAPI_VERSION"] = "3.0.3"
    app.config["OPENAPI_URL_PREFIX"] = "/"
    app.config["OPENAPI_SWAGGER_UI_PATH"] = "/swagger-ui"
    app.config[
        "OPENAPI_SWAGGER_UI_URL"
    ] = "https://cdn.jsdelivr.net/npm/swagger-ui-dist/"
    
    app.config["SQLALCHEMY_DATABASE_URI"]= db_url or os.getenv("DATABASE_URL","sqlite:///data.db")
    # app.config["SQLALCHEMY_DATABASE_URI"] = db_url or 'sqlite:///data.db'
    
    # app.config['SQLALCHEMY_DATABASE_URI_EVEN'] = 'even_url'
    # db1 = SQLAlchemy(app)

    # app.config['SQLALCHEMY_DATABASE_URI_ODD'] = 'odd_url'
    # db2 = SQLAlchemy(app) 
    
    #create model for even and odd
    #class EvenModel(db1.model)
    #class OddModel(db2.model)

    # in route deifning we can access db according to our decision as

    # if value%2==0
    #        db=db1
    # else
    #         db=db2

    #db.query.session(tabel) we can query in the right database
        
    #If we add a __bind_key = users in any model it will add that table into this database
    # app.config["SQLALCHEMY_BINDS"] = {
    # "users": "sqlite:///userdatabase.db"
    # }

    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db.init_app(app)
    
    migrate = Migrate(app, db)
    api = Api(app)

    #Secret key help to create jwt token with id
    # secrets.SystemRandom().getrandbits(128) random secret key
    app.config["JWT_SECRET_KEY"] = '133264670805844422338422208271091836555'
    
    #connect our jwt to the flask app
    jwt = JWTManager(app)
    
    #When we recieve a jwt this funtion runs and it check that jwt-token in the blocklist
    #if the token in the block list it function return true and it terminated and user get error 
    @jwt.token_in_blocklist_loader
    def check_if_token_in_blocklist(jwt_header, jwt_payload):
      return jwt_payload["jti"] in BLOCKLIST

    #If above funtion return true this funtion run
    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
      return (
        jsonify(
            {"description": "The token has been revoked.", "error": "token_revoked"}
        ),
        401,
      )

    #This function run every time when we create jwt access token
    #We can add some exrta data in access-token
    # @jwt.additional_claims_loader
    # def add_claims_to_jwt(identity):
    #   if identity == 1:
    #     return {"is_admin": True}
    #   return {"is_admin": False}

    
    #This function run when user make a request with expired access token
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
      return (
        jsonify({"message": "The token has expired.", "error": "token_expired"}),
        401,
      ) 
    
    @jwt.invalid_token_loader
    def invalid_token_callback(error):
      return (
        jsonify(
            {"message": "Signature verification failed.", "error": "invalid_token"}
        ),
        401,
    )

    @jwt.unauthorized_loader
    def missing_token_callback(error):
      return (
        jsonify(
            {
                "description": "Request does not contain an access token.",
                "error": "authorization_required",
            }
        ),
        401,
    )

    @jwt.needs_fresh_token_loader
    def token_not_fresh_callback(jwt_header, jwt_payload):
      return (
        jsonify(
            {
                "description": "The token is not fresh.",
                "error": "fresh_token_required",
            }
        ),
        401,
     )

    # with app.app_context():
    #     db.create_all()

    api.register_blueprint(ItemBlueprint)
    api.register_blueprint(StoreBlueprint)
    api.register_blueprint(TagBlueprint)
    api.register_blueprint(UserBlueprint)

    return app