from application.database import db
from flask import current_app as app
from flask_login import UserMixin
import pandas as pd
import os

class Cases(db.Model):
    __tablename__ = 'Cases'
    id = db.Column(db.Integer,autoincrement = True,primary_key = True)
    Comment = db.Column(db.String, nullable = False)
    Status = db.Column(db.String, nullable = False)
    User_id = db.Column(db.Integer,db.ForeignKey('User.id'), nullable = False)
    Verifier_id = db.Column(db.Integer, nullable = False)

class Messages(db.Model):
    __tablename__ = 'Messages'
    id = db.Column(db.Integer, autoincrement= True,primary_key = True)
    Content = db.Column(db.String, nullable = False)
    Sender_id = db.Column(db.Integer, nullable = False)
    Case_id = db.Column(db.Integer, nullable=False)

class Documents(db.Model):
    __tablename__ = 'Documents'
    id=db.Column(db.Integer,autoincrement=True,primary_key = True)
    Filename = db.Column(db.String, nullable = False)
    Case_id = db.Column(db.Integer, nullable = False)
    Uploader_id = db.Column(db.Integer, nullable = False)

class User(db.Model,UserMixin):
    __tablename__ = 'User'
    id=db.Column(db.Integer, autoincrement=True,primary_key=True)
    Username=db.Column(db.String,nullable = False,unique=True)
    Password = db.Column(db.String, nullable = False)
    Email = db.Column(db.String, nullable = False, unique = True)
    Role = db.Column(db.String, nullable = False)
    Verifier_id = db.Column(db.Integer, nullable=False)
    Cases = db.relationship('Cases',backref='user')

