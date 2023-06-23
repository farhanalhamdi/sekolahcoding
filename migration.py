from app import database
from models import User, Relationship, Message

def create_tables():
    with database:
        database.create_tables([User,Relationship,Message])