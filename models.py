import datetime
from app import database
from peewee import *

class BaseModel(Model):
    class Meta:
        database = database

class User(BaseModel):
    username = CharField(unique=True) 
    password = CharField()
    email = CharField(unique=True) 
    joint_at = DateTimeField(default=datetime.datetime.now())

    def following(self):
        return (User.select()
                    .join(Relationship,on=Relationship.to_user)
                    .where(Relationship.from_user == self)
                    .order_by(User.username))
    
    def followers(self):
        return (User.select()
                    .join(Relationship,on=Relationship.from_user)
                    .where(Relationship.to_user == self)
                    .order_by(User.username))

    def is_following(self, user):
        return (Relationship.select()
                .where((Relationship.from_user == self) &
                       (Relationship.to_user == user ))
                .exists())
class Message(BaseModel):
    user = ForeignKeyField(User, backref='messages') 
    content = TextField()
    published_at = DateTimeField(default=datetime.datetime.now())

class Relationship(BaseModel):
    from_user = ForeignKeyField(User, backref='Relationships')   
    to_user   = ForeignKeyField(User, backref='related_to')

    class Meta:
        indexes = (
            (('from_user', 'to_user'), True),
        )