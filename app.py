from flask import Flask 
from peewee import *


app = Flask(__name__)
app.config.from_pyfile('config.py')

database = SqliteDatabase(app.config['DATABASE_URI'])

from routes import *

if __name__ == '__main__':
    app.run(debug=app.config['DEBUG'])
    












#endfile