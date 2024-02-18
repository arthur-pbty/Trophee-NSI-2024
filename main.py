import os
from dotenv import load_dotenv
from app import app, db
from app.models import Users

load_dotenv()


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host=os.getenv('HOST'), port=os.getenv('PORT'), debug=os.getenv('DEBUG'), threaded=os.getenv('THREADED'))