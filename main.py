import os
from dotenv import load_dotenv
from app import app

load_dotenv()


if __name__ == '__main__':
    app.run(host=os.getenv('HOST'), port=os.getenv('PORT'), debug=os.getenv('DEBUG'), threaded=os.getenv('THREADED'))