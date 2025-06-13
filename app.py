import os
from extensions import app
from routes import routes

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

app.register_blueprint(routes)

app = Flask(__name__)


if __name__ == '__main__':
    app.run(debug=True)
