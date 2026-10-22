from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

# Extensions are created here and configured by create_app().
db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
