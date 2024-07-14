# Initialize the Flask application and SQLAlchemy
app = Flask(__name__)
db = SQLAlchemy(app)

# Import models after initializing db to avoid circular imports
from models import User, Task, Comment

# Create all tables defined in models
db.create_all()
