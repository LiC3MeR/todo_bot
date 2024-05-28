from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

    def is_active(self):
        return True

    class Task(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        task_id = db.Column(db.String(80), unique=True, nullable=False)
        content = db.Column(db.String(200), nullable=False)
        priority = db.Column(db.Integer, nullable=False)
        description = db.Column(db.String(500), nullable=False)
        project_id = db.Column(db.Integer, nullable=False)
        status = db.Column(db.Integer, nullable=False)

        def __repr__(self):
            return f'<Task {self.content}>'

    def __repr__(self):
        return f"<User {self.username}>"