from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    usernick = db.Column(db.String(50), unique=True, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    avatar_data = db.Column(db.LargeBinary)
    image_file = db.Column(db.String(255), nullable=False, default='logo.jpg')
    telegram_id = db.Column(db.String(80), unique=True)
    is_verified = db.Column(db.Boolean, default=False)

    role = db.relationship('Role', backref=db.backref('users', lazy=True))
    tasks = db.relationship('Task', backref='assigned_user', lazy=True)

    comments = db.relationship('Comment', back_populates='user', lazy=True)

    def __repr__(self):
        return f"<User {self.username}>"

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.String(80), unique=True, nullable=False)
    content = db.Column(db.String(200), nullable=False)
    priority = db.Column(db.Integer, nullable=False)
    description = db.Column(db.String(500), nullable=False)
    project_id = db.Column(db.BigInteger, nullable=True)
    status = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.TIMESTAMP, nullable=False, server_default=db.func.now())
    start_time = db.Column(db.DateTime)
    end_time = db.Column(db.DateTime)
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref=db.backref('tasks_assigned', lazy=True))
    duration = db.Column(db.Integer)
    tags = db.Column(db.String(30), nullable=True)
    sprint_id = db.Column(db.Integer, db.ForeignKey('sprints.id'), nullable=True)
    board_id = db.Column(db.Integer, db.ForeignKey('board.id'))  # Добавьте это поле

    comments = db.relationship('Comment', backref='task_related', lazy=True)
    board = db.relationship('Board', backref='tasks')

    def __repr__(self):
        return f'<Task {self.content}>'
