from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = r'sqlite:///C:\Users\New\todo_bot\instance\tasks.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usernick = db.Column(db.String(50), unique=True, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    avatar_data = db.Column(db.LargeBinary)
    image_file = db.Column(db.String(255), nullable=False, default='logo.jpg')

    role = db.relationship('Role', backref=db.backref('users', lazy=True))
    tasks = db.relationship('Task', backref='assigned_user', lazy=True)  # Added relationship

    comments = db.relationship('Comment', back_populates='user', lazy=True)

class Sprint(db.Model):
    __tablename__ = 'sprints'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    tasks = db.relationship('Task', backref='sprint', lazy=True)

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

    comments = db.relationship('Comment', backref='task_related', lazy=True)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.TIMESTAMP, nullable=False, server_default=db.func.now())
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    user = db.relationship('User', back_populates='comments')

    def __repr__(self):
        return f'<Comment {self.id} by User {self.user_id}>'

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

roles_permissions = db.Table('roles_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permission.id'), primary_key=True)
)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    permissions = db.relationship('Permission', secondary=roles_permissions, backref=db.backref('roles', lazy='dynamic'))

class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30), unique=True, nullable=False)

class VerificationCode(db.Model):
    __tablename__ = 'verification_code'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    code = db.Column(db.String(6), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()