from flask import Flask, render_template, request, jsonify, redirect, flash, url_for, redirect, abort, session
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from telebot import TeleBot
import os
import subprocess
from flask_login import LoginManager, login_required, login_user, logout_user, current_user, UserMixin
from config import DevelopmentConfig, ProductionConfig, NLUConfig, CalConfig
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from models import User, Task
from flask_bcrypt import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import pytz
import sys
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, DateTime, LargeBinary, func, String
from functools import wraps
from flask_principal import Principal, Permission, RoleNeed, identity_loaded, UserNeed, Identity
from jinja2 import TemplateNotFound
from models import User, Task
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.date import DateTrigger
import logging
import mimetypes
from dotenv import load_dotenv
import calendar as cal
import json
import random
import string
from datetime import datetime, timedelta

load_dotenv()

app = Flask(__name__, static_url_path='/static')
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'static')

handler = logging.StreamHandler()
handler.setLevel(logging.ERROR)
app.logger.addHandler(handler)
app.logger.setLevel(logging.ERROR)

# Определяем конфигурацию на основе переданных аргументов или переменных окружения
if len(sys.argv) > 1:
    if sys.argv[1] == 'prod':
        app.config.from_object(ProductionConfig)
    elif sys.argv[1] == 'nlu':
        app.config.from_object(NLUConfig)
    elif sys.argv[1] == 'cal':
        app.config.from_object(CalConfig)
    else:
        app.config.from_object(DevelopmentConfig)
else:
    app.config.from_object(DevelopmentConfig)

# Установка порта из переменной окружения или аргумента командной строки
port = os.getenv('FLASK_PORT') or 5000
if len(sys.argv) > 2 and sys.argv[2].isdigit():
    port = int(sys.argv[2])

# Инициализация SQLAlchemy
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

roles_permissions = db.Table('roles_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permission.id'), primary_key=True)
)

class VerificationCode(db.Model):
    __tablename__ = 'verification_code'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    code = db.Column(db.String(6), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)

    def __repr__(self):
        return f'<VerificationCode {self.code}>'


scheduler = BackgroundScheduler()
scheduler.start()

def cleanup_expired_codes():
    try:
        now = datetime.now()
        expired_codes = VerificationCode.query.filter(VerificationCode.expires_at < now).all()
        for code in expired_codes:
            db.session.delete(code)
        db.session.commit()
    except Exception as e:
        app.logger.error(f"Error cleaning up expired verification codes: {e}")

# Запускаем очистку каждые 24 часа
scheduler.add_job(cleanup_expired_codes, 'interval', seconds=10)

class TaskAdmin(ModelView):
    column_list = ('content', 'description', 'priority', 'project_id', 'status', 'assignee')

# Инициализация Flask-Admin
admin = Admin(app, name='Admin Panel', template_mode='bootstrap3')

# Регистрация моделей для админки
admin.add_view(TaskAdmin(Task, db.session))

@identity_loaded.connect_via(app)
def on_identity_loaded(sender, identity):
    identity.user = current_user
    if hasattr(current_user, 'id'):
        identity.provides.add(UserNeed(current_user.id))
    if hasattr(current_user, 'role'):
        identity.provides.add(RoleNeed(current_user.role))

@app.route('/all_routes')
def all_routes():
    routes = []
    for rule in app.url_map.iter_rules():
        routes.append(str(rule))
    return '<br>'.join(routes)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect(url_for('login'))

# Настройки Telegram бота из переменных окружения
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

bot = TeleBot(TELEGRAM_BOT_TOKEN)


def generate_verification_code(length=6):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))


def send_verification_code(user):
    code = generate_verification_code()
    expires_at = datetime.now() + timedelta(minutes=10)

    verification = VerificationCode(user_id=user.id, code=code, expires_at=expires_at)
    db.session.add(verification)
    db.session.commit()

    # Логируем для отладки
    print(f"Sent verification code '{code}' to user ID {user.id}")

    # Отправляем код пользователю через Telegram API
    try:
        bot.send_message(user.telegram_id, f"Your verification code is {code}. It expires in 10 minutes.")
    except Exception as e:
        print(f"Error sending verification code: {e}")

def role_required(role_id_required):
    def decorator(view_function):
        @wraps(view_function)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()

            # Check if the current user has role id 1
            if current_user.role_id == 1:
                # If the current user's role id is 1, grant access
                return view_function(*args, **kwargs)

            # For other roles, check if the role id matches the required id
            if current_user.role_id != role_id_required:
                # If not, return a 403 Forbidden error
                abort(403)

            # If the current user has the required role id, proceed to the view function
            return view_function(*args, **kwargs)

        return wrapper

    return decorator

ROLE_ID = int(os.getenv('ROLE_ID'))

def permission_required(permission_name, role_id=None):
    def decorator(func):
        @wraps(func)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()

            # Проверяем, есть ли у пользователя разрешение
            if role_id is not None:
                # Если текущая роль совпадает с ролью из .env, предоставляем все разрешения
                if current_user.role_id == ROLE_ID:
                    return func(*args, **kwargs)

                if not (current_user.can(permission_name) or current_user.role_id == role_id):
                    abort(403)  # 403 Forbidden
            else:
                if not current_user.can(permission_name) and current_user.role_id != ROLE_ID:
                    abort(403)  # 403 Forbidden

            return func(*args, **kwargs)
        return decorated_function
    return decorator



@app.context_processor
def utility_processor():
    def check_permission(permission_name):
        return current_user.can(permission_name)

    return dict(permission_required=permission_required, check_permission=check_permission)

def hash_password(password):
    # Генерируем хэш пароля
    hashed_password = generate_password_hash(password)
    return hashed_password

scheduler = BackgroundScheduler()
scheduler.start()

def send_telegram_message(message):
    bot.send_message(TELEGRAM_CHAT_ID, message)

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    permissions = db.relationship('Permission', secondary=roles_permissions, backref=db.backref('roles', lazy='dynamic'))

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.TIMESTAMP, nullable=False, server_default=db.func.now())
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    user = db.relationship('User', back_populates='comments')

    def __repr__(self):
        return f'<Comment {self.id} by User {self.user_id}>'

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

    def start_task(self):
        self.start_time = datetime.now()
        self.status = 2  # Предположим, что статус 2 - "В работе"
        db.session.commit()

    def time_to_start(self):
        if self.start_time:
            current_time = datetime.now()
            time_to_start = self.start_time - current_time
            return time_to_start.total_seconds() > 0
        return False

    def end_task(self):
        self.end_time = datetime.now()
        self.status = 3  # Предположим, что статус 3 - "Готово"
        if self.start_time:
            duration_seconds = (self.end_time - self.start_time).total_seconds()
            self.duration = int(duration_seconds)
        db.session.commit()

    @staticmethod
    def format_duration(seconds):
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        seconds = seconds % 60
        return f"{hours}ч {minutes}м {seconds}с"

    def __repr__(self):
        return f'<Task {self.id}>'

    def update_details(self, content, description):
        self.content = content
        self.description = description

    def assign_to_user(self, user_id):
        self.assigned_to = user_id

    def add_comment(self, content, user_id):
        comment = Comment(content=content, task_id=self.id, user_id=user_id)
        db.session.add(comment)
        db.session.commit()

    def remove_comment(self, comment_id):
        comment = Comment.query.get(comment_id)
        if comment:
            db.session.delete(comment)
            db.session.commit()

    @classmethod
    def load_user(cls, user_id):
        return db.session.query(User).get(int(user_id))


class Sprint(db.Model):
    __tablename__ = 'sprints'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)

    def __init__(self, name, start_date, end_date):
        self.name = name
        self.start_date = start_date
        self.end_date = end_date


def __init__(self, usernick, username, password, role='user'):
    self.usernick = usernick
    self.username = username
    self.password = hash_password(password)
    self.role = role


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

    # Define relationship with Role
    role = db.relationship('Role', backref=db.backref('users', lazy=True))
    tasks = db.relationship('Task', backref='assigned_user', lazy=True)

    comments = db.relationship('Comment', back_populates='user', lazy=True)

    def is_active(self):
        return True

    # В функции can в модели User
    def can(self, permission_name):
        permission = Permission.query.filter_by(name=permission_name).first()
        return permission is not None and permission in self.role.permissions

    def display_name(self):
        if self.role:
            # Check if the role has the specific permission
            permission_name = "Отображать название организации перед именем"
            permission = Permission.query.filter_by(name=permission_name).first()
            if permission and permission in self.role.permissions:
                return f'{self.role.name} | {self.usernick}'
        return self.usernick

    def to_dict(self):
        return {
            'id': self.id,
            'usernick': self.usernick,
            'username': self.username,
            'role': self.role.name if self.role else None,
            'display_name': self.display_name()  # Include the display name in the dictionary
        }

# Функция для генерации уникального идентификатора задачи
def generate_unique_id(department):
    try:
        # Определение префикса в зависимости от отдела
        if department == 'Разработка - FullStack' or department == 'Разработка - Front' or department == 'Разработка - Back':
            prefix = 'DEV'
        elif department == 'Тестировка':
            prefix = 'TEST'
        elif department == 'DevOps':
            prefix = 'DPS'
        else:
            prefix = 'OTH'

        # Поиск последней задачи с таким же префиксом
        last_task = Task.query.filter(Task.task_id.startswith(prefix)).order_by(Task.id.desc()).first()

        if last_task:
            last_id_number = int(last_task.task_id.split('-')[1])
            new_id_number = last_id_number + 1
        else:
            new_id_number = 1

        return f"{prefix}-{new_id_number}"
    except Exception as e:
        print("Error generating unique ID:", e)
        return "OTH-1"

def require_telegram_link(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and not current_user.telegram_id:
            return redirect(url_for('link_telegram'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/link_telegram', methods=['GET', 'POST'])
@login_required
def link_telegram():
    if request.method == 'POST':
        telegram_id = request.form.get('telegram_id')

        if not telegram_id:
            flash('Telegram ID is required', 'error')
            return redirect(url_for('link_telegram'))

        user = current_user
        user.telegram_id = telegram_id
        db.session.commit()
        flash('Telegram ID successfully linked', 'success')
        return redirect(url_for('task_board'))

    return render_template('link_telegram.html')


@app.route('/task/<int:task_id>/comments', methods=['GET', 'POST'])
@login_required
def comments(task_id):
    task = Task.query.get_or_404(task_id)

    if request.method == 'POST':
        content = request.form.get('comment_content')
        if content:
            try:
                comment = Comment(content=content, user_id=current_user.id, task_id=task.id)
                db.session.add(comment)
                db.session.commit()

                # Возвращаем данные комментария в формате JSON
                comment_data = {
                    'username': comment.user.usernick,
                    'content': comment.content,
                    'created_at': comment.created_at.strftime('%Y-%m-%d %H:%M:%S')
                }
                # Отправляем уведомление в телеграм
                send_telegram_message(f'Добавлен новый комментарий от пользователя {comment.user.usernick} к задаче {task.task_id}:\n {content}')

                return jsonify(comment_data), 201  # HTTP статус 201 Created для успешного создания ресурса
            except Exception as e:
                print(e)
                return jsonify({'error': 'Failed to add comment'}), 400  # Пример обработки ошибки

    if request.method == 'GET':
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            comments = [{'username': comment.user.usernick, 'content': comment.content, 'created_at': comment.created_at.strftime('%Y-%m-%d %H:%M:%S')}
                        for comment in task.comments if comment.user]  # Проверяем, что comment.user не None
            return jsonify(comments)

    return render_template('comments.html', task=task, comments=task.comments)

from calendar import monthrange  # добавляем импорт
from collections import defaultdict

def get_contribution_data(user_tasks):
    contribution_data = defaultdict(int)
    for task in user_tasks:
        # Используем время создания задачи как дату, когда задача была добавлена
        created_date = task.created_at.date()
        contribution_data[created_date] += 1
    return sorted(contribution_data.items())

@app.route('/user')
@permission_required('Возможность просмотреть профиль пользователя')
def user_list():
    users = User.query.all()
    image_filename = current_user.image_file if current_user.image_file else ''
    return render_template('user_list.html', users=users, image_filename=image_filename)

@app.route('/user/<int:user_id>')
@permission_required('Возможность просмотреть профиль пользователя')
def user_profile(user_id):
    user = User.query.get_or_404(user_id)
    user_tasks = user.tasks  # Предполагаем, что у пользователя есть задачи, которые хранятся в user.tasks
    contribution_months = get_contribution_data(user_tasks)

    current_date = datetime.now()
    first_day_of_month = current_date.replace(day=1)
    _, days_in_month = monthrange(current_date.year, current_date.month)
    last_day_of_month = first_day_of_month + timedelta(days=days_in_month - 1)
    image_filename = current_user.image_file if current_user.image_file else ''
    return render_template('user_profile.html',
                           user=user,
                           contribution_months=contribution_months,
                           current_date=current_date,
                           first_day_of_month=first_day_of_month,
                           last_day_of_month=last_day_of_month,
                           image_filename=image_filename)

@app.route('/update_task/<id>', methods=['POST'])
def update_task(id):
    try:
        task = db.session.get(Task, id)
        if not task:
            return jsonify({"error": f"Задача с ID {id} не найдена"}), 404

        # Получаем данные из запроса
        content = request.json.get('content')
        description = request.json.get('description')
        assigned_to = request.json.get('assigned_to')

        # Обновляем задачу
        if content:
            task.content = content
        if description:
            task.description = description
        if assigned_to:
            task.assigned_to = assigned_to

        db.session.commit()

        return jsonify({"message": "Задача успешно обновлена"})
    except Exception as error:
        print("Error updating task:", error)
        return jsonify({"error": str(error)})

@app.route('/menu')
@login_required
@permission_required('Меню')
def menu():
    image_filename = current_user.image_file if current_user.image_file else ''
    return render_template('menu.html', user=current_user, image_filename=image_filename)

@app.route('/register')
def reg():
    image_filename = current_user.image_file if current_user.image_file else ''
    return render_template('reg.html', user=current_user,  image_filename=image_filename)

@app.route('/create_user', methods=['POST'])
def create_user():
    if request.method == 'POST':
        usernick = request.form['usernick']
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role')
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Пользователь с таким именем уже существует', 'error')
            return redirect(url_for('users'))
        if not (username and password and role):
            return jsonify({'error': 'Не все поля были заполнены'}), 400
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, usernick=usernick, password=hashed_password, role_id=role)
        db.session.add(new_user)
        db.session.commit()
        flash('Пользователь успешно создан', 'success')
        return redirect(url_for('users'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)  # Вход пользователя

            # Проверка двухфакторной аутентификации
            if user.can('Отключение двухэтапной аутентификации'):
                return redirect(url_for('task_board'))

            if user.telegram_id:
                send_verification_code(user)  # Отправка кода подтверждения
                session['pending_user_id'] = user.id
                return redirect(url_for('verify_telegram_code'))
            else:
                return redirect(url_for('link_telegram'))  # Перенаправление на привязку Telegram

        else:
            flash('Неправильное имя пользователя или пароль', 'error')

    return render_template('login.html')

def verify_code(user_id, code):
    verification = VerificationCode.query.filter_by(user_id=user_id, code=code).first()

    if verification and verification.expires_at > datetime.now():
        db.session.delete(verification)
        db.session.commit()
        print(f"Code '{code}' verified successfully for user ID {user_id}")
        return True
    else:
        print(f"Code '{code}' verification failed for user ID {user_id}")
        return False


@app.route('/verify_telegram_code', methods=['GET', 'POST'])
def verify_telegram_code():
    if request.method == 'POST':
        code = request.form['code']
        user_id = session.get('pending_user_id')

        if not user_id:
            flash('No pending user ID in session', 'error')
            return redirect(url_for('login'))

        user = User.query.get(user_id)
        if user and verify_code(user_id, code):  # Используйте user_id
            session.pop('pending_user_id', None)
            login_user(user)
            return redirect(url_for('task_board'))
        else:
            flash('Invalid verification code', 'error')

    return render_template('verify_telegram_code.html')


@app.route('/after_login', methods=['GET', 'POST'])
def after_login():
    user_name = current_user.usernick if current_user.is_authenticated else 'Неизвестный пользователь'
    send_telegram_message(f" Пользователь {user_name} вошёл в свой аккаунт")
    return redirect('/task_board')

@app.route('/admin_panel')
@login_required
def admin_panel():
    return 'Admin Panel'

@app.route('/change_role', methods=['POST'])
def change_role():
    data = request.get_json()
    user_id = data.get('user_id')
    new_role = data.get('new_role')

    user = User.query.get(user_id)
    if user:
        user.role_id = new_role
        db.session.commit()
        return jsonify(success=True, message="Роль успешно изменена.")
    else:
        return jsonify(success=False, message="Пользователь не найден."), 404

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')  # Перенаправление на страницу входа после выхода

@app.route('/phpmyadmin')
def phpmyadmin():
    return redirect('/phpmyadmin')
@app.route('/', methods=['GET', 'POST'])
@login_required
@permission_required('Главная')
def index():
    if request.method == 'POST':
        task_content = request.form['task_content']
        priority = int(request.form['priority'])
        description = request.form['description']
        customer = request.form['customer']
        department = request.form['department']

        # Получение префикса для уникального идентификатора
        unique_id = generate_unique_id(department)

        # Добавление имени заказчика в описание задачи
        task_description = f"{description}\n\nЗаказчик: {customer}\n\nОтдел: {department}"

        try:
            task_content_with_id = f"{unique_id}: {task_content}"
            # Сохранение задачи в локальной базе данных с уникальным task_id
            new_task = Task(
                task_id=unique_id,
                content=task_content_with_id,
                priority=priority,
                description=task_description,
                project_id=2322606786,
                status=1  # Assuming default section
            )
            db.session.add(new_task)
            db.session.commit()
            # Отправка уведомления в телеграм
            send_telegram_message(f"Новая задача: {task_content_with_id}")
            return jsonify({"message": "Задача успешно добавлена"})
        except Exception as error:
            # Логирование ошибки
            print("Error adding task:", error)
            return jsonify({"error": str(error)})
    elif request.method == 'GET':
        try:
            # Обработка GET запроса (получение данных)
            tasks = Task.query.all()
            image_filename = current_user.image_file if current_user.image_file else ''
            return render_template('index.html', tasks=tasks, user=current_user, image_filename=image_filename)
        except Exception as error:
            print("Error fetching tasks:", error)
            return jsonify({"error": str(error)})
    else:
        return "Method Not Allowed", 405  # Обработка других методов не поддерживается

@app.route('/start_task/<int:task_id>', methods=['POST'])
def start_task(task_id):
    try:
        task = Task.query.get(task_id)
        if not task:
            return jsonify({"error": f"Задача с ID {task_id} не найдена"}), 404

        task.start_task()
        unique_id = task.task_id
        user_name = current_user.usernick if current_user.is_authenticated else 'Неизвестный пользователь'
        send_telegram_message(f" Пользователь {user_name} взял задачу {unique_id} в работу")
        return jsonify("OK"), 200

    except Exception as error:
        print("Error starting task:", error)
        return jsonify({"error": str(error)}), 500

@app.route('/end_task/<int:task_id>', methods=['POST'])
def end_task(task_id):
    try:
        task = Task.query.get(task_id)
        if not task:
            return jsonify({"error": f"Задача с ID {task_id} не найдена"}), 404


        task.end_task()
        unique_id = task.task_id
        user_name = current_user.usernick if current_user.is_authenticated else 'Неизвестный пользователь'
        formatted_duration = format_duration(task.duration)
        send_telegram_message(f"Пользователь {user_name} завершил выполнение задачи {unique_id} за {formatted_duration}")
        return jsonify("OK"), 200

    except Exception as error:
        print("Error ending task:", error)
        return jsonify({"error": str(error)}), 500

def format_duration(seconds):
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    seconds = seconds % 60
    return f"{hours}ч {minutes}м {seconds}с"

@app.route('/admin', methods=['GET', 'POST'])
@login_required
@permission_required('Админ страница')
def admin():
    try:
        tasks = Task.query.all()

        section_status_mapping = {
            1: 'В очереди',
            2: 'В работе',
            3: 'Готово'
        }
        tasks_by_section = {
            'В очереди': [],
            'В работе': [],
            'Готово': []
        }

        # Собираем задачи по разделам
        for task in tasks:
            status = section_status_mapping.get(task.status, 'В очереди')
            if status in tasks_by_section:
                tasks_by_section[status].append(task)

        # Получаем имя файла изображения текущего пользователя
        image_filename = current_user.image_file if current_user.image_file else ''

        # Возвращаем шаблон только после того, как все данные подготовлены
        return render_template('indexfront.html', user=current_user, tasks_by_section=tasks_by_section, image_filename=image_filename)

    except Exception as error:
        print("Error fetching tasks:", error)
        return jsonify({"error": str(error)})


@app.route('/tasks', methods=['GET'])
def get_tasks():
    try:
        tasks = Task.query.all()
        task_list = []
        for task in tasks:
            section_status_mapping = {
                1: 'В очереди',
                2: 'В работе',
                3: 'Готово'
            }

            status = task.status
            task_status = section_status_mapping.get(status, 'В очереди')
            # Форматирование даты создания для удобного отображения
            created_at = task.created_at.strftime('%Y-%m-%d %H:%M:%S') if task.created_at else "Не указана"
            tags = task.tags
            assigned_user_name = None
            if task.user:
                assigned_user_name = task.user.usernick

            task_list.append({
                "content": task.content,
                "status": task_status,
                "created_at": created_at,
                "assigned_to": assigned_user_name,
                "tag": tags or []
            })

        return jsonify({"tasks": task_list})
    except Exception as error:
        print("Error fetching tasks:", error)
        return jsonify({"error": str(error)})

@app.route('/update_task_status', methods=['POST'])
def update_task_status():
    try:
        task_id = int(request.json.get('task_id'))  # Convert task_id to int
        new_status = request.json['status']

        section_status_mapping = {
            'В очереди': 1,
            'В работе': 2,
            'Готово': 3
        }

        id_to_status_mapping = {v: k for k, v in section_status_mapping.items()}

        if isinstance(new_status, str):
            new_section_id = section_status_mapping.get(new_status)
            if new_section_id is None:
                return jsonify({"error": "Неизвестный статус"}), 400
        elif isinstance(new_status, int) and new_status in id_to_status_mapping:
            new_section_id = new_status
            new_status = id_to_status_mapping[new_section_id]
        else:
            return jsonify({"error": "Некорректный формат статуса"}), 400

        # Query using task_id instead of id
        task = Task.query.filter_by(id=task_id).first()
        if task is None:
            return jsonify({"error": "Задача не найдена"}), 404

        old_status_id = task.status
        old_status = id_to_status_mapping.get(old_status_id, 'Неизвестный статус')
        task.status = new_section_id
        db.session.commit()

        user_name = current_user.usernick if current_user.is_authenticated else 'Неизвестный пользователь'
        send_telegram_message(f"Пользователь {user_name} обновил статус задачи {task.task_id} изменен с '{old_status}' на '{new_status}'")

        return jsonify({"message": "Статус задачи изменён"})
    except Exception as error:
        print("Ошибка обновления статуса задачи:", error)
        return jsonify({"error": str(error)}), 500


@app.route('/task/<int:task_id>/add_comment', methods=['POST'])
@login_required
def add_comment(task_id):
    task = Task.query.get_or_404(task_id)
    content = request.form.get('content')
    if content:
        try:
            comment = Comment(content=content, task_id=task.id, user_id=current_user.id)
            db.session.add(comment)
            db.session.commit()
            return jsonify({"message": "Комментарий успешно добавлен"}), 201
        except Exception as e:
            print("Error adding comment:", e)
            return jsonify({"error": str(e)}), 500
    return jsonify({"error": "Контент не может быть пустым"}), 400


@app.route('/sprint/create', methods=['GET', 'POST'])
@login_required
@permission_required('Создать спринт')
def create_sprint():
    image_filename = current_user.image_file if current_user.image_file else ''

    if request.method == 'POST':
        name = request.form.get('name')
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')

        if not all([name, start_date, end_date]):
            flash('Пожалуйста, заполните все поля', 'danger')
            return render_template('create_sprint.html', user=current_user, image_filename=image_filename)

        try:
            start_date = datetime.strptime(start_date, '%Y-%m-%d')
            end_date = datetime.strptime(end_date, '%Y-%m-%d')
        except ValueError:
            flash('Некорректный формат даты', 'danger')
            return render_template('create_sprint.html', user=current_user, image_filename=image_filename)

        sprint = Sprint(name=name, start_date=start_date, end_date=end_date)
        db.session.add(sprint)
        db.session.commit()

        flash('Спринт успешно создан!', 'success')
        return redirect(url_for('list_sprints'))

    return render_template('create_sprint.html', user=current_user, image_filename=image_filename)


@app.route('/sprints')
@login_required
@permission_required('Просматривать список спринтов')
def list_sprints():
    image_filename = current_user.image_file if current_user.image_file else ''
    sprints = Sprint.query.all()
    return render_template('list_sprints.html', sprints=sprints, user=current_user, image_filename=image_filename)

@app.route('/sprint/<int:sprint_id>', methods=['GET', 'POST'])
@login_required
@permission_required('Редактировать спринт')
def view_sprint(sprint_id):
    image_filename = current_user.image_file if current_user.image_file else ''
    sprint = Sprint.query.get_or_404(sprint_id)

    if request.method == 'POST':
        sprint.name = request.form.get('name')
        sprint.start_date = datetime.strptime(request.form.get('start_date'), '%Y-%m-%d')
        sprint.end_date = datetime.strptime(request.form.get('end_date'), '%Y-%m-%d')
        db.session.commit()

        flash('Спринт успешно обновлен!', 'success')
        return redirect(url_for('list_sprints'))

    return render_template('view_sprint.html', sprint=sprint, user=current_user, image_filename=image_filename)


def get_current_sprint():
    now = datetime.now()
    return Sprint.query.filter(Sprint.start_date <= now, Sprint.end_date >= now).first()

@app.route('/task_board', methods=['GET', 'POST'])
@login_required
@permission_required('Доска задач')
def task_board():
    try:
        filter_status = request.args.get('status')
        filter_tag = request.args.get('tag')
        filter_user = request.args.get('user')

        current_sprint = Sprint.query.filter(Sprint.start_date <= datetime.now(), Sprint.end_date >= datetime.now()).first()

        if not current_sprint:
            return render_template(
                'task_board.html',
                tasks_by_section={},
                user=current_user,
                image_filename=current_user.image_file if current_user.image_file else '',
                task_id=None,
                existing_tags=[],
                selected_status=filter_status,
                selected_tag=filter_tag,
                selected_user=filter_user,
                users_list=[],
                sprints=[]
            )

        query = Task.query.filter_by(sprint_id=current_sprint.id)

        section_status_mapping = {
            1: 'В очереди',
            2: 'В работе',
            3: 'Готово'
        }
        if filter_status in section_status_mapping.values():
            status_id = next(key for key, value in section_status_mapping.items() if value == filter_status)
            query = query.filter_by(status=status_id)

        if filter_tag:
            query = query.filter(Task.tags.contains(filter_tag))

        if filter_user:
            query = query.join(User).filter(User.usernick == filter_user)

        tasks = query.all()

        tasks_by_section = {
            'В очереди': [],
            'В работе': [],
            'Готово': []
        }

        for task in tasks:
            status = section_status_mapping.get(task.status, 'В очереди')
            if status in tasks_by_section:
                tasks_by_section[status].append(task)

        image_filename = current_user.image_file if current_user.image_file else ''
        existing_tags = db.session.query(Task.tags.distinct()).all()
        tags_list = [tag[0] for tag in existing_tags if tag[0]]

        users_list = db.session.query(User.usernick.distinct()).all()
        users_list = [user[0] for user in users_list if user[0]]

        sprints = Sprint.query.all()

        return render_template(
            'task_board.html',
            tasks_by_section=tasks_by_section,
            user=current_user,
            image_filename=image_filename,
            task_id=Task.id,
            existing_tags=tags_list,
            selected_status=filter_status,
            selected_tag=filter_tag,
            selected_user=filter_user,
            users_list=users_list,
            sprints=sprints
        )
    except Exception as error:
        print("Error fetching tasks:", error)
        return jsonify({"error": str(error)})

@app.route('/manage_roles', methods=['GET', 'POST'])
@login_required
@permission_required('Роли')
def manage_roles():
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        role_id = request.form.get('role_id')
        user = User.query.get(user_id)
        if user:
            user.role_id = role_id
            db.session.commit()
            return redirect(url_for('manage_roles'))

    users = User.query.all()
    roles = Role.query.all()
    return render_template('manage_roles.html', users=users, roles=roles)

@app.route('/roles', methods=['GET', 'POST'])
@login_required
@permission_required('Роли')
def role_management():
    if request.method == 'POST':
        if 'role_name' in request.form:
            # Handle role creation
            role_name = request.form['role_name']
            existing_role = Role.query.filter_by(name=role_name).first()
            if existing_role:
                flash('Role already exists!', 'error')
                return redirect(url_for('role_management'))

            selected_permissions = request.form.getlist('permissions')
            # Create the new role and assign permissions
            new_role = Role(name=role_name)
            db.session.add(new_role)
            db.session.commit()
            for permission_name in selected_permissions:
                permission = Permission.query.filter_by(name=permission_name).first()
                if permission:
                    new_role.permissions.append(permission)
            db.session.commit()
            flash('Role created successfully!', 'success')

        elif 'role_id' in request.form:
            # Handle role update
            role_id = request.form['role_id']
            selected_permissions = request.form.getlist('permissions')
            role = Role.query.get(role_id)
            if role:
                role.permissions = []
                for permission_name in selected_permissions:
                    permission = Permission.query.filter_by(name=permission_name).first()
                    if permission:
                        role.permissions.append(permission)
                db.session.commit()
                flash('Role updated successfully!', 'success')

        return redirect(url_for('role_management'))

    permissions = Permission.query.all()
    roles = Role.query.all()
    image_filename = current_user.image_file if current_user.image_file else ''
    return render_template('create_role.html', permissions=permissions, roles=roles, image_filename=image_filename)

@app.route('/get_role_permissions/<int:role_id>', methods=['GET'])
@login_required
def get_role_permissions(role_id):
    role = Role.query.get(role_id)
    if not role:
        return jsonify({"permissions": []}), 404
    permissions = [permission.name for permission in role.permissions]
    return jsonify({"permissions": permissions})

@app.route('/select_role', methods=['POST'])
def select_role():
    role_id = request.form.get('role_id')
    # Handle role selection logic here
    return redirect(url_for('role_management'))

@app.route('/create_permission', methods=['GET', 'POST'])
@login_required
@permission_required('Роли')
def create_permission():
    if request.method == 'POST':
        permission_name = request.form.get('permission_name')
        new_permission = Permission(name=permission_name)
        db.session.add(new_permission)
        db.session.commit()
        return redirect(url_for('create_permission'))

    return render_template('create_permission.html')

@app.route('/restart_calls')
def restart_calls():
    # Выполняем команду supervisorctl restart calls с помощью subprocess
    try:
        subprocess.run(['supervisorctl', 'restart', 'calls'], check=True)
        return 'Команда supervisorctl restart calls выполнена успешно'
    except subprocess.CalledProcessError:
        return 'Ошибка выполнения команды supervisorctl restart calls'

@app.route('/task_nlu')
@login_required
def task_board_nlu():
    try:
        tasks = Task.query.all()
        section_status_mapping = {
            1: 'В очереди',
            2: 'В работе',
            3: 'Готово'
        }
        tasks_by_section = {
            'В очереди': [],
            'В работе': [],
            'Готово': []
        }
        for task in tasks:
            status = section_status_mapping.get(task.status, 'В очереди')
            if status in tasks_by_section:
                tasks_by_section[status].append(task)

        image_filename = current_user.image_file if current_user.image_file else ''
        return render_template('task_boardnlu.html', tasks_by_section=tasks_by_section, user=current_user, image_filename=image_filename)
    except Exception as error:
        print("Error fetching tasks:", error)
        return jsonify({"error": str(error)})

@app.route('/create_task', methods=['POST'])
@login_required
def create_task():
    try:
        # Получаем данные из JSON-запроса
        data = request.json
        task_content = data.get('task_content')
        priority = data.get('priority')
        description = data.get('description')
        customer = data.get('customer')
        department = data.get('department')
        assigned_to_id = data.get('assigned_to')
        selected_tag = data.get('tags')  # Выбранный тег из списка
        new_tag = data.get('newTag')  # Новый тег, введенный пользователем
        sprint_id = data.get('sprint')

        if not all([task_content, priority, description, customer, department, assigned_to_id, sprint_id]):
            return jsonify({"error": "Не все обязательные поля заполнены"}), 400

        try:
            priority = int(priority)
            assigned_to_id = int(assigned_to_id)
            sprint_id = int(sprint_id)
        except ValueError:
            return jsonify({"error": "Поля priority, assigned_to и sprint должны быть числовыми"}), 400

        assigned_user = User.query.get(assigned_to_id)
        if not assigned_user:
            return jsonify({"error": "Назначенный пользователь не найден"}), 404

        task_description = f"{description}\n\nЗаказчик: {customer}\n\nОтдел: {department}"
        unique_id = generate_unique_id(department)
        task_content_with_id = f"{unique_id}: {task_content}"

        gmt_plus_5 = pytz.timezone('Etc/GMT-5')
        created_at = datetime.now(gmt_plus_5)

        # Определяем, какой тег использовать в новой задаче
        tag_to_use = selected_tag if selected_tag else new_tag

        # Создаем новую задачу с указанием тэга
        new_task = Task(
            task_id=unique_id,
            content=task_content_with_id,
            priority=priority,
            description=task_description,
            project_id=2322606786,
            status=1,  # По умолчанию "В очереди"
            created_at=created_at,
            assigned_to=assigned_to_id,
            sprint_id=sprint_id,
            tags=','.join(tag_to_use) if isinstance(tag_to_use, list) else tag_to_use
        )
        db.session.add(new_task)
        db.session.commit()

        user_name = current_user.usernick
        send_telegram_message(f"Пользователь {user_name} добавил задачу {task_content_with_id} | Исполнитель: {assigned_user.usernick}")

        return jsonify({"message": "Задача успешно добавлена", "task_id": unique_id, "content": task_content_with_id})
    except Exception as error:
        print("Error creating task:", error)
        return jsonify({"error": str(error)}), 500



@app.route('/test')
def calendar():
    return render_template('calendar.html')

@app.route('/kanban')
def kanban():
    return render_template('kanban.html')

@app.route('/api/v2/tasks')
def api_v2_tasks():
    tasks = Task.query.all()
    tasks_data = [{
        'id': task.id,
        'content': task.content,
        'status': task.status,
        'start_time': task.start_time.strftime('%Y-%m-%d') if task.start_time else None,
        'end_time': task.end_time.strftime('%Y-%m-%d') if task.end_time else None
    } for task in tasks]
    return jsonify(tasks_data)

@app.route('/api/tasks', methods=['GET', 'POST'])
def api_tasks():
    if request.method == 'POST':
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid data'}), 400
        department = request.json.get('department')
        unique_id = generate_unique_id(department)

        task = Task(
            task_id=unique_id,
            content=data.get('title'),
            description=data.get('description'),
            start_time=datetime.fromisoformat(data.get('start')),
            end_time=datetime.fromisoformat(data.get('end')),
            priority=1,  # Установить значение приоритета по умолчанию
            status=1  # Установить значение статуса по умолчанию
        )
        db.session.add(task)
        db.session.commit()
        send_telegram_message(f"Задача добавлена в Календарь: {task.task_id} | {task.content}")
        return jsonify({'success': 'Task added'}), 201
    tasks = Task.query.all()
    events = []
    for task in tasks:
        event = {
            'unique_id': task.task_id,
            'title': task.content,
            'start': task.start_time.isoformat() if task.start_time else None,
            'end': task.end_time.isoformat() if task.end_time else None,
            'description': task.description
        }
        events.append(event)
    return jsonify(events)

@app.route('/api/tasks/<int:task_id>', methods=['DELETE'])
def delete_task_api(task_id):
    task = Task.query.get_or_404(task_id)  # Получаем задачу по её ID или возвращаем 404 ошибку, если не найдена
    db.session.delete(task)  # Удаляем задачу из сессии SQLAlchemy
    db.session.commit()  # Применяем изменения в базе данных

    return jsonify({"message": "Task deleted successfully"})
@app.route('/users')
@login_required
@permission_required('Пользователи')
def users():
    try:
        users = User.query.all()
        image_filename = current_user.image_file if current_user.image_file else ''
        roles = Role.query.all()
        return render_template('register.html', users=users, user=current_user, image_filename=image_filename, roles=roles)
    except Exception as error:
        print("Error fetching users:", error)
        return jsonify({"error": str(error)}), 500

@app.route('/users_by_role/<int:role_id>')
def users_by_role(role_id):
    role = Role.query.get_or_404(role_id)
    users = User.query.filter_by(role_id=role.id).all()
    return jsonify(users=[user.to_dict() for user in users])

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    data = request.get_json()
    user_id = data['user_id']
    new_password = data['new_password']
    user = User.query.get(user_id)
    if user:
        user.password = generate_password_hash(new_password)
        db.session.commit()
        return jsonify({'message': 'Password updated successfully'}), 200
    return jsonify({'error': 'User not found'}), 404


@app.route('/delete_user', methods=['POST'])
@login_required
def delete_user():
    if request.method == 'POST':
        data = request.get_json()
        user_id = data.get('user_id')

        if user_id:
            user = User.query.get(user_id)
            if user:
                db.session.delete(user)
                db.session.commit()
                return jsonify({'message': 'Пользователь успешно удален'}), 200
            else:
                return jsonify({'error': 'Пользователь не найден'}), 404
        else:
            return jsonify({'error': 'Отсутствует или неверный user_id'}), 400
    else:
        return jsonify({'error': 'Метод не поддерживается'}), 405

@app.route('/delete_tasks', methods=['POST'])
def delete_tasks():
    try:
        task_ids = request.form.getlist('task_ids[]')  # Используем getlist для получения всех значений с одним именем
        if task_ids:
            Task.query.filter(Task.task_id.in_(task_ids)).delete(synchronize_session='fetch')
            db.session.commit()
            for task_id in task_ids:
                send_telegram_message(f"Задача удалена: {task_id}")
            return jsonify({"message": "Tasks successfully deleted"})
        else:
            return jsonify({"error": "No tasks selected"}), 400
    except Exception as error:
        print("Error deleting tasks:", error)
        return jsonify({"error": str(error)}), 500

@app.route('/pravki', methods=['GET'])
def run_script():
    try:
        # Запускаем bash-скрипт
        result = subprocess.run(['/root/todo_bot/pravki.sh'], capture_output=True, text=True, check=True)
        return jsonify({
            'success': True,
            'stdout': result.stdout,
            'stderr': result.stderr
        })
    except subprocess.CalledProcessError as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'stdout': e.stdout,
            'stderr': e.stderr
        }), 500

@app.route('/get_users', methods=['GET'])
def get_users():
    try:
        users = User.query.all()
        user_list = [{'id': user.id, 'username': user.usernick} for user in users]

        return jsonify(user_list)
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/profile', methods=['GET'])
@login_required
@permission_required('Профиль')
def profile():
    user_tasks = current_user.tasks  # Получаем задачи текущего пользователя
    contribution_months = get_contribution_data(user_tasks)

    current_date = datetime.now()
    first_day_of_month = current_date.replace(day=1)
    _, days_in_month = monthrange(current_date.year, current_date.month)
    last_day_of_month = first_day_of_month + timedelta(days=days_in_month - 1)

    # Передаем данные текущего пользователя и другие переменные в шаблон
    return render_template('profile.html',
                           user=current_user,  # Передаем текущего пользователя
                           image_filename=current_user.image_file if current_user.image_file else '',
                           contribution_months=contribution_months,
                           current_date=current_date,
                           first_day_of_month=first_day_of_month,
                           last_day_of_month=last_day_of_month)

@app.route('/update_avatar', methods=['POST'])
@login_required
def update_avatar():
    if 'new-avatar' in request.files:
        new_avatar = request.files['new-avatar']
        if new_avatar.filename != '' and allowed_file(new_avatar.filename):
            filename = secure_filename(new_avatar.filename)
            new_avatar.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            current_user.image_file = filename
            try:
                db.session.commit()
                flash('Аватар обновлен успешно!', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f'Ошибка при сохранении аватара: {str(e)}', 'error')
        else:
            flash('Недопустимый формат файла для загрузки.', 'error')
    else:
        flash('Файл не был передан.', 'error')

    return redirect(url_for('profile'))

def allowed_file(filename):
    if '.' not in filename:
        return False

    ext = filename.rsplit('.', 1)[1].lower()

    if ext not in {'jpg', 'jpeg', 'png', 'gif'}:
        return False

    # Проверяем тип MIME файла
    mime_type, _ = mimetypes.guess_type(filename)
    if mime_type is None or not mime_type.startswith('image'):
        return False

    # Дополнительная проверка на безопасность: предотвращение загрузки опасных файлов
    if ext in {'exe', 'bat', 'sh', 'php'}:  # примеры опасных расширений
        return False

    return True


# Маршрут для обновления имени пользователя
@app.route('/update_name', methods=['POST'])
@login_required
def update_name():
    new_name = request.form.get('new-name')
    current_user.usernick = new_name
    db.session.commit()
    flash('Имя пользователя обновлено успешно!', 'success')
    return redirect(url_for('profile'))

@app.route('/update_name_admin', methods=['POST'])
@login_required
def update_name_admin():
    data = request.get_json()
    user_id = data['user_id']
    new_name = data['new_name']
    user = User.query.get(user_id)
    if user:
        user.usernick = new_name
        db.session.commit()
        return jsonify({'message': 'Никнейм изменён'}), 200
    return jsonify({'error': 'Пользователь не найден'}), 404

# Маршрут для обновления пароля пользователя
@app.route('/update_password', methods=['POST'])
@login_required
def update_password():
    current_password = request.form.get('current-password')
    new_password = request.form.get('new-password')
    confirm_password = request.form.get('confirm-password')

    if new_password != confirm_password:
        flash('Новый пароль и подтверждение пароля не совпадают.', 'error')
        return redirect(url_for('profile'))

    if not check_password_hash(current_user.password, current_password):
        flash('Текущий пароль введен неверно.', 'error')
        return redirect(url_for('profile'))

    current_user.password = generate_password_hash(new_password)
    db.session.commit()
    flash('Пароль успешно обновлен!', 'success')
    return redirect(url_for('profile'))

@app.route('/show_delete_task')
@login_required
@permission_required('Удаление задач')
def show_delete_task():
    tasks = Task.query.all()
    image_filename = current_user.image_file if current_user.image_file else ''
    return render_template('delete_task.html', tasks=tasks, user=current_user, image_filename=image_filename)

def template_exists(template_name):
    try:
        app.jinja_env.get_template(template_name)
        return True
    except TemplateNotFound:
        print(f"Template not found: {template_name}")  # Добавьте эту строку для отладки
        return False

app.jinja_env.globals['template_exists'] = template_exists

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=port, debug=True)