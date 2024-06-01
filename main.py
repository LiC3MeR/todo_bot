from flask import Flask, render_template, request, jsonify, redirect, flash, url_for, redirect, abort
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from telebot import TeleBot
import os
import subprocess
from flask_login import LoginManager, login_required, login_user, logout_user, current_user, UserMixin
from config import DevelopmentConfig, ProductionConfig, NLUConfig
from werkzeug.security import generate_password_hash, check_password_hash
from models import User, Task
from flask_bcrypt import generate_password_hash, check_password_hash
from datetime import datetime
import pytz
import sys
from sqlalchemy.orm import relationship
from functools import wraps
from flask_principal import Principal, Permission, RoleNeed, identity_loaded, UserNeed, Identity
from jinja2 import TemplateNotFound


app = Flask(__name__, static_url_path='/static')

# Определяем конфигурацию на основе переданных аргументов или переменных окружения
if len(sys.argv) > 1:
    if sys.argv[1] == 'prod':
        app.config.from_object(ProductionConfig)
    elif sys.argv[1] == 'nlu':
        app.config.from_object(NLUConfig)
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

class TaskAdmin(ModelView):
    column_list = ('content', 'description', 'priority', 'project_id', 'status', 'assignee')

# Инициализация Flask-Admin
admin = Admin(app, name='Admin Panel', template_mode='bootstrap3')

# Регистрация моделей для админки
from models import User, Task  # Подключаем модели после инициализации db
admin.add_view(TaskAdmin(Task, db.session))

@identity_loaded.connect_via(app)
def on_identity_loaded(sender, identity):
    identity.user = current_user
    if hasattr(current_user, 'id'):
        identity.provides.add(UserNeed(current_user.id))
    if hasattr(current_user, 'role'):
        identity.provides.add(RoleNeed(current_user.role))

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect(url_for('login'))

# Настройки Telegram бота из переменных окружения
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "6734859669:AAFPaSB8FwPPXS7P0dBDFvUj1wPlxPWVsH0")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "-1002075733635")

bot = TeleBot(TELEGRAM_BOT_TOKEN)

def role_required(role):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.role != role:
                return abort(403)  # Доступ запрещен
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper

def hash_password(password):
    # Генерируем хэш пароля
    hashed_password = generate_password_hash(password, rounds=8).decode('utf-8')
    return hashed_password

    def __init__(self, username, password):
        self.username = username
        self.password = hash_password(password)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(80), nullable=False)
    def is_active(self):
        return True

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.String(80), unique=True, nullable=False)
    content = db.Column(db.String(200), nullable=False)
    priority = db.Column(db.Integer, nullable=False)
    description = db.Column(db.String(500), nullable=False)
    project_id = db.Column(db.BigInteger, nullable=True)
    status = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.TIMESTAMP, nullable=False, server_default=db.func.now())

    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref=db.backref('tasks_assigned', lazy=True))

    def __repr__(self):
        return f'<Task {self.id}>'

    def update_details(self, content, description):
        self.content = content
        self.description = description

    def assign_to_user(self, user_id):
        self.assigned_to = user_id

    def load_user(user_id):
        return db.session.query(User).get(int(user_id))

# Function to initialize the database
def init_db():
    with app.app_context():
        db.create_all()

# Initialize the database
init_db()

# Функция для отправки уведомления в телеграм
def send_telegram_message(message):
    bot.send_message(TELEGRAM_CHAT_ID, message)

# Функция для генерации уникального идентификатора задачи
def generate_unique_id(department):
    try:
        # Определение префикса в зависимости от отдела
        if department == 'Разработка - FullStack' or department == 'Разработка - Front' or department == 'Разработка - Back':
            prefix = 'DEV'
        elif department == 'Тестировка':
            prefix = 'TEST'
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

@app.route('/update_task/<task_id>', methods=['POST'])
def update_task(task_id):
    try:
        task = Task.query.filter_by(task_id=task_id).first()
        if not task:
            return jsonify({"error": f"Задача с ID {task_id} не найдена"}), 404

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
def menu():
    return render_template('menu.html')

@app.route('/register')
@login_required
def reg():
    return render_template('reg.html')

@app.route('/create_user', methods=['POST'])
@login_required
@role_required('admin')
def create_user():
    if request.method == 'POST':
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
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('Пользователь успешно создан', 'success')
        return redirect(url_for('users'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Check user data (e.g., from the database)
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect('/menu')
        else:
            flash('Incorrect username or password', 'error')
    return render_template('login.html')

@app.route('/admin_panel')
@login_required
@role_required('admin')
def admin_panel():
    return 'Admin Panel'

@app.route('/change_role', methods=['POST'])
def change_role():
    data = request.get_json()
    user_id = data.get('user_id')
    new_role = data.get('new_role')

    user = User.query.get(user_id)
    if user:
        user.role = new_role
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
            return render_template('index.html', tasks=tasks)
        except Exception as error:
            print("Error fetching tasks:", error)
            return jsonify({"error": str(error)})
    else:
        return "Method Not Allowed", 405  # Обработка других методов не поддерживается

@app.route('/admin', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def admin():
    if request.method == 'POST':
        task_content = request.form['task_content']
        priority = int(request.form['priority'])
        description = request.form['description']
        customer = request.form['customer']  # Добавлено поле "Заказчик"
        department = request.form['department']
        # Добавление имени заказчика в описание задачи
        task_description = f"{description}\n\nЗаказчик: {customer}\n\nОтдел: {department}"

        try:
            unique_id = generate_unique_id()
            task_content_with_id = f"{unique_id}: {task_content}"
            # Save the task in the local database with a unique task_id
            new_task = Task(task_id=unique_id, content=task_content_with_id, priority=priority, description=task_description, project_id=2322606786, status=1)
            db.session.add(new_task)
            db.session.commit()
            # Отправка уведомления в телеграм
            send_telegram_message(f"Новая задача: {task_content_with_id}")
            return jsonify({"message": "Задача успешно добавлена"})
        except Exception as error:
            # Логирование ошибки
            print("Error adding task:", error)
            return jsonify({"error": str(error)})
    else:
        try:
            tasks = Task.query.all()
            return render_template('indexfront.html', tasks=tasks)
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
            task_list.append({
                "content": task.content,
                "status": task_status,
                "created_at": created_at  # Добавление даты создания
            })

        return jsonify({"tasks": task_list})
    except Exception as error:
        print("Error fetching tasks:", error)
        return jsonify({"error": str(error)})

@app.route('/update_task_status', methods=['POST'])
def update_task_status():
    try:
        task_id = request.json['task_id']
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

        task = Task.query.filter_by(task_id=task_id).first()
        if task is None:
            return jsonify({"error": "Задача не найдена"}), 404

        old_status_id = task.status
        old_status = id_to_status_mapping.get(old_status_id, 'Неизвестный статус')
        task.status = new_section_id
        db.session.commit()

        send_telegram_message(f"Статус задачи {task_id} изменен с '{old_status}' на '{new_status}'")

        return jsonify({"message": "Статус задачи изменён"})
    except Exception as error:
        print("Ошибка обновления статуса задачи:", error)
        return jsonify({"error": str(error)}), 500

@app.route('/task_board')
@login_required
@role_required('admin')
def task_board():
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

        return render_template('task_board.html', tasks_by_section=tasks_by_section)
    except Exception as error:
        print("Error fetching tasks:", error)
        return jsonify({"error": str(error)})

@app.route('/task_nlu')
@login_required
@role_required('admin')
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

        return render_template('task_boardnlu.html', tasks_by_section=tasks_by_section)
    except Exception as error:
        print("Error fetching tasks:", error)
        return jsonify({"error": str(error)})

@app.route('/create_task', methods=['POST'])
@login_required
def create_task():
    try:
        # Получаем данные из запроса
        task_content = request.json.get('task_content')
        priority = request.json.get('priority')
        description = request.json.get('description')
        customer = request.json.get('customer')
        department = request.json.get('department')
        assigned_to = request.json.get('assigned_to')

        # Проверяем обязательные поля и их типы данных
        if not all([task_content, priority, description, customer, department, assigned_to]):
            return jsonify({"error": "Не все обязательные поля заполнены"}), 400

        # Преобразуем при необходимости
        try:
            priority = int(priority)
            assigned_to = int(assigned_to)
        except ValueError:
            return jsonify({"error": "Поля priority и assigned_to должны быть числовыми"}), 400

        # Остальной код сохранения задачи
        task_description = f"{description}\n\nЗаказчик: {customer}\n\nОтдел: {department}"
        unique_id = generate_unique_id(department)
        task_content_with_id = f"{unique_id}: {task_content}"

        gmt_plus_5 = pytz.timezone('Etc/GMT-5')
        created_at = datetime.now(gmt_plus_5)

        new_task = Task(
            task_id=unique_id,
            content=task_content_with_id,
            priority=priority,
            description=task_description,
            project_id=2322606786,
            status=1,  # Default to "В очереди"
            created_at=created_at,
            assigned_to=assigned_to
        )
        db.session.add(new_task)
        db.session.commit()
        send_telegram_message(f"Новая задача: {task_content_with_id}")

        return jsonify({"message": "Задача успешно добавлена", "task_id": unique_id, "content": task_content_with_id})
    except Exception as error:
        print("Error creating task:", error)
        return jsonify({"error": str(error)}), 500


@app.route('/users')
@login_required
def users():
    if current_user.role != 'admin':
        abort(403)

    try:
        users = User.query.all()
        return render_template('register.html', users=users)
    except Exception as error:
        print("Error fetching users:", error)
        return jsonify({"error": str(error)}), 500

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

@app.route('/delete_task', methods=['POST'])
def delete_task():
    try:
        task_id = request.form.get('task_id')
        if not task_id:
            return jsonify({"error": "Task ID is required"}), 400

        task = Task.query.filter_by(task_id=task_id).first()
        if task is None:
            return jsonify({"error": "Task not found"}), 404

        db.session.delete(task)
        db.session.commit()
        send_telegram_message(f"Задача удалена: {task.content}")
        return jsonify({"message": "Task deleted successfully"})
    except Exception as error:
        print("Error deleting task:", error)
        return jsonify({"error": str(error)}), 500

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
        user_list = [{'id': user.id, 'username': user.username} for user in users]
        return jsonify(user_list)
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/show_delete_task')
@login_required
def show_delete_task():
    tasks = Task.query.all()
    return render_template('delete_task.html', tasks=tasks)

def template_exists(template_name):
    try:
        app.jinja_env.get_template(template_name)
        return True
    except TemplateNotFound:
        print(f"Template not found: {template_name}")  # Добавьте эту строку для отладки
        return False

app.jinja_env.globals['template_exists'] = template_exists

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=port)