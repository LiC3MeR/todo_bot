from flask import Flask, render_template, request, jsonify, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from telebot import TeleBot
import os
import subprocess

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://admin:hf3h8hews@localhost/tasks'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Настройки Telegram бота из переменных окружения
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "6734859669:AAFPaSB8FwPPXS7P0dBDFvUj1wPlxPWVsH0")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "-1002075733635")

bot = TeleBot(TELEGRAM_BOT_TOKEN)

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

# Initialize Flask-Admin
admin = Admin(app, name='Admin Panel', template_mode='bootstrap3')
admin.add_view(ModelView(Task, db.session))

@app.route('/phpmyadmin')
def phpmyadmin():
    return redirect('/phpmyadmin')

@app.route('/', methods=['GET', 'POST'])
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
            task_list.append({"content": task.content, "status": task_status})

        return jsonify({"tasks": task_list})
    except Exception as error:
        print("Error fetching tasks:", error)
        return jsonify({"error": str(error)})


@app.route('/update_task_status', methods=['POST'])
def update_task_status():
    try:
        task_id = request.json['task_id']
        new_status = request.json['status']

        # Mapping for status names to section IDs
        section_status_mapping = {
            'В очереди': 1,
            'В работе': 2,
            'Готово': 3
        }

        # Determine the new section ID based on the status provided
        if isinstance(new_status, str):
            new_status = section_status_mapping.get(new_status)
        elif isinstance(new_status, int):
            new_status = new_status
        else:
            return jsonify({"error": "Неизвестная ошибка"})

        if new_status is None:
            return jsonify({"error": "Неизвестный статус"})

        task = Task.query.filter_by(task_id=task_id).first()
        if task is None:
            return jsonify({"error": "Задача не найдена"})

        old_status = section_status_mapping.get(task.status, 'В очереди')
        task.status = new_status
        db.session.commit()

        # Отправка уведомления в телеграм
        send_telegram_message(f"Статус задачи {task_id} изменен с '{old_status}' на '{new_status}'")

        return jsonify({"message": "Статус задачи изменён"})
    except Exception as error:
        print("Ошибка обновления статуса задачи:", error)
        return jsonify({"error": str(error)})

@app.route('/task_board')
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

@app.route('/create_task', methods=['POST'])
def create_task():
    try:
        task_content = request.json['task_content']
        priority = int(request.json['priority'])
        description = request.json['description']
        customer = request.json['customer']
        department = request.json['department']
        task_description = f"{description}\n\nЗаказчик: {customer}\n\nОтдел: {department}"

        unique_id = generate_unique_id()
        task_content_with_id = f"{unique_id}: {task_content}"

        new_task = Task(
            task_id=unique_id,
            content=task_content_with_id,
            priority=priority,
            description=task_description,
            project_id=2322606786,
            status=1  # Default to "В очереди"
        )
        db.session.add(new_task)
        db.session.commit()
        send_telegram_message(f"Новая задача: {task_content_with_id}")
        return jsonify({"message": "Задача успешно добавлена", "task_id": unique_id, "content": task_content_with_id})
    except Exception as error:
        print("Error creating task:", error)
        return jsonify({"error": str(error)})

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

@app.route('/show_delete_task')
def show_delete_task():
    tasks = Task.query.all()
    return render_template('delete_task.html', tasks=tasks)



if __name__ == '__main__':
    app.run(host='0.0.0.0', port='777')