from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from telebot import TeleBot
import os

app = Flask(__name__)

# Setup SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///base.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Настройки Telegram бота из переменных окружения
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "6734859669:AAFPaSB8FwPPXS7P0dBDFvUj1wPlxPWVsH0")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "-1002075733635")

bot = TeleBot(TELEGRAM_BOT_TOKEN)

# Define a Task model
class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.String(80), unique=True, nullable=False)
    content = db.Column(db.String(200), nullable=False)
    priority = db.Column(db.Integer, nullable=False)
    description = db.Column(db.String(500), nullable=False)
    project_id = db.Column(db.Integer, nullable=False)
    section_id = db.Column(db.Integer, nullable=False)

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
def generate_unique_id():
    try:
        last_task = Task.query.order_by(Task.id.desc()).first()
        if last_task and last_task.task_id.startswith("SYS-"):
            last_id_number = int(last_task.task_id.split('-')[1])
            new_id_number = last_id_number + 1
        else:
            new_id_number = 1
        return f"SYS-{new_id_number}"
    except Exception as e:
        print("Error generating unique ID:", e)
        return "SYS-1"  # Fallback to "SYS-1" if there's an error

@app.route('/', methods=['GET', 'POST'])
def index():
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
            new_task = Task(task_id=unique_id, content=task_content_with_id, priority=priority, description=task_description, project_id=2322606786, section_id=155860104)
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
            return render_template('index.html', tasks=tasks)
        except Exception as error:
            print("Error fetching tasks:", error)
            return jsonify({"error": str(error)})

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
            new_task = Task(task_id=unique_id, content=task_content_with_id, priority=priority, description=task_description, project_id=2322606786, section_id=155860104)
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
                155860104: 'В очереди',
                155859386: 'В работе',
                138005323: 'Готово'
            }

            section_id = task.section_id
            task_status = section_status_mapping.get(section_id, 'Статус неизвестен')
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
            '155860104': 155860104,
            '155859386': 155859386,
            '138005323': 138005323
        }

        # Determine the new section ID based on the status provided
        if isinstance(new_status, str):
            new_section_id = section_status_mapping.get(new_status)
        elif isinstance(new_status, int):
            new_section_id = new_status
        else:
            return jsonify({"error": "Не известный формат статса"})

        if new_section_id is None:
            return jsonify({"error": "Неизвестный статус"})

        task = Task.query.filter_by(task_id=task_id).first()
        if task is None:
            return jsonify({"error": "Задача не найдена"})

        task.section_id = new_section_id
        db.session.commit()
        return jsonify({"message": "Задача успешно обновена"})
    except Exception as error:
        print("Error updating task status:", error)
        return jsonify({"error": str(error)})

if __name__ == '__main__':
    app.run(host='0.0.0.0')