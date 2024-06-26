from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.date import DateTrigger
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import telebot

# Создание экземпляра приложения Flask
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://admin:hf3h8hews@localhost/cal'  # Замените на вашу строку подключения к БД
db = SQLAlchemy(app)

# Настройка Telegram бота
TELEGRAM_BOT_TOKEN = '6681103388:AAEza9CHKOxC_J-_4p6t-2HJ32z7_onpyJ4'
TELEGRAM_CHAT_ID = '1212068138'

bot = telebot.TeleBot(TELEGRAM_BOT_TOKEN)

# Модель данных для задачи
class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.String(80), unique=True, nullable=False)
    start_time = db.Column(db.DateTime)

    def time_to_start(self):
        if self.start_time:
            current_time = datetime.now()
            time_to_start = self.start_time - current_time
            return time_to_start.total_seconds() > 0
        return False

# Настройка планировщика задач
scheduler = BackgroundScheduler()
scheduler.start()

# Функция для отправки уведомления в Telegram
def send_telegram_message(message):
    bot.send_message(TELEGRAM_CHAT_ID, message)

# Функция для отправки уведомления
def send_notification(task_id):
    with app.app_context():
        task = Task.query.get(task_id)
        if task:
            try:
                message = f"Напоминание: Задача {task.task_id} начинается сейчас!"
                send_telegram_message(message)
                app.logger.info(f"Уведомление отправлено для задачи {task_id} в {datetime.now()}")
            except Exception as e:
                app.logger.error(f"Ошибка отправки уведомления для задачи {task_id}: {e}")

# Функция для проверки и планирования уведомлений
def check_and_notify():
    with app.app_context():
        try:
            tasks = Task.query.filter(Task.start_time != None).all()
            for task in tasks:
                if task.time_to_start():
                    notification_time = task.start_time - timedelta(minutes=15)
                    scheduler.add_job(send_notification, trigger=DateTrigger(run_date=notification_time), args=[task.id])
                    print(f"Запланировано уведомление для задачи {task.task_id} в {notification_time}")
        except Exception as e:
            app.logger.error(f"Ошибка при планировании уведомлений: {e}")

# Добавление задачи для проверки и планирования уведомлений с интервалом 1 минута
scheduler.add_job(check_and_notify, 'interval', minutes=1)

# Обработчик для команды /start
@bot.message_handler(commands=['start'])
def send_welcome(message):
    print("Received /start command")
    bot.reply_to(message, "Привет! Я бот уведомлений.")

# Запуск приложения Flask
if __name__ == '__main__':
    app.run(debug=False)
