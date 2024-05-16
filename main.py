import telebot
from flask import Flask, render_template, request, jsonify
from todoist_api_python.api import TodoistAPI

app = Flask(__name__)
api = TodoistAPI("376f6ca4763413e176fd2a0eadd30af37f44cbea")

# Настройки телеграм бота
TELEGRAM_BOT_TOKEN = "6978569386:AAHPFeCfyfPDCrZS_HfvT6i5oP8cnBfP-b4"
TELEGRAM_CHAT_ID = "1212068138"

# Создание экземпляра бота
bot = telebot.TeleBot(TELEGRAM_BOT_TOKEN)


# Функция для отправки уведомления в телеграм
def send_telegram_message(message):
    bot.send_message(TELEGRAM_CHAT_ID, message)


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        task_content = request.form['task_content']
        priority = int(request.form['priority'])
        description = request.form['description']
        customer = request.form['customer']  # Добавлено поле "Заказчик"'

        # Добавление имени заказчика в описание задачи
        task_description = f"{description}\n\nЗаказчик: {customer}"

        try:
            task = api.add_task(
                content=task_content,
                priority=priority,
                description=task_description,  # Используем обновленное описание задачи
                project_id=2322606786,
                section_id=155860104,
            )
            # Отправка уведомления в телеграм
            send_telegram_message(f"Новая задача: {task_content}")
            return jsonify({"message": "Задача успешно добавлена"})
        except Exception as error:
            # Логирование ошибки
            print("Error sending Telegram message:", error)
            return jsonify({"error": str(error)})
    else:
        try:
            tasks = api.get_tasks(project_id=2322606786)
            return render_template('index.html', tasks=tasks)
        except Exception as error:
            return jsonify({"error": str(error)})


@app.route('/tasks', methods=['GET'])
def get_tasks():
    try:
        tasks = api.get_tasks(project_id=2322606786)
        task_list = []
        for task in tasks:
            section_status_mapping = {
                '155860104': 'В очереди',
                '155859386': 'В работе',
                '138005323': 'Готово'
            }

            section_id = task.section_id
            if section_id in section_status_mapping:
                task_status = section_status_mapping[section_id]
            else:
                task_status = 'Статус неизвестен'

            task_list.append({"content": task.content, "status": task_status})

        return jsonify({"tasks": task_list})
    except Exception as error:
        return jsonify({"error": str(error)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)