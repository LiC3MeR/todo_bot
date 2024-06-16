from flask import Flask, render_template, request, jsonify, redirect, flash, url_for, redirect, abort
import os
import subprocess
app = Flask(__name__)

@app.route('/')
def restart_calls():
    # Выполняем команду supervisorctl restart calls с помощью subprocess
    try:
        subprocess.run(['supervisorctl', 'restart', 'calls'], check=True)
        return 'Команда supervisorctl restart calls выполнена успешно'
    except subprocess.CalledProcessError:
        return 'Ошибка выполнения команды supervisorctl restart calls'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=1234)