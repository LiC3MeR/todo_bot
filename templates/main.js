    function updateTaskList() {
        fetch('/tasks')
            .then(response => response.json())
            .then(data => {
                taskList.innerHTML = ''; // Очистить текущий список задач
                data.tasks.forEach(task => {
                    const li = document.createElement('li');
                    li.textContent = `${task.content} - ${task.status}`;
                    taskList.appendChild(li);
                });
            })
            .catch(error => console.error('Error updating task list:', error));
    }

    updateTaskList(); // Обновить список задач при загрузке страницы

    setInterval(updateTaskList, 30000); // Обновлять список задач каждые 30 секунд