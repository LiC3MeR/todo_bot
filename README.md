# Приложение Доска Задач

Это веб-приложение на основе Flask, которое позволяет пользователям создавать, управлять и организовывать задачи с помощью интерфейса drag-and-drop. Задачи сохраняются локально в базе данных SQLite. Приложение включает тёмную тему и полностью локализовано на русском языке.

## Возможности

- Создание новых задач с приоритетом, описанием, заказчиком и отделом.
- Перетаскивание задач между разными колонками (статусами): "В очереди", "В работе" и "Готово".
- Задачи сохраняются локально в базе данных SQLite.
- Автоматические уведомления в Telegram о новых задачах.
- Интерфейс с тёмной темой для лучшей читаемости.

## Начало работы

### Предварительные требования

- Python 3.7 или выше
- Flask
- SQLite
- Mysql

### Установка

1. Клонируйте репозиторий:

    ```bash
    git clone https://github.com/LiC3MeR/todo_bot.git
    cd todo_bot
    ```

2. Создайте и активируйте виртуальное окружение:

    ```bash
    python3 -m venv venv
    source venv/bin/activate  # На Windows используйте `venv\Scripts\activate`
    ```

3. Установите необходимые пакеты:

    ```bash
    pip install -r requirements.txt
    ```

4. Настройте переменные окружения:

    Создайте файл `.env` в корневом каталоге проекта и добавьте следующие строки:

    ```env
   FLASK_PORT=80
   TELEGRAM_BOT_TOKEN=token
   TELEGRAM_CHAT_ID=chatid
   DEV_DATABASE_URI=linkdatabase
   PROD_DATABASE_URI=linkdatabase
   NLU_DATABASE_URI=linkdatabase
   CAL_DATABASE_URI=linkdatabase
    ```

5. Запустите приложение в нужном режиме:

    ```bash
    python3 main.py dev/prod
    ```

6. Откройте браузер и перейдите по адресу
`http://127.0.0.1/`


7. Создание базы cli mysql
   ```sql
   CREATE TABLE `comment` (
     `id` int(11) NOT NULL,
     `content` varchar(500) NOT NULL,
     `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
     `task_id` int(11) NOT NULL,
     `user_id` int(11) NOT NULL
   ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
   
   CREATE TABLE `permission` (
     `id` int(11) NOT NULL,
     `name` varchar(50) NOT NULL
   ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
   
   INSERT INTO `permission` (`id`, `name`) VALUES
   (9, 'root'),
   (2, 'Админ страница'),
   (3, 'Главная'),
   (4, 'Доска задач'),
   (1, 'Меню'),
   (10, 'Отображать название организации перед именем'),
   (6, 'Пользователи'),
   (7, 'Профиль'),
   (5, 'Роли'),
   (8, 'Удаление задач');
   
   CREATE TABLE `role` (
     `id` int(11) NOT NULL,
     `name` varchar(50) NOT NULL
   ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
   
   INSERT INTO `role` (`id`, `name`) VALUES
   (2, 'admin'),
   (1, 'root'),
   (3, 'user');
   
   CREATE TABLE `roles_permissions` (
     `role_id` int(11) NOT NULL,
     `permission_id` int(11) NOT NULL
   ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
   
   INSERT INTO `roles_permissions` (`role_id`, `permission_id`) VALUES
   (1, 1),
   (1, 2),
   (1, 3),
   (1, 4),
   (1, 5),
   (1, 6),
   (1, 7),
   (1, 8),
   (1, 9);
   
   CREATE TABLE `task` (
     `id` int(11) NOT NULL,
     `task_id` varchar(80) NOT NULL,
     `content` varchar(200) NOT NULL,
     `priority` int(11) NOT NULL,
     `description` varchar(500) NOT NULL,
     `project_id` bigint(20) DEFAULT NULL,
     `status` int(11) NOT NULL,
     `created_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
     `assigned_to` int(11) DEFAULT NULL,
     `start_time` datetime DEFAULT NULL,
     `end_time` datetime DEFAULT NULL,
     `duration` int(11) DEFAULT NULL
   ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
   
   CREATE TABLE `tasks` (
     `id` int(11) NOT NULL,
     `task_id` varchar(80) NOT NULL,
     `content` varchar(200) NOT NULL,
     `description` varchar(500) NOT NULL,
     `priority` int(11) NOT NULL,
     `status` int(11) NOT NULL,
     `start_time` datetime DEFAULT NULL,
     `end_time` datetime DEFAULT NULL,
     `duration` int(11) DEFAULT NULL
   ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
   
   CREATE TABLE `user` (
     `id` int(11) NOT NULL,
     `username` varchar(50) NOT NULL,
     `password` varchar(255) NOT NULL,
     `role` varchar(50) NOT NULL DEFAULT 'user',
     `avatar_data` blob DEFAULT NULL,
     `image_file` varchar(225) DEFAULT NULL,
     `usernick` varchar(50) DEFAULT NULL,
     `role_id` int(11) DEFAULT NULL
   ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
   
   INSERT INTO `user` (`id`, `username`, `password`, `role`, `avatar_data`, `image_file`, `usernick`, `role_id`) VALUES
   (1, 'root', '$2b$12$KTR2cZWx43BX6ITouCmLuuX7XO75nxtAGxVckKHZmZd5vWEeTMUnG', 'admin', NULL, 'archpepe.gif', 'root ТЕСТОВАЯ СРЕДА', 1);
   
   ALTER TABLE `comment`
     ADD PRIMARY KEY (`id`),
     ADD KEY `task_id` (`task_id`),
     ADD KEY `user_id` (`user_id`);
   
   ALTER TABLE `permission`
     ADD PRIMARY KEY (`id`),
     ADD UNIQUE KEY `name` (`name`);
   
   ALTER TABLE `role`
     ADD PRIMARY KEY (`id`),
     ADD UNIQUE KEY `name` (`name`);
   
   ALTER TABLE `roles_permissions`
     ADD PRIMARY KEY (`role_id`,`permission_id`),
     ADD KEY `permission_id` (`permission_id`);
   
   ALTER TABLE `task`
     ADD PRIMARY KEY (`id`),
     ADD UNIQUE KEY `task_id` (`task_id`),
     ADD KEY `fk_assigned_to_user` (`assigned_to`);
   
   ALTER TABLE `tasks`
     ADD PRIMARY KEY (`id`),
     ADD UNIQUE KEY `task_id` (`task_id`);
   
   ALTER TABLE `user`
     ADD PRIMARY KEY (`id`),
     ADD UNIQUE KEY `username` (`username`);
   
   ALTER TABLE `comment`
     MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;
   
   ALTER TABLE `permission`
     MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=9;
   
   ALTER TABLE `role`
     MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=19;
   
   ALTER TABLE `task`
     MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=16;
   
   ALTER TABLE `tasks`
     MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;
   
   ALTER TABLE `user`
     MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=24;
   
   ALTER TABLE `comment`
     ADD CONSTRAINT `comment_ibfk_1` FOREIGN KEY (`task_id`) REFERENCES `task` (`id`),
     ADD CONSTRAINT `comment_ibfk_2` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`);
   
   ALTER TABLE `roles_permissions`
     ADD CONSTRAINT `roles_permissions_ibfk_1` FOREIGN KEY (`role_id`) REFERENCES `Role` (`id`),
     ADD CONSTRAINT `roles_permissions_ibfk_2` FOREIGN KEY (`permission_id`) REFERENCES `Permission` (`id`);
   
   ALTER TABLE `task`
     ADD CONSTRAINT `fk_assigned_to_user` FOREIGN KEY (`assigned_to`) REFERENCES `user` (`id`);
   COMMIT;
   ```
### Использование

- **Создание задач:** Заполните форму в верхней части доски задач, чтобы создать новую задачу. Задача появится в колонке "В очереди".
- **Обновление статуса задачи:** Перетаскивайте задачи между колонками для обновления их статуса.
- **Уведомления:** Каждый раз, когда создается новая задача, уведомление будет отправлено в настроенный чат Telegram.