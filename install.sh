#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# Create MySQL databases and user
MYSQL_ROOT_PASSWORD="6QCzW@w8"
DB_USER="admin"
DB_PASSWORD="hf3h8hews"
DB_HOST="localhost"
DB1="tasks"
DB2="tasks_test"

# Create tables in tasks database
sudo mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "USE tasks;
INSERT INTO role (name) VALUES ('root'), ('user'), ('admin');
INSERT INTO permission (name) VALUES ('admin_access'), ('user_access'), ('edit_content'), ('view_content');
INSERT INTO roles_permissions (role_id, permission_id)
SELECT role.id, permission.id
FROM role, permission
WHERE role.name = 'admin';
INSERT INTO `roles_permissions` (`role_id`, `permission_id`) VALUES
(2, 2),
(2, 3),
(2, 4),
(1, 1),
(1, 2),
(1, 3),
(1, 4);"

sudo mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "USE tasks_test;
INSERT INTO role (name) VALUES ('root'), ('user'), ('admin');
INSERT INTO permission (name) VALUES ('admin_access'), ('user_access'), ('edit_content'), ('view_content');
INSERT INTO roles_permissions (role_id, permission_id)
SELECT role.id, permission.id
FROM role, permission
WHERE role.name = 'admin';
INSERT INTO `roles_permissions` (`role_id`, `permission_id`) VALUES
(2, 2),
(2, 3),
(2, 4),
(1, 1),
(1, 2),
(1, 3),
(1, 4);"

sudo mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "USE tasks;
INSERT INTO `user` (`id`, `username`, `password`, `avatar_data`, `image_file`, `usernick`, `role_id`) VALUES
(1, 'root', '$2b$12$KTR2cZWx43BX6ITouCmLuuX7XO75nxtAGxVckKHZmZd5vWEeTMUnG', NULL, 0x61726368706570652e676966, 'root', 1);"

sudo mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "USE tasks_test;
INSERT INTO `user` (`id`, `username`, `password`, `avatar_data`, `image_file`, `usernick`, `role_id`) VALUES
(1, 'root', '$2b$12$KTR2cZWx43BX6ITouCmLuuX7XO75nxtAGxVckKHZmZd5vWEeTMUnG', NULL, 0x61726368706570652e676966, 'root', 1);"

sudo mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "GRANT ALL PRIVILEGES ON tasks.* TO 'admin'@'localhost';"
sudo mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "GRANT ALL PRIVILEGES ON tasks_test.* TO 'admin'@'localhost';"
sudo mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "FLUSH PRIVILEGES;"

echo "Setup complete. Databases '$DB1' and '$DB2' created with user '$DB_USER'."
