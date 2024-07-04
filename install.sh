#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# Update package lists for upgrades
sudo apt-get update

# Install MySQL server
sudo apt-get install -y mysql-server

# Secure MySQL installation (interactive script)
sudo mysql_secure_installation

# Install Python3 and pip3
sudo apt-get install -y python3 python3-pip

# Install required Python packages
pip install flask flask_sqlalchemy flask_admin flask_login telebot pytz sqlalchemy flask_principal apscheduler mysqlclient

# Create MySQL databases and user
MYSQL_ROOT_PASSWORD="6QCzW@w8"
DB_USER="admin"
DB_PASSWORD="hf3h8hews"
DB_HOST="localhost"
DB1="tasks"
DB2="tasks_test"

# Login to MySQL and create databases and user
sudo mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "CREATE DATABASE $DB1;"
sudo mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "CREATE DATABASE $DB2;"
sudo mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "USE tasks;
CREATE TABLE roles_permissions (
    role_id INT NOT NULL,
    permission_id INT NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES role(id),
    FOREIGN KEY (permission_id) REFERENCES permission(id)
);

CREATE TABLE role (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL
);

CREATE TABLE permission (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL
);

CREATE TABLE user (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usernick VARCHAR(50) UNIQUE NOT NULL,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role_id INT NOT NULL,
    avatar_data LONGBLOB,
    image_file VARCHAR(20) NOT NULL DEFAULT 'logo.jpg',
    FOREIGN KEY (role_id) REFERENCES role(id)
);

CREATE TABLE task (
    id INT AUTO_INCREMENT PRIMARY KEY,
    task_id VARCHAR(80) UNIQUE NOT NULL,
    content VARCHAR(200) NOT NULL,
    priority INT NOT NULL,
    description VARCHAR(500) NOT NULL,
    project_id BIGINT,
    status INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    start_time DATETIME,
    end_time DATETIME,
    assigned_to INT,
    duration INT,
    FOREIGN KEY (assigned_to) REFERENCES user(id)
);

CREATE TABLE comment (
    id INT AUTO_INCREMENT PRIMARY KEY,
    content VARCHAR(500) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    task_id INT NOT NULL,
    user_id INT NOT NULL,
    FOREIGN KEY (task_id) REFERENCES task(id),
    FOREIGN KEY (user_id) REFERENCES user(id)
);"

sudo mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "USE tasks_test;
CREATE TABLE roles_permissions (
    role_id INT NOT NULL,
    permission_id INT NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES role(id),
    FOREIGN KEY (permission_id) REFERENCES permission(id)
);

CREATE TABLE role (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL
);

CREATE TABLE permission (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL
);

CREATE TABLE user (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usernick VARCHAR(50) UNIQUE NOT NULL,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role_id INT NOT NULL,
    avatar_data LONGBLOB,
    image_file VARCHAR(20) NOT NULL DEFAULT 'logo.jpg',
    FOREIGN KEY (role_id) REFERENCES role(id)
);

CREATE TABLE task (
    id INT AUTO_INCREMENT PRIMARY KEY,
    task_id VARCHAR(80) UNIQUE NOT NULL,
    content VARCHAR(200) NOT NULL,
    priority INT NOT NULL,
    description VARCHAR(500) NOT NULL,
    project_id BIGINT,
    status INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    start_time DATETIME,
    end_time DATETIME,
    assigned_to INT,
    duration INT,
    FOREIGN KEY (assigned_to) REFERENCES user(id)
);

CREATE TABLE comment (
    id INT AUTO_INCREMENT PRIMARY KEY,
    content VARCHAR(500) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    task_id INT NOT NULL,
    user_id INT NOT NULL,
    FOREIGN KEY (task_id) REFERENCES task(id),
    FOREIGN KEY (user_id) REFERENCES user(id)
);"
sudo mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "GRANT ALL PRIVILEGES ON $DB1.* TO '$DB_USER'@'$DB_HOST';"
sudo mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "GRANT ALL PRIVILEGES ON $DB2.* TO '$DB_USER'@'$DB_HOST';"
sudo mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "FLUSH PRIVILEGES;"

echo "Setup complete. Databases '$DB1' and '$DB2' created with user '$DB_USER'."