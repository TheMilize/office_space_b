# 🏢 Office Space Backend

![Welcome](./src/assets/RM.png)

**Office Space Backend** — серверная часть системы для управления офисным пространством, бронирования рабочих мест, отпусков и психологической поддержки сотрудников.

---

## 🚀 Быстрый старт (локально)

1. **Клонируйте репозиторий:**
   ```bash
   git clone [url-репозитория]
   cd office_space_b
   ```
2. **Установите зависимости:**
   ```bash
   npm install
   ```
3. **Создайте файл `.env` в корне и заполните переменные:**
   ```env
   DB_USER=your_db_user
   DB_PASSWORD=your_db_password
   DB_HOST=localhost
   DB_PORT=5432
   DB_NAME=office_space
   JWT_SECRET=your_jwt_secret
   PORT=3000
   ```
4. **Создайте базу данных PostgreSQL и выполните скрипт:**
   ```bash
   psql -U your_db_user -d office_space -f src/db/database.sql
   ```
5. **Запустите сервер:**
   - В режиме разработки:
     ```bash
     npm run dev
     ```
   - В продакшн-режиме:
     ```bash
     npm start
     ```

---

## 🌐 Запуск в продакшн

1. Убедитесь, что переменные окружения корректно настроены (см. `.env.example`).
2. Используйте процесс-менеджер (например, pm2) для запуска:
   ```bash
   pm2 start npm --name office_space_b -- start
   ```
3. Настройте reverse proxy (например, nginx) для HTTPS и маршрутизации.
4. Проверьте логи и доступность API.

---

## 🔑 Основные возможности

- 🪑 Бронирование рабочих мест
- 📅 Управление отпусками и выходными
- 👨‍💼 Админ-панель и логирование
- 🔐 JWT-аутентификация и роли
- 🤖 Интеграция с AI-чатом (OpenAI/DeepSeek и др.)
- 🧹 Автоматическая очистка устаревших данных
- 📊 API для фронтенда (см. [frontend](https://github.com/TheMilize/office_space_f))

---

## 📦 Технологии

- Node.js, Express.js
- PostgreSQL
- JWT, bcrypt
- dotenv, cors

---

## 📁 Структура

- `src/` — исходный код
- `src/db/` — SQL-скрипты и структура БД
- `src/routes/` — API-роуты
- `src/models/` — модели данных
- `assets/` — картинки для документации

---

## 📞 Обратная связь

Если у вас есть вопросы или предложения — создайте issue или pull request!

---

## 🔗 Смотрите также
- [Frontend (Vue.js)](https://github.com/TheMilize/office_space_f)

![Node.js](https://img.shields.io/badge/Node.js-43853D?style=for-the-badge&logo=node.js&logoColor=white)
![Express.js](https://img.shields.io/badge/Express.js-404D59?style=for-the-badge)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-316192?style=for-the-badge&logo=postgresql&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-000000?style=for-the-badge&logo=JSON%20web%20tokens&logoColor=white)

📋 Описание

Этот сервер предоставляет API для управления:
- 🪑 Бронированием рабочих мест
- 📅 Управлением отпусками
- 🏖️ Управлением выходными днями
- 👨‍💼 Административными функциями
- 🔐 Аутентификацией пользователей

🛠️ Технологии

- **Node.js** - среда выполнения JavaScript
- **Express.js** - веб-фреймворк для Node.js
- **PostgreSQL** - система управления реляционными базами данных
- **JWT** - для аутентификации и авторизации
- **bcrypt** - для хеширования паролей
- **cors** - для настройки Cross-Origin Resource Sharing
- **dotenv** - для управления переменными окружения

⚙️ Установка

1. Клонируйте репозиторий:

git clone [url-репозитория]
cd office_space_b

2. Установите зависимости:

npm install

3. Создайте файл `.env` в корневой директории и добавьте необходимые переменные окружения:

DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_HOST=localhost
DB_PORT=5432
DB_NAME=office_space
JWT_SECRET=your_jwt_secret
PORT=3000

4. Создайте базу данных PostgreSQL и выполните скрипт инициализации:

psql -U your_db_user -d office_space -f database.sql

🚀 Запуск

Для запуска в режиме разработки:

npm run dev

Для запуска в продакшн режиме:

npm start

🔌 API Endpoints

🔐 Аутентификация
- `POST /api/register` - Регистрация нового пользователя
- `POST /api/login` - Вход в систему

📅 Бронирование
- `GET /api/bookings` - Получение всех бронирований
- `POST /api/bookings` - Создание нового бронирования
- `DELETE /api/bookings/:id` - Удаление бронирования

🏖️ Отпуска
- `GET /api/vacation-periods/:userId` - Получение отпусков пользователя
- `POST /api/vacation-periods` - Создание нового отпуска
- `PUT /api/vacation-periods/:id` - Обновление статуса отпуска

🏖️ Выходные
- `GET /api/weekends` - Получение выходных дней
- `POST /api/weekends` - Создание выходного дня
- `DELETE /api/weekends/:id` - Удаление выходного дня

👨‍💼 Административные функции
- `GET /api/admin/users` - Получение списка пользователей
- `GET /api/admin/timeoff` - Получение данных об отпусках и выходных
- `POST /api/admin/logs` - Логирование действий администратора

📊 Структура базы данных

Основные таблицы:
- `users` - информация о пользователях (id, name, email, password, role)
- `bookings` - бронирования рабочих мест (id, user_id, booking_date, week_start)
- `vacation_periods` - периоды отпусков (id, user_id, start_date, end_date, status)
- `weekend_selections` - выходные дни (id, user_id, selected_day, week_start)
- `admin_logs` - логи действий администратора (id, admin_id, action, details, timestamp)

🔒 Безопасность

- Все пароли хешируются с использованием bcrypt
- JWT используется для аутентификации
- Реализована проверка ролей пользователей
- Защита от SQL-инъекций через параметризованные запросы
- CORS настройки для безопасного взаимодействия с фронтендом
- Валидация входных данных

📝 Логирование

Система ведет логирование:
- Действий администраторов
- Ошибок сервера
- Важных операций с данными
- Попыток входа в систему
- Изменений статусов отпусков

⚡ Автоматизация

Реализованы автоматические задачи:
- Очистка старых бронирований
- Очистка старых ответов на опросы
- Еженедельная очистка данных
- Автоматическое обновление статусов отпусков

📦 Зависимости

Основные пакеты:
- express: ^4.18.2
- pg: ^8.11.3
- jsonwebtoken: ^9.0.2
- bcrypt: ^5.1.1
- cors: ^2.8.5
- dotenv: ^16.3.1
