require("dotenv").config();
const { Pool } = require("pg");
const fs = require('fs');
const path = require('path');

const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: 'postgres', // Подключаемся к системной базе данных
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

async function initDatabase() {
    try {
        console.log('Инициализация базы данных...');
        
        // Создаем базу данных, если она не существует
        const client = await pool.connect();
        console.log('✓ Подключение к PostgreSQL успешно установлено');

        // Проверяем существование базы данных
        const dbExists = await client.query(
            "SELECT 1 FROM pg_database WHERE datname = $1",
            [process.env.DB_NAME]
        );

        if (dbExists.rows.length === 0) {
            console.log(`Создание базы данных ${process.env.DB_NAME}...`);
            await client.query(`CREATE DATABASE ${process.env.DB_NAME}`);
            console.log('✓ База данных создана');
        } else {
            console.log(`База данных ${process.env.DB_NAME} уже существует. Пересоздание...`);
             
            // Завершаем все подключения к базе данных перед удалением
            try {
                await client.query(`
                    SELECT pg_terminate_backend(pg_stat_activity.pid)
                    FROM pg_stat_activity
                    WHERE pg_stat_activity.datname = $1
                    AND pid <> pg_backend_pid();
                `, [process.env.DB_NAME]);
                 
                console.log('✓ Все соединения с базой данных завершены');
                 
                // Удаляем базу данных
                await client.query(`DROP DATABASE ${process.env.DB_NAME}`);
                console.log('✓ Старая база данных удалена');
                 
                // Создаем новую базу данных
                await client.query(`CREATE DATABASE ${process.env.DB_NAME}`);
                console.log('✓ Новая база данных создана');
            } catch (error) {
                console.error('Ошибка при пересоздании базы данных:', error.message);
                console.log('Продолжаем работу с существующей базой данных...');
            }
        }

        client.release();

        // Создаем новое подключение к созданной базе данных
        const dbPool = new Pool({
            user: process.env.DB_USER,
            host: process.env.DB_HOST,
            database: process.env.DB_NAME,
            password: process.env.DB_PASSWORD,
            port: process.env.DB_PORT,
        });

        const dbClient = await dbPool.connect();
        console.log('✓ Подключение к новой базе данных установлено');

        // Вместо ручного создания таблиц, используем файл database.sql
        console.log('\nСоздание схемы базы данных из файла database.sql...');
        const sqlFilePath = path.join(__dirname, 'src', 'db', 'database.sql');
        
        try {
            const sqlContent = fs.readFileSync(sqlFilePath, 'utf8');
            await dbClient.query(sqlContent);
            console.log('✓ Схема базы данных создана успешно');
        } catch (sqlError) {
            console.error('Ошибка при выполнении SQL из файла:', sqlError);
            
            // Если не удалось выполнить файл целиком, создадим базовые таблицы
            console.log('\nСоздание базовых таблиц...');
            
            // Таблица пользователей
            await dbClient.query(`
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    role VARCHAR(50) DEFAULT 'user',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            `);
            console.log('✓ Таблица users создана');
            
            // Добавляем администратора
            await dbClient.query(`
                INSERT INTO users (name, email, password, role) 
                VALUES ('Admin', 'admin@example.com', '$2b$10$JcZrK6rliQ4ZzN2WYYPsXuD85JVDuGhepnndpdaHQE3/zLKX/5jEK', 'admin')
                ON CONFLICT (email) DO NOTHING;
            `);
            console.log('✓ Администратор добавлен');
        }

        dbClient.release();
        console.log('\n✓ Инициализация базы данных завершена успешно');
        
        // Устанавливаем флаг переинициализации для server.js
        console.log('Установка флага переинициализации базы данных...');
        
        try {
            const appClient = await dbPool.connect();
            await appClient.query('SET app.reinitialize = true');
            console.log('✓ Флаг переинициализации базы данных установлен');
            appClient.release();
        } catch (flagError) {
            console.warn('Не удалось установить флаг переинициализации:', flagError.message);
        }
        
        await dbPool.end();
        
        process.exit(0);
    } catch (error) {
        console.error('Ошибка при инициализации базы данных:', error);
        process.exit(1);
    }
}

initDatabase(); 