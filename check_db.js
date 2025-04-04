require("dotenv").config();
const { Pool } = require("pg");

const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

async function checkDatabase() {
    try {
        console.log('Проверка подключения к базе данных...');
        
        // Проверяем подключение
        const client = await pool.connect();
        console.log('✓ Подключение к базе данных успешно установлено');

        // Проверяем наличие таблиц
        const tables = [
            'users',
            'surveys',
            'survey_questions',
            'survey_responses',
            'support_requests',
            'support_messages'
        ];

        console.log('\nПроверка наличия таблиц:');
        for (const table of tables) {
            const result = await client.query(
                "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = $1)",
                [table]
            );
            console.log(`${result.rows[0].exists ? '✓' : '✗'} Таблица ${table}`);
        }

        // Проверяем количество записей в каждой таблице
        console.log('\nКоличество записей в таблицах:');
        for (const table of tables) {
            const result = await client.query(`SELECT COUNT(*) FROM ${table}`);
            console.log(`${table}: ${result.rows[0].count} записей`);
        }

        // Проверяем структуру таблиц
        console.log('\nПроверка структуры таблиц:');
        for (const table of tables) {
            const result = await client.query(
                "SELECT column_name, data_type FROM information_schema.columns WHERE table_name = $1",
                [table]
            );
            console.log(`\nСтруктура таблицы ${table}:`);
            result.rows.forEach(column => {
                console.log(`  - ${column.column_name}: ${column.data_type}`);
            });
        }

        client.release();
        console.log('\n✓ Проверка базы данных завершена успешно');
        process.exit(0);
    } catch (error) {
        console.error('Ошибка при проверке базы данных:', error);
        process.exit(1);
    }
}

checkDatabase(); 