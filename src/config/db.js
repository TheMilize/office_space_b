const { Sequelize } = require("sequelize");
require("dotenv").config();

console.log('Database connection settings:', {
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    database: process.env.DB_NAME,
    user: process.env.DB_USER
});

const sequelize = new Sequelize(process.env.DB_NAME, process.env.DB_USER, process.env.DB_PASSWORD, {
    host: process.env.DB_HOST,
    port: process.env.DB_PORT || 5432,
    dialect: "postgres",
    logging: console.log,
    dialectOptions: {
        ssl: {
            require: true,
            rejectUnauthorized: false
        }
    },
    pool: {
        max: 5,
        min: 0,
        acquire: 30000,
        idle: 10000
    }
});

// Функция для проверки подключения с повторными попытками
const testConnection = async (retries = 5, delay = 5000) => {
    for (let i = 0; i < retries; i++) {
        try {
            console.log(`Attempting to connect to database (attempt ${i + 1}/${retries})...`);
            console.log(`Connecting to: ${process.env.DB_HOST}:${process.env.DB_PORT}`);
            await sequelize.authenticate();
            console.log("✅ Connected to PostgreSQL successfully");
            return true;
        } catch (err) {
            console.error(`❌ Database connection failed (attempt ${i + 1}/${retries}):`, err.message);
            if (i < retries - 1) {
                console.log(`Waiting ${delay/1000} seconds before next attempt...`);
                await new Promise(resolve => setTimeout(resolve, delay));
            }
        }
    }
    return false;
};

// Запускаем проверку подключения
testConnection();

module.exports = sequelize;
