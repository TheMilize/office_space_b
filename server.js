require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fs = require('fs');
const path = require('path');

const app = express();
const port = process.env.PORT || 5001;

// Подключение к PostgreSQL
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

// Функция для получения начала текущей недели (понедельник)
function getCurrentWeekStart() {
  const now = new Date();
  const currentDay = now.getDay() || 7; // Если 0 (воскресенье), то 7
  const daysToMonday = currentDay - 1; // Понедельник - 1-й день
  const monday = new Date(now);
  monday.setDate(now.getDate() - daysToMonday);
  monday.setHours(0, 0, 0, 0);
  return monday;
}

// Функция для очистки устаревших бронирований
async function cleanupOldBookings() {
  try {
    console.log('Запуск очистки устаревших бронирований...');
    const currentWeekStart = getCurrentWeekStart();
    
    // Удаляем бронирования, которые старше текущей недели
    const result = await pool.query(
      'DELETE FROM bookings WHERE week_start < $1 RETURNING id',
      [currentWeekStart]
    );
    
    console.log(`Удалено ${result.rowCount} старых бронирований`);
  } catch (error) {
    console.error('Ошибка при очистке старых бронирований:', error);
  }
}

// Функция для очистки просроченных выходных дней
async function cleanupOldWeekends() {
  try {
    console.log('Запуск очистки просроченных выходных дней...');
    const currentWeekStart = getCurrentWeekStart();
    
    // Удаляем выходные дни, которые относятся к прошедшим неделям
    const result = await pool.query(
      'DELETE FROM weekend_selections WHERE week_start < $1 RETURNING id',
      [currentWeekStart]
    );
    
    console.log(`Удалено ${result.rowCount} просроченных выходных дней`);
  } catch (error) {
    console.error('Ошибка при очистке просроченных выходных дней:', error);
  }
}

// Функция для очистки ответов пользователей на еженедельные опросы
async function cleanupSurveyResponses() {
  try {
    console.log('Запуск очистки ответов на еженедельные опросы...');
    const currentWeekStart = getCurrentWeekStart();
    
    // Находим все ответы на еженедельные опросы, которые были созданы до начала текущей недели
    const result = await pool.query(`
      DELETE FROM survey_responses 
      WHERE id IN (
        SELECT sr.id 
        FROM survey_responses sr
        JOIN surveys s ON sr.survey_id = s.id
        WHERE s.type = 'weekly' AND sr.created_at < $1
      ) RETURNING id`, [currentWeekStart]);
    
    console.log(`Удалено ${result.rowCount} ответов на еженедельные опросы`);
  } catch (error) {
    console.error('Ошибка при очистке ответов на еженедельные опросы:', error);
  }
}

// Функция для выполнения всей еженедельной очистки
async function weeklyCleanup() {
  console.log('Выполнение еженедельной очистки данных...');
  await cleanupOldBookings();
  await cleanupOldWeekends();
  await cleanupSurveyResponses();
  console.log('Еженедельная очистка данных завершена.');
}

// Запускать очистку при старте сервера
weeklyCleanup();

// Установка интервала для еженедельной очистки (каждый понедельник в 00:00)
function scheduleWeeklyCleanup() {
  const now = new Date();
  const currentDay = now.getDay(); // 0 - воскресенье, 1 - понедельник, ...
  const currentHour = now.getHours();
  const currentMinute = now.getMinutes();
  
  // Рассчитываем время до следующего понедельника 00:00
  let daysUntilMonday = (1 + 7 - currentDay) % 7; // 1 - понедельник
  if (daysUntilMonday === 0 && (currentHour > 0 || currentMinute > 0)) {
    daysUntilMonday = 7; // Если сегодня понедельник после 00:00, то следующий понедельник
  }
  
  // Устанавливаем время для следующего понедельника 00:00
  const nextMondayMidnight = new Date();
  nextMondayMidnight.setDate(now.getDate() + daysUntilMonday);
  nextMondayMidnight.setHours(0, 0, 0, 0);
  
  // Вычисляем время до следующего запуска
  const timeUntilNextCleanup = nextMondayMidnight - now;
  
  console.log(`Следующая еженедельная очистка запланирована на: ${nextMondayMidnight.toISOString()}`);
  console.log(`Это через ${Math.floor(timeUntilNextCleanup / 1000 / 60 / 60)} часов`);
  
  // Устанавливаем таймер для первой очистки
  setTimeout(() => {
    console.log('Запуск плановой еженедельной очистки...');
    weeklyCleanup();
    
    // Затем устанавливаем интервал для еженедельных очисток
    const weeklyInterval = 7 * 24 * 60 * 60 * 1000; // неделя в миллисекундах
    setInterval(weeklyCleanup, weeklyInterval);
  }, timeUntilNextCleanup);
}

// Запускаем планировщик очистки
scheduleWeeklyCleanup();

// Инициализация базы данных
async function initializeDatabase() {
    try {
        console.log('Проверка соединения с базой данных...');
        const dbInfo = await pool.query('SELECT current_database() as db_name, current_schema as schema_name');
        console.log(`Подключено к базе данных: ${dbInfo.rows[0].db_name}, схема: ${dbInfo.rows[0].schema_name}`);
        
        // Проверяем структуру таблицы shifts
        try {
            console.log('Проверка структуры таблицы shifts...');
            const shiftColumns = await pool.query(`
                SELECT column_name, data_type 
                FROM information_schema.columns 
                WHERE table_name = 'shifts'
                ORDER BY ordinal_position
            `);
            console.log('Столбцы таблицы shifts:', JSON.stringify(shiftColumns.rows));
        } catch (shiftError) {
            console.warn('Не удалось получить информацию о структуре таблицы shifts:', shiftError);
        }
        
        // Проверяем, нужно ли полностью переинициализировать базу данных
        const shouldReinit = await pool.query(`SELECT current_setting('app.reinitialize', true)::boolean AS reinit`);
        
        if (shouldReinit.rows[0]?.reinit === true) {
            console.log('Полная переинициализация базы данных...');
            
            // Выполняем database.sql - единый файл со схемой и начальными данными
            const databasePath = path.join(__dirname, 'src', 'db', 'database.sql');
            const databaseSql = fs.readFileSync(databasePath, 'utf8');
            
            try {
                await pool.query(databaseSql);
                console.log('database.sql выполнен успешно');
            } catch (execError) {
                handleSqlError(execError);
            }

            // Сбрасываем флаг переинициализации
            await pool.query('SET app.reinitialize = false');
        } else {
            console.log('База данных уже инициализирована, обновляем схему...');
            try {
                // Выполняем database.sql для обновления структуры
                const databasePath = path.join(__dirname, 'src', 'db', 'database.sql');
                const databaseSql = fs.readFileSync(databasePath, 'utf8');
                
                try {
                    await pool.query(databaseSql);
                    console.log('database.sql выполнен успешно');
                } catch (execError) {
                    handleSqlError(execError);
                }
            } catch (execError) {
                // Проверяем, является ли ошибка конфликтом email
                if (execError.message && execError.message.includes('Email уже существует')) {
                    console.warn('Предупреждение: Пропущена вставка существующего email');
                    
                    // Принудительно удаляем конфликтную функцию
                    await pool.query(`DROP FUNCTION IF EXISTS check_unique_email() CASCADE;`);
                    
                    // Повторно выполняем только структурные запросы
                    console.log('Продолжение инициализации без конфликтующих вставок...');
                } else {
                    // Если ошибка другая, пробрасываем её
                    throw execError;
                }
            }
        }
    } catch (error) {
        // Обрабатываем ошибку и продолжаем выполнение сервера
        console.error('Ошибка при инициализации базы данных:', error);
        console.log('Продолжаем запуск сервера несмотря на ошибки инициализации...');
    }
}

// Функция для обработки ошибок SQL
function handleSqlError(error) {
    // Проверяем известные ошибки и логируем предупреждения
    if (error.message && error.message.includes('already exists')) {
        if (error.message.includes('trigger')) {
            console.warn('Предупреждение: Триггер уже существует:', error.message);
        } else if (error.message.includes('column')) {
            console.warn('Предупреждение: Колонка уже существует:', error.message);
        } else if (error.message.includes('Email')) {
            console.warn('Предупреждение: Email уже существует:', error.message);
        } else {
            console.warn('Предупреждение: Объект уже существует:', error.message);
        }
        // Продолжаем выполнение
        return;
    }
    
    // Для других ошибок логируем и пробрасываем дальше
    console.error('Ошибка при выполнении SQL:', error);
    throw error;
}

// Инициализируем базу данных при запуске сервера
initializeDatabase();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // Для обработки данных формы (если нужно)

// Добавляем middleware для установки заголовков безопасности
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://api.openai.com; " +
    "style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data: https:; " +
    "font-src 'self' data:; " +
    "connect-src 'self' https://api.openai.com; " +
    "form-action 'self'; " +
    "frame-ancestors 'none'; " +
    "base-uri 'self'; " +
    "object-src 'none'; " +
    "media-src 'self'; " +
    "worker-src 'self' blob:; " +
    "child-src 'self' blob:; " +
    "manifest-src 'self'; " +
    "upgrade-insecure-requests;"
  );
  next();
});

//Регистрация пользователя — обработчик POST-запроса
app.post("/api/register", async (req, res) => {
    const { name, email, password } = req.body;
    
    console.log('Получен запрос на регистрацию:', { name, email });

    if (!name || !email || !password) {
        console.log('Отсутствуют обязательные поля');
        return res.status(400).json({ error: "Все поля обязательны для заполнения!" });
    }

    try {
        console.log('Проверяем существование пользователя');
        const userExist = await pool.query("SELECT * FROM users WHERE LOWER(email) = LOWER($1)", [email]);
        console.log('Результат проверки существования:', userExist.rows);
        
        if (userExist.rows.length > 0) {
            console.log('Пользователь уже существует');
            return res.status(400).json({ error: "Пользователь с таким email уже существует!" });
        }

        console.log('Хешируем пароль');
        const hashedPassword = await bcrypt.hash(password, 10);
        console.log('Пароль захеширован');

        console.log('Создаем нового пользователя');
        const newUser = await pool.query(
            "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *",
            [name, email, hashedPassword]
        );
        console.log('Результат создания пользователя:', newUser.rows[0]);

        // Проверяем, что пользователь действительно создан
        const checkUser = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
        console.log('Проверка после создания:', checkUser.rows[0]);

        console.log('Пользователь успешно создан:', newUser.rows[0]);
        res.json({ message: "Пользователь успешно зарегистрирован!", user: newUser.rows[0] });
    } catch (error) {
        console.error("Ошибка при регистрации:", error);
        res.status(500).json({ error: "Ошибка сервера. Попробуйте позже." });
    }
});

//Логин пользователя — обработчик POST-запроса
app.post("/api/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Пожалуйста, введите email и пароль." });
    }

    try {
        const result = await pool.query("SELECT * FROM users WHERE LOWER(email) = LOWER($1)", [email]);

        if (result.rows.length === 0) {
            return res.status(400).json({ error: "Неверный email или пароль." });
        }

        const user = result.rows[0];

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(400).json({ error: "Неверный email или пароль." });
        }

        const token = jwt.sign(
            { 
                userId: user.id, 
                email: user.email,
                role: user.role 
            },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.json({ 
            token,
            userId: user.id,
            name: user.name,
            email: user.email,
            role: user.role
        });
    } catch (error) {
        console.error("Ошибка при логине:", error);
        res.status(500).json({ error: "Ошибка сервера. Попробуйте позже." });
    }
});

// Мидлвар аутентификации
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: "Токен отсутствует" });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.error("Ошибка верификации токена:", err);
            return res.status(403).json({ error: "Невалидный токен" });
        }
        req.user = user;
        next();
    });
};

// Эндпоинт профиля
app.get("/api/profile", authenticateToken, async (req, res) => {
    try {
        console.log(req.user.userId)
        const { rows } = await pool.query(
            "SELECT id, name, email FROM users WHERE id = $1",
            [req.user.userId]
        );

        if (!rows.length) {
            return res.status(404).json({ error: "Пользователь не найден" });
        }

        res.json({
            id: rows[0].id,
            name: rows[0].name,
            email: rows[0].email
        });
    } catch (error) {
        console.error("Ошибка при получении профиля:", error);
        res.status(500).json({ error: "Внутренняя ошибка сервера" });
    }
});

// Эндпоинт для создания нового опроса
app.post("/api/surveys", authenticateToken, async (req, res) => {
    const { title, description, type, questions } = req.body;
    
    try {
        // Создаем новый опрос
        const surveyResult = await pool.query(
            "INSERT INTO surveys (title, description, type, created_by) VALUES ($1, $2, $3, $4) RETURNING *",
            [title, description, type, req.user.userId]
        );
        
        const surveyId = surveyResult.rows[0].id;
        
        // Добавляем вопросы к опросу
        for (let i = 0; i < questions.length; i++) {
            const question = questions[i];
            await pool.query(
                "INSERT INTO survey_questions (survey_id, question_text, question_type, options, is_required, order_index) VALUES ($1, $2, $3, $4::jsonb, $5, $6)",
                [surveyId, question.text, question.type, question.options, question.isRequired, i]
            );
        }
        
        res.json({ message: "Опрос успешно создан", surveyId });
    } catch (error) {
        console.error("Ошибка при создании опроса:", error);
        res.status(500).json({ error: error.message || "Ошибка при создании опроса" });
    }
});

// Эндпоинт для получения всех опросов
app.get("/api/surveys", authenticateToken, async (req, res) => {
    try {
        const surveysResult = await pool.query(
            "SELECT * FROM surveys WHERE is_active = true ORDER BY created_at DESC"
        );
        
        const surveys = await Promise.all(surveysResult.rows.map(async (survey) => {
            const questionsResult = await pool.query(
                "SELECT * FROM survey_questions WHERE survey_id = $1 ORDER BY order_index",
                [survey.id]
            );
            return {
                ...survey,
                questions: questionsResult.rows
            };
        }));
        
        res.json(surveys);
    } catch (error) {
        console.error("Ошибка при получении опросов:", error);
        res.status(500).json({ error: "Ошибка при получении опросов" });
    }
});

// Эндпоинт для получения конкретного опроса
app.get("/api/surveys/:id", authenticateToken, async (req, res) => {
    try {
        const surveyResult = await pool.query(
            "SELECT * FROM surveys WHERE id = $1 AND is_active = true",
            [req.params.id]
        );
        
        if (surveyResult.rows.length === 0) {
            return res.status(404).json({ error: "Опрос не найден" });
        }
        
        const questionsResult = await pool.query(
            "SELECT * FROM survey_questions WHERE survey_id = $1 ORDER BY order_index",
            [req.params.id]
        );
        
        res.json({
            ...surveyResult.rows[0],
            questions: questionsResult.rows
        });
    } catch (error) {
        console.error("Ошибка при получении опроса:", error);
        res.status(500).json({ error: "Ошибка при получении опроса" });
    }
});

// Сохранение ответов на опрос
app.post("/api/surveys/:surveyId/responses", authenticateToken, async (req, res) => {
    const { surveyId } = req.params;
    const { answers } = req.body;
    
    try {
        // Проверяем существование опроса
        const surveyExists = await pool.query(
            "SELECT id FROM surveys WHERE id = $1",
            [surveyId]
        );
        
        if (surveyExists.rows.length === 0) {
            return res.status(404).json({ error: "Опрос не найден" });
        }
        
        // Проверяем, не отвечал ли пользователь уже на этот опрос
        const existingResponse = await pool.query(
            "SELECT id FROM survey_responses WHERE survey_id = $1 AND user_id = $2",
            [surveyId, req.user.userId]
        );
        
        if (existingResponse.rows.length > 0) {
            return res.status(400).json({ error: "Вы уже ответили на этот опрос" });
        }
        
        // Сохраняем ответы
        for (const answer of answers) {
            await pool.query(
                "INSERT INTO survey_responses (survey_id, question_id, user_id, answer_text) VALUES ($1, $2, $3, $4)",
                [surveyId, answer.questionId, req.user.userId, answer.text]
            );
        }
        
        res.json({ message: "Ответы успешно сохранены" });
    } catch (error) {
        console.error("Ошибка при сохранении ответов:", error);
        res.status(500).json({ error: "Ошибка при сохранении ответов" });
    }
});

// Эндпоинт для получения результатов опроса (только для создателя)
app.get("/api/surveys/:id/results", authenticateToken, async (req, res) => {
    try {
        // Проверяем, является ли пользователь создателем опроса
        const surveyResult = await pool.query(
            "SELECT * FROM surveys WHERE id = $1 AND created_by = $2",
            [req.params.id, req.user.userId]
        );
        
        if (surveyResult.rows.length === 0) {
            return res.status(403).json({ error: "У вас нет доступа к результатам этого опроса" });
        }
        
        // Получаем все ответы на опрос
        const responsesResult = await pool.query(
            `SELECT sr.*, sq.question_text, sq.question_type, u.name as user_name 
             FROM survey_responses sr 
             JOIN survey_questions sq ON sr.question_id = sq.id 
             JOIN users u ON sr.user_id = u.id 
             WHERE sr.survey_id = $1`,
            [req.params.id]
        );
        
        // Группируем ответы по пользователям
        const results = responsesResult.rows.reduce((acc, response) => {
            if (!acc[response.user_id]) {
                acc[response.user_id] = {
                    userId: response.user_id,
                    userName: response.user_name,
                    answers: []
                };
            }
            acc[response.user_id].answers.push({
                questionId: response.question_id,
                questionText: response.question_text,
                questionType: response.question_type,
                answer: response.answer_text
            });
            return acc;
        }, {});
        
        res.json(Object.values(results));
    } catch (error) {
        console.error("Ошибка при получении результатов опроса:", error);
        res.status(500).json({ error: "Ошибка при получении результатов опроса" });
    }
});

// Эндпоинт для создания нового запроса на поддержку
app.post("/api/support/requests", authenticateToken, async (req, res) => {
    const { title, description, priority } = req.body;
    
    try {
        const result = await pool.query(
            "INSERT INTO support_requests (user_id, title, description, priority) VALUES ($1, $2, $3, $4) RETURNING *",
            [req.user.userId, title, description, priority || 'medium']
        );
        
        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error("Ошибка при создании запроса:", error);
        res.status(500).json({ error: "Ошибка сервера при создании запроса" });
    }
});

// Эндпоинт для получения всех запросов пользователя
app.get("/api/support/requests", authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT sr.*, u.name as user_name, 
                    (SELECT name FROM users WHERE id = sa.specialist_id) as specialist_name
             FROM support_requests sr
             JOIN users u ON sr.user_id = u.id
             LEFT JOIN support_assignments sa ON sr.id = sa.request_id
             WHERE sr.user_id = $1
             ORDER BY sr.created_at DESC`,
            [req.user.userId]
        );
        res.json(result.rows);
    } catch (error) {
        console.error("Ошибка при получении запросов:", error);
        res.status(500).json({ error: "Ошибка сервера при получении запросов" });
    }
});

// Эндпоинт для получения конкретного запроса с сообщениями
app.get("/api/support/requests/:id", authenticateToken, async (req, res) => {
    try {
        const requestResult = await pool.query(
            `SELECT sr.*, u.name as user_name, 
                    (SELECT name FROM users WHERE id = sa.specialist_id) as specialist_name
             FROM support_requests sr
             JOIN users u ON sr.user_id = u.id
             LEFT JOIN support_assignments sa ON sr.id = sa.request_id
             WHERE sr.id = $1`,
            [req.params.id]
        );
        
        if (requestResult.rows.length === 0) {
            return res.status(404).json({ error: "Запрос не найден" });
        }
        
        const messagesResult = await pool.query(
            `SELECT sm.*, u.name as sender_name
             FROM support_messages sm
             JOIN users u ON sm.sender_id = u.id
             WHERE sm.request_id = $1
             ORDER BY sm.created_at ASC`,
            [req.params.id]
        );
        
        res.json({
            ...requestResult.rows[0],
            messages: messagesResult.rows
        });
    } catch (error) {
        console.error("Ошибка при получении запроса:", error);
        res.status(500).json({ error: "Ошибка сервера при получении запроса" });
    }
});

// Эндпоинт для отправки сообщения в запросе
app.post("/api/support/requests/:id/messages", authenticateToken, async (req, res) => {
    const { message_text } = req.body;
    
    try {
        const result = await pool.query(
            "INSERT INTO support_messages (request_id, sender_id, message_text) VALUES ($1, $2, $3) RETURNING *",
            [req.params.id, req.user.userId, message_text]
        );
        
        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error("Ошибка при отправке сообщения:", error);
        res.status(500).json({ error: "Ошибка сервера при отправке сообщения" });
    }
});

// Эндпоинт для обновления статуса запроса
app.patch("/api/support/requests/:id/status", authenticateToken, async (req, res) => {
    const { status } = req.body;
    
    try {
        const result = await pool.query(
            "UPDATE support_requests SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING *",
            [status, req.params.id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Запрос не найден" });
        }
        
        res.json(result.rows[0]);
    } catch (error) {
        console.error("Ошибка при обновлении статуса:", error);
        res.status(500).json({ error: "Ошибка сервера при обновлении статуса" });
    }
});

// Эндпоинт для назначения специалиста на запрос
app.post("/api/support/requests/:id/assign", authenticateToken, async (req, res) => {
    const { specialist_id } = req.body;
    
    try {
        const result = await pool.query(
            "INSERT INTO support_assignments (request_id, specialist_id) VALUES ($1, $2) RETURNING *",
            [req.params.id, specialist_id]
        );
        
        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error("Ошибка при назначении специалиста:", error);
        res.status(500).json({ error: "Ошибка сервера при назначении специалиста" });
    }
});

// Сохранение выходных дней
app.post('/api/weekend-days', authenticateToken, async (req, res) => {
  const { userId, weekStart, selectedDays } = req.body;
  console.log('Получен запрос на сохранение выходных дней:', { userId, weekStart, selectedDays });

  try {
    // Проверяем, не превышает ли количество выбранных дней лимит
    if (selectedDays.length > 2) {
      return res.status(400).json({ error: "Можно выбрать максимум 2 дня" });
    }

    // Проверяем, что все дни уникальны
    const uniqueDays = [...new Set(selectedDays)];
    if (uniqueDays.length !== selectedDays.length) {
      return res.status(400).json({ error: "Дни не должны повторяться" });
    }

    // Проверяем, что все дни в допустимом диапазоне
    if (!selectedDays.every(day => day >= 1 && day <= 7)) {
      return res.status(400).json({ error: "Недопустимые значения дней" });
    }

    // Проверяем, есть ли уже записи для этой недели
    const existingRecords = await pool.query(
      "SELECT * FROM weekend_selections WHERE user_id = $1 AND week_start = $2",
      [userId, weekStart]
    );

    if (existingRecords.rows.length > 0) {
      // Если записи существуют, удаляем их
      await pool.query(
        "DELETE FROM weekend_selections WHERE user_id = $1 AND week_start = $2",
        [userId, weekStart]
      );
    }

    // Сохраняем новые записи
    for (const day of selectedDays) {
      await pool.query(
        "INSERT INTO weekend_selections (user_id, week_start, selected_day) VALUES ($1, $2, $3)",
        [userId, weekStart, day]
      );
    }

    console.log('Выходные дни успешно сохранены');
    res.json({ message: "Выходные дни успешно сохранены" });
  } catch (error) {
    console.error("Ошибка при сохранении выходных дней:", error);
    res.status(500).json({ error: "Ошибка сервера при сохранении выходных дней" });
  }
});

// Получение выходных дней пользователя
app.get('/api/weekend-days/:userId', authenticateToken, async (req, res) => {
  const userId = req.params.userId;
  console.log('Получен запрос на получение выходных дней для пользователя:', userId);

  try {
    // Проверяем существование таблицы weekend_selections
    const tableCheck = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_name = 'weekend_selections'
      );
    `);

    console.log('Таблица weekend_selections существует:', tableCheck.rows[0].exists);

    if (!tableCheck.rows[0].exists) {
      console.log('Таблица weekend_selections не существует, создаем ее');
      await pool.query(`
        CREATE TABLE weekend_selections (
          id SERIAL PRIMARY KEY,
          user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
          week_start DATE NOT NULL,
          selected_day INTEGER NOT NULL CHECK (selected_day BETWEEN 1 AND 7),
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(user_id, week_start, selected_day)
        );
      `);
      console.log('Таблица weekend_selections успешно создана');
      
      // Создаем индексы
      await pool.query(`
        CREATE INDEX IF NOT EXISTS idx_weekend_selections_user_id ON weekend_selections(user_id);
        CREATE INDEX IF NOT EXISTS idx_weekend_selections_week ON weekend_selections(week_start);
      `);
      console.log('Индексы для таблицы weekend_selections созданы');
      
      // Возвращаем пустой массив, так как таблица только что создана
      return res.json([]);
    }

    // Проверяем структуру таблицы
    const columnsCheck = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'weekend_selections'
    `);

    const existingColumns = columnsCheck.rows.map(row => row.column_name);
    console.log('Существующие колонки в таблице weekend_selections:', existingColumns);

    const result = await pool.query(
      "SELECT * FROM weekend_selections WHERE user_id = $1 ORDER BY week_start, selected_day",
      [userId]
    );
    console.log('Результат запроса:', result.rows);
    res.json(result.rows);
  } catch (error) {
    console.error("Ошибка при получении выходных дней:", error);
    console.error("Детали ошибки:", error.message);
    console.error("Стек вызовов:", error.stack);
    res.status(500).json({ error: "Ошибка сервера при получении выходных дней", details: error.message });
  }
});

// Функция для форматирования даты в формат YYYY-MM-DD с учетом часового пояса
function formatDateForClient(date) {
  const d = new Date(date);
  const year = d.getFullYear();
  const month = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

// Получение периодов отпуска пользователя
app.get('/api/vacation-periods/:userId', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;
    const result = await pool.query(
      'SELECT * FROM vacation_periods WHERE user_id = $1 ORDER BY start_date',
      [userId]
    );
    
    // Форматируем даты перед отправкой на клиент
    const formattedResult = result.rows.map(row => ({
      ...row,
      start_date: formatDateForClient(row.start_date),
      end_date: formatDateForClient(row.end_date)
    }));
    
    res.json(formattedResult);
  } catch (error) {
    console.error('Ошибка при получении периодов отпуска:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Сохранение периода отпуска
app.post('/api/vacation-periods', authenticateToken, async (req, res) => {
  const { userId, startDate, endDate } = req.body;
  
  try {
    // Проверяем, что даты валидны
    if (!startDate || !endDate || new Date(endDate) < new Date(startDate)) {
      return res.status(400).json({ error: 'Некорректные даты' });
    }

    // Проверяем, что период не менее 14 дней
    const start = new Date(startDate);
    const end = new Date(endDate);
    const duration = Math.ceil((end - start) / (1000 * 60 * 60 * 24)) + 1;
    
    if (duration < 14) {
      return res.status(400).json({ error: 'Минимальная продолжительность отпуска - 14 дней' });
    }

    // Проверяем общее количество дней отпуска в текущем году
    const currentYear = new Date().getFullYear();
    const result = await pool.query(
      `SELECT COALESCE(SUM(
        (end_date::date - start_date::date) + 1
      ), 0) as total_days
      FROM vacation_periods
      WHERE user_id = $1
      AND DATE_PART('year', start_date) = $2`,
      [userId, currentYear]
    );

    const totalDays = parseInt(result.rows[0].total_days);
    if (totalDays + duration > 28) {
      return res.status(400).json({ error: 'Превышен лимит отпускных дней (28 дней в год)' });
    }

    // Проверяем наличие колонки status в таблице vacation_periods
    const columnExists = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.columns 
        WHERE table_name = 'vacation_periods' AND column_name = 'status'
      );
    `);

    // Сохраняем новый период отпуска с учетом наличия колонки status
    let insertSql = '';
    let params = [];

    if (columnExists.rows[0].exists) {
      insertSql = `
        INSERT INTO vacation_periods (user_id, start_date, end_date, status)
        VALUES ($1, $2, $3, $4)
        RETURNING *
      `;
      params = [userId, startDate, endDate, 'pending'];
    } else {
      insertSql = `
        INSERT INTO vacation_periods (user_id, start_date, end_date)
        VALUES ($1, $2, $3)
        RETURNING *
      `;
      params = [userId, startDate, endDate];
    }

    const insertResult = await pool.query(insertSql, params);

    res.json(insertResult.rows[0]);
  } catch (error) {
    console.error('Ошибка при сохранении периода отпуска:', error);
    res.status(500).json({ error: 'Ошибка при сохранении периода отпуска' });
  }
});

// Удаление периода отпуска
app.delete('/api/vacation-periods/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query(
      'DELETE FROM vacation_periods WHERE id = $1',
      [id]
    );
    res.json({ message: 'Период отпуска успешно удален' });
  } catch (error) {
    console.error('Ошибка при удалении периода отпуска:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Обновление периода отпуска
app.put('/api/vacation-periods/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { startDate, endDate, status } = req.body;
  
  try {
    console.log('Получен запрос на обновление периода отпуска:', {
      id, startDate, endDate, status
    });

    // Проверяем, что даты валидны
    if (!startDate || !endDate || new Date(endDate) < new Date(startDate)) {
      return res.status(400).json({ error: 'Некорректные даты' });
    }

    // Проверяем, что период не менее 14 дней
    const start = new Date(startDate);
    const end = new Date(endDate);
    const duration = Math.ceil((end - start) / (1000 * 60 * 60 * 24)) + 1;
    
    if (duration < 14) {
      return res.status(400).json({ error: 'Минимальная продолжительность отпуска - 14 дней' });
    }

    // Получаем информацию о текущем периоде
    const currentPeriod = await pool.query(
      'SELECT * FROM vacation_periods WHERE id = $1',
      [id]
    );

    if (currentPeriod.rows.length === 0) {
      return res.status(404).json({ error: 'Период отпуска не найден' });
    }

    // Проверяем, имеет ли пользователь доступ к редактированию
    // Администраторы (req.user.role === 'admin') могут редактировать любые отпуска
    // Обычные пользователи могут редактировать только свои отпуска
    const isAdmin = req.user.role === 'admin';
    if (!isAdmin && currentPeriod.rows[0].user_id !== req.user.userId) {
      return res.status(403).json({ error: 'У вас нет доступа к редактированию этого отпуска' });
    }

    // Проверяем общее количество дней отпуска в текущем году
    const currentYear = new Date().getFullYear();
    const result = await pool.query(
      `SELECT COALESCE(SUM(
        (end_date::date - start_date::date) + 1
      ), 0) as total_days
      FROM vacation_periods
      WHERE user_id = $1
      AND DATE_PART('year', start_date) = $2
      AND id != $3`,
      [currentPeriod.rows[0].user_id, currentYear, id]
    );

    const totalDays = parseInt(result.rows[0].total_days);
    if (totalDays + duration > 28) {
      return res.status(400).json({ error: 'Превышен лимит отпускных дней (28 дней в год)' });
    }

    // Валидация статуса
    const validStatuses = ['pending', 'approved', 'rejected', '0', '1', '2'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ error: 'Недопустимый статус. Допустимые значения: pending, approved, rejected, 0, 1, 2' });
    }
    
    // Преобразование числовых строковых статусов в текстовые для сохранения в БД
    let statusToSave = status;
    if (status === '0') statusToSave = 'pending';
    if (status === '1') statusToSave = 'approved';  
    if (status === '2') statusToSave = 'rejected';
    
    // Строим SQL-запрос для обновления периода отпуска с учетом наличия status
    let updateSql = `
      UPDATE vacation_periods 
      SET start_date = $1, 
          end_date = $2,
          status = $3
    `;
    
    let params = [startDate, endDate, statusToSave];
    
    // Добавляем обновление timestamp и условие WHERE
    updateSql += `, updated_at = CURRENT_TIMESTAMP WHERE id = $4 RETURNING *`;
    params.push(id);
    
    console.log('SQL-запрос:', updateSql);
    console.log('Параметры:', params);
    
    // Выполняем обновление
    const updateResult = await pool.query(updateSql, params);
    console.log('Результат обновления:', updateResult.rows[0]);

    res.json({
      success: true,
      message: 'Период отпуска успешно обновлен',
      vacation: updateResult.rows[0]
    });
  } catch (error) {
    console.error('Ошибка при обновлении периода отпуска:', error);
    res.status(500).json({ error: 'Ошибка при обновлении периода отпуска' });
  }
});

// Отклонение периода отпуска
app.put('/api/vacation-periods/:id/reject', authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    const { id } = req.params;
    
    // Проверяем, существует ли период отпуска
    const periodResult = await client.query(
      'SELECT * FROM vacation_periods WHERE id = $1',
      [id]
    );

    if (periodResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Период отпуска не найден' });
    }

    // Удаляем период отпуска
    await client.query(
      'DELETE FROM vacation_periods WHERE id = $1',
      [id]
    );

    await client.query('COMMIT');
    res.json({ message: 'Период отпуска успешно удален' });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Ошибка при удалении периода отпуска:', error);
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  } finally {
    client.release();
  }
});

// Получение активного еженедельного опроса
app.get("/api/surveys/weekly/active", authenticateToken, async (req, res) => {
    try {
        // Получаем дату начала текущей недели
        const weekStart = getCurrentWeekStart();
        
        // Проверяем, отвечал ли пользователь на еженедельный опрос в текущую неделю
        const hasRespondedThisWeek = await pool.query(
            `SELECT EXISTS (
                SELECT 1 
                FROM survey_responses sr
                JOIN surveys s ON sr.survey_id = s.id
                WHERE sr.user_id = $1 
                AND s.type = 'weekly'
                AND sr.created_at >= $2
            ) as has_responded`,
            [req.user.userId, weekStart]
        );

        if (hasRespondedThisWeek.rows[0].has_responded) {
            return res.status(403).json({ 
                error: "Вы уже прошли анкетирование на этой неделе. Следующее анкетирование будет доступно в понедельник",
                nextReset: new Date(weekStart.getTime() + 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0]
            });
        }

        // Получаем самый последний еженедельный опрос
        const result = await pool.query(
            `SELECT s.*, 
                    array_agg(json_build_object(
                        'id', sq.id,
                        'text', sq.question_text,
                        'type', sq.question_type,
                        'options', sq.options,
                        'isRequired', sq.is_required,
                        'orderIndex', sq.order_index
                    ) ORDER BY sq.order_index) as questions
             FROM surveys s
             LEFT JOIN survey_questions sq ON s.id = sq.survey_id
             WHERE s.type = 'weekly'
             GROUP BY s.id
             ORDER BY s.created_at DESC
             LIMIT 1`
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Активный еженедельный опрос не найден" });
        }

        // Добавляем информацию о текущей неделе и дате следующего сброса
        const nextReset = new Date(weekStart.getTime() + 7 * 24 * 60 * 60 * 1000);
        const survey = {
            ...result.rows[0],
            weekInfo: {
                currentWeekStart: weekStart.toISOString().split('T')[0],
                nextReset: nextReset.toISOString().split('T')[0],
                daysUntilReset: Math.ceil((nextReset - new Date()) / (1000 * 60 * 60 * 24))
            }
        };

        res.json(survey);
    } catch (error) {
        console.error("Ошибка при получении еженедельного опроса:", error);
        res.status(500).json({ error: "Ошибка при получении еженедельного опроса" });
    }
});

// Проверка ответов пользователя на опрос
app.get("/api/surveys/:surveyId/check-response", authenticateToken, async (req, res) => {
    const { surveyId } = req.params;
    
    try {
        // Получаем информацию об опросе
        const surveyInfo = await pool.query(
            "SELECT type FROM surveys WHERE id = $1",
            [surveyId]
        );
        
        if (surveyInfo.rows.length === 0) {
            return res.status(404).json({ error: "Опрос не найден" });
        }
        
        const isWeeklySurvey = surveyInfo.rows[0].type === 'weekly';
        
        // Получаем дату начала текущей недели для еженедельных опросов
        const weekStart = isWeeklySurvey ? getCurrentWeekStart() : null;
        
        // Проверяем, есть ли ответы пользователя на этот опрос
        let query = `SELECT EXISTS (
            SELECT 1 FROM survey_responses 
            WHERE survey_id = $1 AND user_id = $2
        ) as has_responded`;
        
        let queryParams = [surveyId, req.user.userId];
        
        // Для еженедельных опросов проверяем ответы только за текущую неделю
        if (isWeeklySurvey) {
            query = `SELECT EXISTS (
                SELECT 1 FROM survey_responses 
                WHERE survey_id = $1 AND user_id = $2 AND created_at >= $3
            ) as has_responded`;
            queryParams.push(weekStart);
        }
        
        const result = await pool.query(query, queryParams);
        
        const responseData = { 
            hasResponded: result.rows[0].has_responded
        };
        
        // Добавляем информацию о неделе для еженедельных опросов
        if (isWeeklySurvey) {
            const nextReset = new Date(weekStart.getTime() + 7 * 24 * 60 * 60 * 1000);
            responseData.weekInfo = {
                currentWeekStart: weekStart.toISOString().split('T')[0],
                nextReset: nextReset.toISOString().split('T')[0],
                daysUntilReset: Math.ceil((nextReset - new Date()) / (1000 * 60 * 60 * 24))
            };
        }
        
        res.json(responseData);
    } catch (error) {
        console.error("Ошибка при проверке ответов:", error);
        res.status(500).json({ error: "Ошибка при проверке ответов" });
    }
});

// Получение всех смен
app.get("/api/shifts", authenticateToken, async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM shifts ORDER BY start_time");
        res.json(result.rows);
    } catch (error) {
        console.error("Ошибка при получении смен:", error);
        res.status(500).json({ error: "Ошибка при получении смен" });
    }
});

// Получение всех кабинетов
app.get("/api/cabinets", authenticateToken, async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM cabinets ORDER BY floor, name");
        res.json(result.rows);
    } catch (error) {
        console.error("Ошибка при получении кабинетов:", error);
        res.status(500).json({ error: "Ошибка при получении кабинетов" });
    }
});

// Получение мест в кабинете
app.get("/api/cabinets/:cabinetId/seats", authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT * FROM seats WHERE cabinet_id = $1 ORDER BY seat_number",
            [req.params.cabinetId]
        );
        res.json(result.rows);
    } catch (error) {
        console.error("Ошибка при получении мест:", error);
        res.status(500).json({ error: "Ошибка при получении мест" });
    }
});

// Функция для получения текущей даты в часовом поясе Екатеринбурга
function getCurrentDateYekaterinburg() {
  // Создаем объект даты в UTC
  const now = new Date();
  
  // Получаем смещение в минутах для Екатеринбурга (+5 часов = +300 минут)
  const yekaterinburgOffset = 5 * 60;
  
  // Получаем локальное смещение в минутах
  const localOffset = now.getTimezoneOffset();
  
  // Вычисляем разницу в миллисекундах
  const offsetDiff = (yekaterinburgOffset + localOffset) * 60 * 1000;
  
  // Создаем новую дату с учетом смещения
  const yekaterinburgDate = new Date(now.getTime() + offsetDiff);
  
  // Возвращаем дату в формате YYYY-MM-DD
  return yekaterinburgDate.toISOString().split('T')[0];
}

// Функция для форматирования даты в формат YYYY-MM-DD
function formatDate(date) {
  const d = new Date(date);
  return d.toISOString().split('T')[0];
}

// Получение бронирований на определенную дату
app.get('/api/bookings/date/:date', authenticateToken, async (req, res) => {
  try {
    const date = req.params.date;
    const weekStart = new Date(date);
    weekStart.setDate(weekStart.getDate() - weekStart.getDay() + 1); // Устанавливаем на понедельник текущей недели
    
    const query = `
      SELECT * FROM bookings 
      WHERE week_start = $1
      ORDER BY created_at DESC
    `;
    const result = await pool.query(query, [weekStart]);
    res.json(result.rows);
  } catch (error) {
    console.error('Ошибка при получении бронирований:', error);
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  }
});

// Получение бронирований пользователя
app.get("/api/bookings/user", authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const currentDate = new Date();
        const weekStart = new Date(currentDate);
        weekStart.setDate(weekStart.getDate() - weekStart.getDay() + 1); // Устанавливаем на понедельник текущей недели
        
        const result = await pool.query(
            'SELECT b.*, c.name AS cabinet_name, s.seat_number AS seat_name, sh.time AS shift_time FROM bookings b ' +
            'JOIN cabinets c ON b.cabinet_id = c.id ' +
            'JOIN seats s ON b.seat_id = s.id ' +
            'JOIN shifts sh ON b.shift_id = sh.id ' +
            'WHERE b.user_id = $1 AND b.week_start = $2 ' +
            'ORDER BY b.booking_date DESC',
            [userId, weekStart]
        );
        
        // Добавляем информацию о том, сколько дней осталось до автоматического удаления бронирования
        const bookings = result.rows.map(booking => {
            const bookingWeekStart = new Date(booking.week_start);
            const nextWeekStart = new Date(bookingWeekStart);
            nextWeekStart.setDate(nextWeekStart.getDate() + 7);
            
            const daysUntilExpiration = Math.ceil((nextWeekStart - currentDate) / (1000 * 60 * 60 * 24));
            
            return {
                ...booking,
                expires_in_days: daysUntilExpiration > 0 ? daysUntilExpiration : 0,
                expires_on: nextWeekStart.toISOString().split('T')[0]
            };
        });
        
        res.json(bookings);
    } catch (error) {
        console.error('Ошибка при получении бронирований пользователя:', error);
        res.status(500).json({ error: 'Ошибка при получении бронирований пользователя' });
    }
});

// Получение информации о текущей неделе бронирования
app.get("/api/bookings/current-week", authenticateToken, async (req, res) => {
    try {
        // Вычисляем даты текущей недели
        const currentDate = new Date();
        const weekStart = new Date(currentDate);
        weekStart.setDate(weekStart.getDate() - weekStart.getDay() + 1); // Понедельник текущей недели
        weekStart.setHours(0, 0, 0, 0);
        
        const weekEnd = new Date(weekStart);
        weekEnd.setDate(weekStart.getDate() + 6); // Воскресенье текущей недели
        weekEnd.setHours(23, 59, 59, 999);
        
        // Вычисляем дату начала следующей недели (когда произойдет сброс)
        const nextWeekStart = new Date(weekStart);
        nextWeekStart.setDate(nextWeekStart.getDate() + 7);
        
        res.json({
            current_week_start: weekStart.toISOString(),
            current_week_end: weekEnd.toISOString(),
            next_reset_date: nextWeekStart.toISOString(),
            days_until_reset: Math.ceil((nextWeekStart - currentDate) / (1000 * 60 * 60 * 24))
        });
    } catch (error) {
        console.error('Ошибка при получении информации о текущей неделе:', error);
        res.status(500).json({ error: 'Ошибка при получении информации о текущей неделе' });
    }
});

// Создание нового бронирования
app.post('/api/bookings', authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    const { cabinet_id, seat_id, shift_id } = req.body;
    const userId = req.user.userId;
    const bookingDate = formatDate(getCurrentDateYekaterinburg());
    
    // Всегда устанавливаем week_start на понедельник текущей недели
    const now = new Date();
    const weekStart = new Date(now);
    weekStart.setDate(weekStart.getDate() - weekStart.getDay() + 1); // Устанавливаем на понедельник текущей недели
    weekStart.setHours(0, 0, 0, 0);
    
    // Вычисляем дату окончания бронирования (конец недели - воскресенье)
    const weekEnd = new Date(weekStart);
    weekEnd.setDate(weekStart.getDate() + 6); // Воскресенье текущей недели
    weekEnd.setHours(23, 59, 59, 999);
    
    // Проверяем, нет ли уже бронирования на это место в эту смену на текущей неделе
    const existingBooking = await client.query(
      'SELECT * FROM bookings WHERE seat_id = $1 AND cabinet_id = $2 AND shift_id = $3 AND week_start = $4',
      [seat_id, cabinet_id, shift_id, weekStart]
    );

    if (existingBooking.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Это место уже забронировано на выбранную смену на текущей неделе' });
    }

    // Проверяем, нет ли уже бронирования у пользователя на эту смену на текущей неделе
    const userBooking = await client.query(
      'SELECT * FROM bookings WHERE user_id = $1 AND shift_id = $2 AND week_start = $3',
      [userId, shift_id, weekStart]
    );

    if (userBooking.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'У вас уже есть бронирование на эту смену на текущей неделе' });
    }

    const result = await client.query(
      'INSERT INTO bookings (user_id, cabinet_id, seat_id, shift_id, booking_date, week_start) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [userId, cabinet_id, seat_id, shift_id, bookingDate, weekStart]
    );
    
    // Получаем информацию о кабинете и смене
    const cabinetInfo = await client.query('SELECT name FROM cabinets WHERE id = $1', [cabinet_id]);
    const shiftInfo = await client.query('SELECT time FROM shifts WHERE id = $1', [shift_id]);
    const seatInfo = await client.query('SELECT seat_number FROM seats WHERE id = $1', [seat_id]);
    
    // Вычисляем дату начала следующей недели (когда произойдет сброс)
    const nextWeekStart = new Date(weekStart);
    nextWeekStart.setDate(nextWeekStart.getDate() + 7);
    const daysUntilReset = Math.ceil((nextWeekStart - now) / (1000 * 60 * 60 * 24));

    await client.query('COMMIT');
    
    // Добавляем дополнительную информацию в ответ
    const booking = {
      ...result.rows[0],
      cabinet_name: cabinetInfo.rows[0]?.name || 'Неизвестный кабинет',
      seat_number: seatInfo.rows[0]?.seat_number || 'Неизвестное место',
      shift_time: shiftInfo.rows[0]?.time || 'Неизвестная смена',
      week_end: weekEnd.toISOString(),
      next_reset_date: nextWeekStart.toISOString(),
      days_until_reset: daysUntilReset,
      expires_on: nextWeekStart.toISOString().split('T')[0],
      message: `Бронирование действует до конца текущей недели (${weekEnd.toLocaleDateString('ru-RU')}). Будет автоматически отменено в начале новой недели (${nextWeekStart.toLocaleDateString('ru-RU')}).`
    };
    
    res.json(booking);
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Ошибка при создании бронирования:', error);
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  } finally {
    client.release();
  }
});

// Отмена бронирования
app.delete("/api/bookings/:id", authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        // Проверяем, принадлежит ли бронирование пользователю
        const booking = await pool.query(
            "SELECT * FROM bookings WHERE id = $1 AND user_id = $2",
            [req.params.id, userId]
        );

        if (booking.rows.length === 0) {
            return res.status(404).json({ error: "Бронирование не найдено или не принадлежит вам" });
        }

        await pool.query("DELETE FROM bookings WHERE id = $1", [req.params.id]);
        res.json({ message: "Бронирование успешно отменено" });
    } catch (error) {
        console.error("Ошибка при отмене бронирования:", error);
        res.status(500).json({ error: "Ошибка при отмене бронирования" });
    }
});

// API для записи к психологу
app.post('/api/psychologist/appointments', authenticateToken, async (req, res) => {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
        const { appointment_date, appointment_time, notes } = req.body;
        const userId = req.user.userId;

        // Проверяем формат даты и времени
        if (!appointment_date || !appointment_time) {
            return res.status(400).json({ error: 'Необходимо указать дату и время записи' });
        }

        // Проверяем, что дата не в прошлом
        const appointmentDateTime = new Date(`${appointment_date}T${appointment_time}`);
        const currentDate = new Date();
        if (appointmentDateTime < currentDate) {
            return res.status(400).json({ error: 'Нельзя записаться на прошедшую дату' });
        }

        // Проверяем, не является ли дата выходным днем (суббота или воскресенье)
        const dayOfWeek = appointmentDateTime.getDay();
        if (dayOfWeek === 0 || dayOfWeek === 6) {
            return res.status(400).json({ error: 'Запись к психологу невозможна в выходные дни (суббота и воскресенье)' });
        }

        // Проверяем, что время в рабочем диапазоне (9:00 - 18:00)
        const appointmentHour = appointmentDateTime.getHours();
        if (appointmentHour < 9 || appointmentHour > 18) {
            return res.status(400).json({ error: 'Запись возможна только в рабочее время (9:00 - 18:00)' });
        }

        // Проверяем количество записей пользователя на эту дату
        const userAppointmentsCount = await client.query(
            'SELECT COUNT(*) FROM psychologist_appointments WHERE user_id = $1 AND appointment_date = $2',
            [userId, appointment_date]
        );

        if (parseInt(userAppointmentsCount.rows[0].count) >= 2) {
            return res.status(400).json({ error: 'Нельзя записаться более чем на 2 сессии в день' });
        }

        // Проверяем, не занято ли это время
        const existingAppointment = await client.query(
            'SELECT * FROM psychologist_appointments WHERE appointment_date = $1 AND appointment_time = $2',
            [appointment_date, appointment_time]
        );

        if (existingAppointment.rows.length > 0) {
            return res.status(400).json({ error: 'Это время уже занято' });
        }

        // Создаем запись
        const result = await client.query(
            `INSERT INTO psychologist_appointments 
            (user_id, appointment_date, appointment_time, notes) 
            VALUES ($1, $2, $3, $4) 
            RETURNING *`,
            [userId, appointment_date, appointment_time, notes || '']
        );

        await client.query('COMMIT');
        res.json(result.rows[0]);
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Ошибка при создании записи к психологу:', error);
        res.status(500).json({ error: 'Ошибка при создании записи' });
    } finally {
        client.release();
    }
});

// Получение записей пользователя к психологу
app.get('/api/psychologist/appointments', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const result = await pool.query(
            'SELECT * FROM psychologist_appointments WHERE user_id = $1 ORDER BY appointment_date, appointment_time',
            [userId]
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Ошибка при получении записей к психологу:', error);
        res.status(500).json({ error: 'Ошибка при получении записей' });
    }
});

// Отмена записи к психологу
app.delete('/api/psychologist/appointments/:id', authenticateToken, async (req, res) => {
    try {
        const appointmentId = req.params.id;
        const userId = req.user.userId;
        const userRole = req.user.role;

        // Проверяем, является ли пользователь психологом или владельцем записи
        const appointment = await pool.query(
            'SELECT * FROM psychologist_appointments WHERE id = $1 AND (user_id = $2 OR $3 = \'psychologist\')',
            [appointmentId, userId, userRole]
        );

        if (appointment.rows.length === 0) {
            return res.status(404).json({ error: 'Запись не найдена' });
        }

        // Удаляем запись
        await pool.query(
            'DELETE FROM psychologist_appointments WHERE id = $1',
            [appointmentId]
        );

        res.json({ message: 'Запись успешно отменена' });
    } catch (error) {
        console.error('Ошибка при отмене записи к психологу:', error);
        res.status(500).json({ error: 'Ошибка при отмене записи' });
    }
});

// Получение доступных слотов для записи
app.get('/api/psychologist/available-slots', authenticateToken, async (req, res) => {
    try {
        const { date } = req.query;
        
        if (!date) {
            return res.status(400).json({ error: 'Пожалуйста, выберите дату для записи' });
        }

        // Проверяем, что дата не в прошлом
        const selectedDate = new Date(date);
        const currentDate = new Date();
        if (selectedDate < currentDate) {
            return res.status(400).json({ error: 'Нельзя записаться на прошедшую дату' });
        }

        // Проверяем, не является ли дата выходным днем (суббота или воскресенье)
        const dayOfWeek = selectedDate.getDay();
        if (dayOfWeek === 0) {
            return res.status(400).json({ error: 'Запись к психологу невозможна в воскресенье' });
        }
        if (dayOfWeek === 6) {
            return res.status(400).json({ error: 'Запись к психологу невозможна в субботу' });
        }

        // Получаем все записи на указанную дату
        const bookedSlots = await pool.query(
            'SELECT appointment_time FROM psychologist_appointments WHERE appointment_date = $1',
            [date]
        );

        // Генерируем все возможные слоты (с 9:00 до 18:00 с интервалом в 1 час)
        const allSlots = [];
        const startTime = new Date(`2000-01-01T09:00:00`);
        const endTime = new Date(`2000-01-01T18:00:00`);
        
        while (startTime <= endTime) {
            allSlots.push(startTime.toTimeString().slice(0, 5));
            startTime.setHours(startTime.getHours() + 1);
        }

        // Фильтруем занятые слоты
        const bookedTimes = bookedSlots.rows.map(slot => slot.appointment_time);
        const availableSlots = allSlots.filter(slot => !bookedTimes.includes(slot));

        if (availableSlots.length === 0) {
            return res.status(404).json({ error: 'На выбранную дату все слоты уже заняты' });
        }

        res.json(availableSlots);
    } catch (error) {
        console.error('Ошибка при получении доступных слотов:', error);
        res.status(500).json({ error: 'Произошла ошибка при загрузке доступного времени. Пожалуйста, попробуйте позже' });
    }
});

// Middleware для проверки роли психолога
const checkPsychologistRole = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'Необходима авторизация' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await pool.query('SELECT role FROM users WHERE id = $1', [decoded.userId]);
    
    if (user.rows[0]?.role !== 'psychologist') {
      return res.status(403).json({ error: 'Доступ запрещен' });
    }

    next();
  } catch (error) {
    console.error('Error in checkPsychologistRole middleware:', error);
    res.status(401).json({ error: 'Ошибка авторизации' });
  }
};

// API endpoints для панели психолога
app.get('/api/psychologist/dashboard/appointments', checkPsychologistRole, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        pa.*,
        u.name as user_name,
        u.email as user_email
      FROM psychologist_appointments pa
      JOIN users u ON pa.user_id = u.id
      ORDER BY pa.appointment_date ASC, pa.appointment_time ASC
    `);
    
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching appointments:', error);
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  }
});

app.get('/api/psychologist/dashboard/survey-stats', checkPsychologistRole, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        sq.question_text as question,
        sr.answer_text as answer,
        COUNT(*) as count,
        ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (PARTITION BY sq.question_text), 2) as percentage
      FROM survey_responses sr
      JOIN survey_questions sq ON sr.question_id = sq.id
      GROUP BY sq.question_text, sr.answer_text
      ORDER BY sq.question_text, sr.answer_text
    `);
    
    // Преобразуем результаты в нужный формат
    const stats = {};
    result.rows.forEach(row => {
      if (!stats[row.question]) {
        stats[row.question] = {
          question: row.question,
          answers: []
        };
      }
      
      stats[row.question].answers.push({
        text: row.answer,
        count: parseInt(row.count),
        percentage: parseFloat(row.percentage)
      });
    });
    
    res.json(Object.values(stats));
  } catch (error) {
    console.error('Error fetching survey stats:', error);
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  }
});

app.post('/api/psychologist/appointments/:id/confirm', checkPsychologistRole, async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query(
      'UPDATE psychologist_appointments SET status = $1 WHERE id = $2',
      ['confirmed', id]
    );
    res.json({ message: 'Запись подтверждена' });
  } catch (error) {
    console.error('Error confirming appointment:', error);
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  }
});

app.get('/api/psychologist/dashboard/user-surveys', checkPsychologistRole, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.name as user_name,
        u.email as user_email,
        sq.question_text as question,
        sr.answer_text as answer,
        sr.created_at as answered_at
      FROM survey_responses sr
      JOIN users u ON sr.user_id = u.id
      JOIN survey_questions sq ON sr.question_id = sq.id
      ORDER BY u.name, sr.created_at DESC
    `);
    
    // Группируем ответы по пользователям
    const userSurveys = {};
    result.rows.forEach(row => {
      if (!userSurveys[row.user_email]) {
        userSurveys[row.user_email] = {
          name: row.user_name,
          email: row.user_email,
          answers: []
        };
      }
      
      userSurveys[row.user_email].answers.push({
        question: row.question,
        answer: row.answer,
        answered_at: row.answered_at
      });
    });
    
    res.json(Object.values(userSurveys));
  } catch (error) {
    console.error('Error fetching user surveys:', error);
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  }
});

// Middleware для проверки роли администратора
const isAdmin = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Требуется авторизация' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        console.log('Decoded token:', decoded); // Добавляем для отладки
        if (!decoded.role || decoded.role !== 'admin') {
            return res.status(403).json({ error: 'Доступ запрещен. Требуются права администратора.' });
        }
        req.user = decoded;
        req.userId = decoded.id; // Добавляем для использования в других частях кода
        next();
    } catch (error) {
        console.error('Ошибка в middleware isAdmin:', error);
        res.status(401).json({ error: 'Недействительный токен' });
    }
};

// Эндпоинт для получения данных для админ-панели
app.get('/api/admin/bookings', isAdmin, async (req, res) => {
  try {
    const today = new Date();
    const weekStart = new Date(today);
    weekStart.setDate(today.getDate() - today.getDay() + 1); // Устанавливаем на понедельник текущей недели
    weekStart.setHours(0, 0, 0, 0);
    
    // Получаем все бронирования на текущую неделю с информацией о смене
    const bookings = await pool.query(
      `SELECT b.*, u.name as user_name, u.email as user_email, s.seat_number, s.id as seat_id 
       FROM bookings b 
       JOIN users u ON b.user_id = u.id 
       JOIN seats s ON b.seat_id = s.id 
       WHERE b.week_start = $1`,
      [weekStart]
    );

    // Получаем только кабинеты А и Б (id=1 и id=2)
    const cabinets = await pool.query(
      `SELECT c.* FROM cabinets c WHERE c.id IN (1, 2) ORDER BY c.name`
    );
    
    // Получаем все места и связываем их с кабинетами
    const seats = await pool.query(
      `SELECT s.* FROM seats s WHERE s.cabinet_id IN (1, 2) ORDER BY s.cabinet_id, s.seat_number`
    );
    
    // Получаем только 3 смены
    const shifts = await pool.query('SELECT * FROM shifts ORDER BY id LIMIT 3');

    console.log('Загружено смен:', shifts.rows.length);
    console.log('Загружено бронирований:', bookings.rows.length);
    
    // Выводим информацию о бронированиях для отладки
    bookings.rows.forEach(booking => {
      console.log(`Бронирование: ID=${booking.id}, место=${booking.seat_number}, смена=${booking.shift_id}, кабинет=${booking.cabinet_id}`);
    });

    // Форматируем данные о местах для каждого кабинета
    const formattedCabinets = cabinets.rows.map(cabinet => {
      // Если имя кабинета начинается с "Кабинет", убираем дубликат
      let cabinetName = cabinet.name || '';
      if (cabinetName.startsWith('Кабинет ')) {
        cabinetName = cabinetName.substring(8); // Убираем "Кабинет " из начала строки
      }
      
      // Фильтруем места только для текущего кабинета
      const cabinetSeats = seats.rows.filter(seat => seat.cabinet_id === cabinet.id);
      
      // Фильтруем бронирования только для текущего кабинета
      const cabinetBookings = bookings.rows.filter(b => b.cabinet_id === cabinet.id);
      
      // Создаём список мест для кабинета на основе реальных данных из БД
      const formattedSeats = cabinetSeats.map(seat => {
        // Находим бронирование для этого места, если оно есть
        const booking = cabinetBookings.find(b => b.seat_id === seat.id);
        
        return {
          id: `${cabinet.id}-${seat.seat_number}`,
          number: seat.seat_number,
          status: booking ? 'Занято' : 'Свободно',
          user: booking ? `${booking.user_name} (${booking.user_email})` : null,
          shift_id: booking ? booking.shift_id : null
        };
      });

      return {
        ...cabinet,
        name: cabinetName, // Используем отформатированное имя без дубликата
        seats: formattedSeats,
        seats_count: formattedSeats.length
      };
    });

    // Добавляем логирование для отладки
    console.log('Общее количество мест в системе:', seats.rows.length);
    formattedCabinets.forEach(cab => {
      console.log(`Кабинет ${cab.name} (ID: ${cab.id}): ${cab.seats.length} мест`);
      const occupiedSeats = cab.seats.filter(seat => seat.status === 'Занято');
      console.log(`  - Занято мест: ${occupiedSeats.length}`);
      occupiedSeats.forEach(seat => {
        console.log(`    - Место ${seat.number}, смена: ${seat.shift_id}`);
      });
    });

    res.json({
      bookings: bookings.rows,
      cabinets: formattedCabinets,
      shifts: shifts.rows
    });
  } catch (error) {
    console.error('Ошибка при получении данных для админ-панели:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Эндпоинт для получения выходных и отпусков для админ-панели
app.get('/api/admin/timeoff', isAdmin, async (req, res) => {
  try {
    let weekends = [];
    let vacations = [];

    // Проверяем существование таблицы weekends
    const weekendsTableExists = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_name = 'weekend_selections'
      );
    `);

    if (weekendsTableExists.rows[0].exists) {
      // Таблица существует, получаем данные
      const weekendsQuery = `
        SELECT ws.*, u.name as user_name, u.email as user_email 
        FROM weekend_selections ws
        JOIN users u ON ws.user_id = u.id 
        ORDER BY ws.week_start, ws.selected_day
      `;
      const weekendsResult = await pool.query(weekendsQuery);
      weekends = weekendsResult.rows.map(row => ({
        ...row,
        week_start: formatDateForClient(row.week_start)
      }));
    }

    // Проверяем существование таблицы vacations
    const vacationsTableExists = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_name = 'vacation_periods'
      );
    `);

    if (vacationsTableExists.rows[0].exists) {
      // Таблица существует, получаем данные
      const vacationsQuery = `
        SELECT vp.*, u.name as user_name, u.email as user_email 
        FROM vacation_periods vp
        JOIN users u ON vp.user_id = u.id 
        ORDER BY vp.start_date
      `;
      const vacationsResult = await pool.query(vacationsQuery);
      vacations = vacationsResult.rows.map(row => ({
        ...row,
        start_date: formatDateForClient(row.start_date),
        end_date: formatDateForClient(row.end_date)
      }));
    }

    res.json({
      weekends,
      vacations
    });
  } catch (error) {
    console.error('Ошибка при получении данных о выходных и отпусках:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Функция для логирования действий администратора
async function logAdminAction(adminId, action, targetId, targetType, details) {
  try {
    const query = `
      INSERT INTO admin_logs (admin_id, action, entity_id, entity_type, details)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *
    `;
    const values = [adminId, action, targetId, targetType, details];
    const result = await pool.query(query, values);
    console.log('Действие администратора успешно залогировано:', result.rows[0]);
    return result.rows[0];
  } catch (error) {
    console.error('Ошибка при логировании действия администратора:', error);
    throw error;
  }
}

// Обновляем эндпоинт для обновления статуса отпуска
app.put('/api/admin/vacation/status', authenticateToken, isAdmin, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    const { vacationId, status } = req.body;
    const adminId = req.user.userId; // Получаем ID администратора из токена
    
    // Проверяем, существует ли период отпуска
    const periodResult = await client.query(
      'SELECT * FROM vacation_periods WHERE id = $1',
      [vacationId]
    );

    if (periodResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Период отпуска не найден' });
    }

    // Обновляем статус
    await client.query(
      'UPDATE vacation_periods SET status = $1 WHERE id = $2',
      [status, vacationId]
    );

    // Логируем действие администратора
    await logAdminAction(
      adminId,
      'update_vacation_status',
      vacationId,
      'vacation_period',
      { newStatus: status }
    );

    await client.query('COMMIT');
    res.json({ success: true, message: 'Статус отпуска успешно обновлен' });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Ошибка при обновлении статуса отпуска:', error);
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  } finally {
    client.release();
  }
});

// Добавляем функцию для проверки и добавления колонки status в таблицу vacation_periods
async function ensureVacationStatusColumn() {
  try {
    console.log('Проверка наличия колонки status в таблице vacation_periods...');
    const statusColumnExists = await pool.query(`
      SELECT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'vacation_periods' AND column_name = 'status'
      );
    `);

    const updatedAtColumnExists = await pool.query(`
      SELECT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'vacation_periods' AND column_name = 'updated_at'
      );
    `);

    let alterQuery = '';

    // Если колонки status нет, добавляем её
    if (!statusColumnExists.rows[0].exists) {
      console.log('Добавление колонки status в таблицу vacation_periods...');
      alterQuery += `ADD COLUMN status VARCHAR(20) DEFAULT 'pending'`;
    }

    // Если колонки updated_at нет, добавляем её
    if (!updatedAtColumnExists.rows[0].exists) {
      if (alterQuery) alterQuery += ', ';
      alterQuery += `ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP`;
    }

    // Выполняем ALTER TABLE только если есть что добавлять
    if (alterQuery) {
      await pool.query(`ALTER TABLE vacation_periods ${alterQuery};`);
      console.log('Колонки успешно добавлены в таблицу vacation_periods.');
    } else {
      console.log('Все необходимые колонки уже существуют в таблице vacation_periods.');
    }
  } catch (error) {
    console.error('Ошибка при проверке/добавлении колонок в таблицу vacation_periods:', error);
  }
}

// Добавляем функцию для проверки и создания таблицы admin_logs
async function ensureAdminLogsTable() {
  try {
    console.log('Проверка наличия таблицы admin_logs...');
    const tableExists = await pool.query(`
      SELECT EXISTS (
        SELECT 1 FROM information_schema.tables 
        WHERE table_name = 'admin_logs'
      );
    `);

    if (!tableExists.rows[0].exists) {
      console.log('Создание таблицы admin_logs...');
      await pool.query(`
        CREATE TABLE admin_logs (
          id SERIAL PRIMARY KEY,
          admin_id INT NOT NULL,
          action VARCHAR(100) NOT NULL,
          entity_id INT,
          entity_type VARCHAR(50),
          details JSONB,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);
      console.log('Таблица admin_logs успешно создана.');
    } else {
      console.log('Таблица admin_logs уже существует.');
    }
  } catch (error) {
    console.error('Ошибка при проверке/создании таблицы admin_logs:', error);
  }
}

// Функция для проверки и добавления колонки name в таблицу shifts
async function ensureShiftsNameColumn() {
  try {
    console.log('Проверка наличия колонки name в таблице shifts...');
    
    // Сначала проверяем, что таблица существует
    const tableExists = await pool.query(`
      SELECT EXISTS (
        SELECT 1 FROM information_schema.tables 
        WHERE table_name = 'shifts'
      );
    `);
    
    if (!tableExists.rows[0].exists) {
      console.log('Таблица shifts не существует. Будет создана скриптом инициализации.');
      return;
    }
    
    // Получаем существующие колонки
    const columns = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'shifts'
    `);
    
    const existingColumns = columns.rows.map(row => row.column_name);
    console.log('Существующие колонки в таблице shifts:', existingColumns);
    
    // Проверяем наличие колонки name
    if (!existingColumns.includes('name')) {
      console.log('Колонка name отсутствует в таблице shifts, добавляем её...');
      await pool.query(`
        ALTER TABLE shifts ADD COLUMN name VARCHAR(50) NULL;
      `);
      
      // Заполняем данные на основе time или start_time, в зависимости от того, какая колонка есть
      if (existingColumns.includes('start_time')) {
        await pool.query(`
          UPDATE shifts SET name = 
            CASE 
              WHEN start_time::time = '08:00:00'::time THEN 'Утренняя'
              WHEN start_time::time = '13:00:00'::time THEN 'Дневная'
              WHEN start_time::time = '18:00:00'::time THEN 'Вечерняя'
              ELSE 'Смена ' || id::text
            END
        `);
      } else if (existingColumns.includes('time')) {
        await pool.query(`
          UPDATE shifts SET name = 
            CASE 
              WHEN time = '08:00' THEN 'Утренняя'
              WHEN time = '13:00' THEN 'Дневная'
              WHEN time = '18:00' THEN 'Вечерняя'
              ELSE 'Смена ' || id::text
            END
        `);
      } else {
        // Если нет данных о времени, просто используем идентификаторы
        await pool.query(`
          UPDATE shifts SET name = 'Смена ' || id::text
        `);
      }
      
      // Устанавливаем NOT NULL после заполнения данными
      await pool.query(`
        ALTER TABLE shifts ALTER COLUMN name SET NOT NULL;
      `);
      
      console.log('Колонка name успешно добавлена и заполнена данными.');
    } else {
      console.log('Колонка name уже существует в таблице shifts.');
    }
    
    // Проверяем наличие колонок start_time и end_time
    if (!existingColumns.includes('start_time')) {
      console.log('Колонка start_time отсутствует в таблице shifts, добавляем её...');
      
      // Добавляем колонку start_time
      await pool.query(`ALTER TABLE shifts ADD COLUMN start_time TIME NULL;`);
      
      // Если есть колонка time, копируем данные
      if (existingColumns.includes('time')) {
        try {
          // Получаем значения времени
          const shiftsData = await pool.query(`SELECT id, time FROM shifts;`);
          
          // Обновляем каждую запись отдельно, чтобы избежать проблем с форматированием
          for(const shift of shiftsData.rows) {
            let startTime = '08:00'; // Значение по умолчанию
            
            // Проверяем и устанавливаем время на основе существующего значения
            if(shift.time === '08:00' || shift.time.includes('8')) {
              startTime = '08:00';
            } else if(shift.time === '13:00' || shift.time.includes('13')) {
              startTime = '13:00';
            } else if(shift.time === '18:00' || shift.time.includes('18')) {
              startTime = '18:00';
            }
            
            await pool.query(`UPDATE shifts SET start_time = $1::time WHERE id = $2`, [startTime, shift.id]);
          }
        } catch(timeError) {
          console.error('Ошибка при копировании данных из time в start_time:', timeError);
          // Устанавливаем значения по умолчанию, если возникла ошибка
          await pool.query(`UPDATE shifts SET start_time = '08:00'::time;`);
        }
      } else {
        // Устанавливаем значение по умолчанию
        await pool.query(`UPDATE shifts SET start_time = '08:00'::time;`);
      }
      
      // Делаем колонку not null
      await pool.query(`ALTER TABLE shifts ALTER COLUMN start_time SET NOT NULL;`);
    }
    
    if (!existingColumns.includes('end_time')) {
      console.log('Колонка end_time отсутствует в таблице shifts, добавляем её...');
      
      // Добавляем колонку end_time
      await pool.query(`ALTER TABLE shifts ADD COLUMN end_time TIME NULL;`);
      
      // Устанавливаем значения на основе start_time
      if (existingColumns.includes('start_time')) {
        try {
          // Получаем значения start_time
          const shiftsData = await pool.query(`SELECT id, start_time FROM shifts;`);
          
          // Обновляем каждую запись отдельно
          for(const shift of shiftsData.rows) {
            let endTime = '12:00'; // Значение по умолчанию
            
            // Устанавливаем end_time на 4 часа позже start_time
            if(shift.start_time === '08:00:00') {
              endTime = '12:00';
            } else if(shift.start_time === '13:00:00') {
              endTime = '17:00';
            } else if(shift.start_time === '18:00:00') {
              endTime = '22:00';
            }
            
            await pool.query(`UPDATE shifts SET end_time = $1::time WHERE id = $2`, [endTime, shift.id]);
          }
        } catch(timeError) {
          console.error('Ошибка при установке end_time на основе start_time:', timeError);
          // Устанавливаем значения по умолчанию, если возникла ошибка
          await pool.query(`UPDATE shifts SET end_time = '12:00'::time;`);
        }
      } else {
        // Устанавливаем значение по умолчанию
        await pool.query(`UPDATE shifts SET end_time = '12:00'::time;`);
      }
      
      // Делаем колонку not null
      await pool.query(`ALTER TABLE shifts ALTER COLUMN end_time SET NOT NULL;`);
    }
    
    // Проверяем наличие колонки time
    if (!existingColumns.includes('time')) {
      console.log('Колонка time отсутствует в таблице shifts, добавляем её...');
      
      // Добавляем колонку time
      await pool.query(`ALTER TABLE shifts ADD COLUMN time VARCHAR(50);`);
      
      // Если есть колонка start_time, копируем данные
      if (existingColumns.includes('start_time')) {
        try {
          await pool.query(`
            UPDATE shifts SET time = 
              CASE 
                WHEN start_time::time = '08:00:00'::time THEN '08:00'
                WHEN start_time::time = '13:00:00'::time THEN '13:00'
                WHEN start_time::time = '18:00:00'::time THEN '18:00'
                ELSE start_time::text
              END
          `);
        } catch(timeError) {
          console.error('Ошибка при копировании данных из start_time в time:', timeError);
          // Устанавливаем значения по умолчанию, если возникла ошибка
          await pool.query(`UPDATE shifts SET time = '08:00';`);
        }
      } else {
        // Устанавливаем значение по умолчанию
        await pool.query(`UPDATE shifts SET time = '08:00';`);
      }
    }
    
    console.log('Структура таблицы shifts успешно обновлена.');
    
  } catch (error) {
    console.error('Ошибка при проверке/добавлении колонок в таблицу shifts:', error);
    console.error('Детали ошибки:', error.message);
  }
}

// Функция для проверки и обновления структуры таблицы cabinets
async function ensureCabinetsColumns() {
  try {
    console.log('Проверка структуры таблицы cabinets...');
    
    // Сначала проверяем, что таблица существует
    const tableExists = await pool.query(`
      SELECT EXISTS (
        SELECT 1 FROM information_schema.tables 
        WHERE table_name = 'cabinets'
      );
    `);
    
    if (!tableExists.rows[0].exists) {
      console.log('Таблица cabinets не существует. Будет создана скриптом инициализации.');
      return;
    }
    
    // Получаем существующие колонки
    const columns = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'cabinets'
    `);
    
    const existingColumns = columns.rows.map(row => row.column_name);
    console.log('Существующие колонки в таблице cabinets:', existingColumns);
    
    // Проверяем наличие колонки number и добавляем значения по умолчанию, если нужно
    if (existingColumns.includes('number') && !existingColumns.includes('number_is_nullable')) {
      // Проверяем, есть ли ограничение NOT NULL
      const constraintCheck = await pool.query(`
        SELECT is_nullable 
        FROM information_schema.columns 
        WHERE table_name = 'cabinets' AND column_name = 'number'
      `);
      
      const isNullable = constraintCheck.rows[0]?.is_nullable === 'YES';
      
      if (!isNullable) {
        console.log('Колонка number имеет ограничение NOT NULL, заполняем её для существующих записей...');
        
        // Добавляем временную колонку для отслеживания статуса миграции
        await pool.query(`ALTER TABLE cabinets ADD COLUMN number_is_nullable BOOLEAN DEFAULT FALSE;`);
        
        // Временно отключаем ограничение NOT NULL
        await pool.query(`ALTER TABLE cabinets ALTER COLUMN number DROP NOT NULL;`);
        
        // Проверяем, есть ли записи с NULL в поле number
        const nullCheck = await pool.query(`SELECT COUNT(*) FROM cabinets WHERE number IS NULL;`);
        
        if (parseInt(nullCheck.rows[0].count) > 0) {
          // Заполняем NULL значения
          await pool.query(`
            UPDATE cabinets SET number = id::text WHERE number IS NULL;
          `);
        }
        
        // Восстанавливаем ограничение NOT NULL
        await pool.query(`ALTER TABLE cabinets ALTER COLUMN number SET NOT NULL;`);
        
        // Отмечаем, что миграция выполнена
        await pool.query(`UPDATE cabinets SET number_is_nullable = TRUE;`);
        
        console.log('Колонка number в таблице cabinets успешно обновлена.');
      }
    }
    
    // Проверяем наличие колонки name
    if (!existingColumns.includes('name')) {
      console.log('Колонка name отсутствует в таблице cabinets, добавляем её...');
      await pool.query(`
        ALTER TABLE cabinets ADD COLUMN name VARCHAR(100) NULL;
      `);
      
      // Заполняем данные на основе id или number, если оно существует
      if (existingColumns.includes('number')) {
        await pool.query(`
          UPDATE cabinets SET name = 'Кабинет ' || number
        `);
      } else {
        await pool.query(`
          UPDATE cabinets SET name = 'Кабинет ' || id::text;
        `);
      }
      
      // Устанавливаем NOT NULL после заполнения данными
      await pool.query(`
        ALTER TABLE cabinets ALTER COLUMN name SET NOT NULL;
      `);
      
      console.log('Колонка name успешно добавлена в таблицу cabinets и заполнена данными.');
    } else {
      console.log('Колонка name уже существует в таблице cabinets.');
    }
    
    // Проверяем наличие колонки floor
    if (!existingColumns.includes('floor')) {
      console.log('Колонка floor отсутствует в таблице cabinets, добавляем её...');
      await pool.query(`
        ALTER TABLE cabinets ADD COLUMN floor INTEGER DEFAULT 1 NOT NULL;
      `);
      console.log('Колонка floor успешно добавлена в таблицу cabinets.');
    }
    
    // Проверяем наличие колонки capacity
    if (!existingColumns.includes('capacity')) {
      console.log('Колонка capacity отсутствует в таблице cabinets, добавляем её...');
      await pool.query(`
        ALTER TABLE cabinets ADD COLUMN capacity INTEGER DEFAULT 25 NOT NULL;
      `);
      console.log('Колонка capacity успешно добавлена в таблицу cabinets.');
    }
    
    console.log('Структура таблицы cabinets успешно обновлена.');
    
  } catch (error) {
    console.error('Ошибка при проверке/добавлении колонок в таблицу cabinets:', error);
    console.error('Детали ошибки:', error.message);
  }
}

// Запуск сервера
app.listen(port, async () => {
    console.log(`Сервер запущен на порту ${port}`);
    
    // Проверяем и добавляем колонку status в таблицу vacation_periods при запуске
    await ensureVacationStatusColumn();
    
    // Проверяем и добавляем колонку name в таблицу shifts при запуске
    await ensureShiftsNameColumn();
    
    // Проверяем и обновляем структуру таблицы cabinets при запуске
    await ensureCabinetsColumns();
    
    // Проверяем и создаем таблицу admin_logs при запуске
    await ensureAdminLogsTable();
});

// Получение информации о текущем пользователе
app.get('/api/user/me', authenticateToken, async (req, res) => {
  try {
    console.log('Получен запрос на получение данных текущего пользователя', { userId: req.userId });
    
    const userId = req.userId;
    if (!userId) {
      return res.status(401).json({ error: 'Пользователь не авторизован' });
    }
    
    const result = await pool.query(
      'SELECT id, name, email, role FROM users WHERE id = $1',
      [userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Пользователь не найден' });
    }
    
    const user = result.rows[0];
    console.log('Данные пользователя найдены:', user);
    
    res.json(user);
  } catch (error) {
    console.error('Ошибка при получении данных пользователя:', error);
    res.status(500).json({ error: 'Ошибка сервера при получении данных пользователя' });
  }
});

// Эндпоинт для получения информации о текущей неделе
app.get("/api/surveys/current-week", authenticateToken, async (req, res) => {
    try {
        const weekStart = getCurrentWeekStart();
        const nextReset = new Date(weekStart.getTime() + 7 * 24 * 60 * 60 * 1000);
        const now = new Date();
        
        res.json({
            currentWeekStart: weekStart.toISOString().split('T')[0],
            currentWeekEnd: new Date(nextReset.getTime() - 1).toISOString().split('T')[0], // Конец текущей недели (воскресенье)
            nextResetDate: nextReset.toISOString().split('T')[0],
            daysUntilReset: Math.ceil((nextReset - now) / (1000 * 60 * 60 * 24)),
            hoursUntilReset: Math.ceil((nextReset - now) / (1000 * 60 * 60))
        });
    } catch (error) {
        console.error("Ошибка при получении информации о текущей неделе:", error);
        res.status(500).json({ error: "Ошибка при получении информации о текущей неделе" });
    }
});

// Эндпоинт для получения результатов анализа опроса пользователя
app.get("/api/user/survey-status", authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const weekStart = getCurrentWeekStart();
        
        // Проверяем, есть ли ответы пользователя на еженедельный опрос за текущую неделю
        const hasResponse = await pool.query(
            `SELECT EXISTS (
                SELECT 1 
                FROM survey_responses sr
                JOIN surveys s ON sr.survey_id = s.id
                WHERE sr.user_id = $1 
                AND s.type = 'weekly'
                AND sr.created_at >= $2
            ) as has_responded`,
            [userId, weekStart]
        );
        
        if (!hasResponse.rows[0].has_responded) {
            // Если опрос не пройден, возвращаем специальный статус
            return res.json({ 
                status: "not_completed", 
                score: -1,
                message: "Анкетирование не пройдено на этой неделе"
            });
        }
        
        // Получаем ID последнего еженедельного опроса
        const surveyResult = await pool.query(
            `SELECT id FROM surveys
             WHERE type = 'weekly'
             ORDER BY created_at DESC
             LIMIT 1`
        );
        
        if (surveyResult.rows.length === 0) {
            return res.status(404).json({ error: "Активный еженедельный опрос не найден" });
        }
        
        const surveyId = surveyResult.rows[0].id;
        
        // Получаем ответы пользователя
        const responsesResult = await pool.query(
            `SELECT sr.question_id, sr.answer_text, sq.question_text 
             FROM survey_responses sr
             JOIN survey_questions sq ON sr.question_id = sq.id
             WHERE sr.survey_id = $1 AND sr.user_id = $2
             AND sr.created_at >= $3`,
            [surveyId, userId, weekStart]
        );
        
        if (responsesResult.rows.length === 0) {
            return res.json({ 
                status: "incomplete", 
                score: 0,
                message: "Недостаточно ответов для анализа"
            });
        }
        
        // Анализируем ответы и рассчитываем общий балл
        let totalScore = 0;
        let maxPossibleScore = 0;
        
        for (const response of responsesResult.rows) {
            const questionText = response.question_text.toLowerCase();
            const answer = response.answer_text;
            
            // Стресс
            if (questionText.includes('стресс')) {
                maxPossibleScore += 10;
                if (answer === 'very-low') totalScore += 10;
                else if (answer === 'low') totalScore += 7;
                else if (answer === 'medium') totalScore += 4;
                else if (answer === 'high') totalScore += 1;
            }
            // Настроение (1-10)
            else if (questionText.includes('настроени')) {
                maxPossibleScore += 10;
                const mood = parseInt(answer);
                if (!isNaN(mood) && mood >= 1 && mood <= 10) {
                    totalScore += mood;
                }
            }
            // Сон
            else if (questionText.includes('спали')) {
                maxPossibleScore += 10;
                if (answer === 'more-8') totalScore += 10;
                else if (answer === '7-8') totalScore += 8;
                else if (answer === '4-6') totalScore += 4;
                else if (answer === 'less-4') totalScore += 1;
            }
            // Физическая усталость
            else if (questionText.includes('физическ') && questionText.includes('усталость')) {
                maxPossibleScore += 10;
                if (answer === 'no') totalScore += 10;
                else if (answer === 'yes') totalScore += 2;
            }
            // Эмоциональное выгорание
            else if (questionText.includes('выгорани')) {
                maxPossibleScore += 10;
                if (answer === 'no') totalScore += 10;
                else if (answer === 'yes') totalScore += 1;
            }
            // Хобби
            else if (questionText.includes('хобби')) {
                maxPossibleScore += 10;
                if (answer === 'yes') totalScore += 10;
                else if (answer === 'no') totalScore += 3;
            }
            // Сложности с коллегами
            else if (questionText.includes('общении с коллегами')) {
                maxPossibleScore += 10;
                if (answer === 'no') totalScore += 10;
                else if (answer === 'yes') totalScore += 3;
            }
            // Концентрация
            else if (questionText.includes('концентрац')) {
                maxPossibleScore += 10;
                if (answer === 'no') totalScore += 10;
                else if (answer === 'yes') totalScore += 3;
            }
        }
        
        // Рассчитываем итоговый процент
        const finalScore = maxPossibleScore > 0 ? Math.round((totalScore / maxPossibleScore) * 100) : 0;
        
        // Определяем статус на основе балла
        let status;
        let message;
        
        if (finalScore >= 80) {
            status = "excellent";
            message = "Отличное психологическое состояние";
        } else if (finalScore >= 60) {
            status = "good";
            message = "Хорошее психологическое состояние";
        } else if (finalScore >= 40) {
            status = "moderate";
            message = "Удовлетворительное психологическое состояние";
        } else if (finalScore >= 20) {
            status = "poor";
            message = "Плохое психологическое состояние";
        } else {
            status = "critical";
            message = "Критическое психологическое состояние";
        }
        
        res.json({
            status,
            score: finalScore,
            message,
            lastUpdated: new Date().toISOString()
        });
    } catch (error) {
        console.error("Ошибка при получении результатов анализа:", error);
        res.status(500).json({ error: "Ошибка при получении результатов анализа" });
    }
});

// Эндпоинт для отмены утвержденного отпуска
app.post('/api/admin/vacations/:id/cancel', isAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const adminId = req.user.id;

    // Проверяем существование отпуска и его статус
    const vacation = await pool.query(
      'SELECT * FROM vacation_periods WHERE id = $1',
      [id]
    );

    if (vacation.rows.length === 0) {
      return res.status(404).json({ error: 'Отпуск не найден' });
    }

    if (vacation.rows[0].status !== 'approved') {
      return res.status(400).json({ error: 'Можно отменять только утвержденные отпуска' });
    }

    // Обновляем статус отпуска
    await pool.query(
      'UPDATE vacation_periods SET status = $1 WHERE id = $2',
      ['pending', id]
    );

    // Логируем действие администратора
    await logAdminAction(
      adminId,
      'cancel_vacation',
      id,
      'vacation',
      `Отмена утвержденного отпуска пользователя ${vacation.rows[0].user_id}`
    );

    res.json({ message: 'Отпуск успешно отменен' });
  } catch (error) {
    console.error('Ошибка при отмене отпуска:', error);
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  }
});
