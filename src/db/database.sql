-- =============================================================================
-- СХЕМА БАЗЫ ДАННЫХ (СТРУКТУРА)
-- =============================================================================

-- Создание расширений
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Функция для проверки необходимости полной переинициализации
CREATE OR REPLACE FUNCTION should_reinitialize()
RETURNS BOOLEAN AS $$
BEGIN
    RETURN current_setting('app.reinitialize', true) = 'true';
END;
$$ LANGUAGE plpgsql;

-- Удаление существующих таблиц и зависимостей только при необходимости
DO $$
BEGIN
    IF should_reinitialize() THEN
        DROP TABLE IF EXISTS file_attachments CASCADE;
        DROP TABLE IF EXISTS files CASCADE;
        DROP TABLE IF EXISTS support_assignments CASCADE;
        DROP TABLE IF EXISTS support_messages CASCADE;
        DROP TABLE IF EXISTS support_requests CASCADE;
        DROP TABLE IF EXISTS survey_responses CASCADE;
        DROP TABLE IF EXISTS survey_questions CASCADE;
        DROP TABLE IF EXISTS surveys CASCADE;
        DROP TABLE IF EXISTS bookings CASCADE;
        DROP TABLE IF EXISTS vacation_periods CASCADE;
        DROP TABLE IF EXISTS weekend_selections CASCADE;
        DROP TABLE IF EXISTS users CASCADE;
        DROP TABLE IF EXISTS shifts CASCADE;
        DROP TABLE IF EXISTS cabinets CASCADE;
        DROP TABLE IF EXISTS seats CASCADE;

        -- Удаление существующих функций и триггеров
        DROP FUNCTION IF EXISTS update_updated_at_column() CASCADE;
        DROP FUNCTION IF EXISTS check_unique_email() CASCADE;
    END IF;
END $$;

-- Проверяем и удаляем функцию check_unique_email, если она существует
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'check_unique_email') THEN
        DROP FUNCTION IF EXISTS check_unique_email() CASCADE;
    END IF;
END $$;

-- Таблица для пользователей
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'user',
    avatar_url TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Таблица для смен
CREATE TABLE IF NOT EXISTS shifts (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL,
    start_time TIME NOT NULL,
    end_time TIME NOT NULL,
    time VARCHAR(50),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Таблица для кабинетов
CREATE TABLE IF NOT EXISTS cabinets (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    floor INTEGER NOT NULL,
    capacity INTEGER NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Таблица для мест в кабинетах
CREATE TABLE IF NOT EXISTS seats (
    id SERIAL PRIMARY KEY,
    cabinet_id INTEGER REFERENCES cabinets(id) ON DELETE CASCADE,
    seat_number VARCHAR(50) NOT NULL,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(cabinet_id, seat_number)
);

-- Таблица для бронирования мест
CREATE TABLE IF NOT EXISTS bookings (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    cabinet_id INTEGER REFERENCES cabinets(id) ON DELETE CASCADE,
    seat_id INTEGER REFERENCES seats(id) ON DELETE CASCADE,
    shift_id INTEGER REFERENCES shifts(id) ON DELETE CASCADE,
    booking_date DATE NOT NULL,
    week_start DATE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(cabinet_id, shift_id, seat_id, booking_date)
);

-- Добавляем колонку week_start, если она не существует
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                  WHERE table_name = 'bookings' AND column_name = 'week_start') THEN
        ALTER TABLE bookings ADD COLUMN week_start DATE NOT NULL;
    END IF;
END $$;

-- Обновляем существующие бронирования, устанавливая week_start
UPDATE bookings 
SET week_start = date_trunc('week', booking_date)
WHERE week_start IS NULL;

-- Создаем индекс для оптимизации запросов по week_start
CREATE INDEX IF NOT EXISTS idx_bookings_week_start ON bookings(week_start);

-- Создаем функцию для автоматического удаления старых бронирований
CREATE OR REPLACE FUNCTION delete_old_bookings()
RETURNS void AS $$
BEGIN
    -- Удаляем бронирования, которые старше текущей недели
    DELETE FROM bookings 
    WHERE week_start < date_trunc('week', CURRENT_DATE);
END;
$$ LANGUAGE plpgsql;

-- Создаем триггер для автоматического удаления старых бронирований
CREATE OR REPLACE FUNCTION trigger_delete_old_bookings()
RETURNS TRIGGER AS $$
BEGIN
    PERFORM delete_old_bookings();
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Создаем триггер, который будет срабатывать каждый день в 00:00
DROP TRIGGER IF EXISTS delete_old_bookings_trigger ON bookings;
CREATE TRIGGER delete_old_bookings_trigger
    AFTER INSERT OR UPDATE ON bookings
    EXECUTE FUNCTION trigger_delete_old_bookings();

-- Таблица для опросов
CREATE TABLE IF NOT EXISTS surveys (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    type VARCHAR(50) DEFAULT 'general',
    created_by INTEGER REFERENCES users(id),
    is_active BOOLEAN DEFAULT true,
    start_date TIMESTAMP WITH TIME ZONE,
    end_date TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Таблица для вопросов опроса
CREATE TABLE IF NOT EXISTS survey_questions (
    id SERIAL PRIMARY KEY,
    survey_id INTEGER REFERENCES surveys(id) ON DELETE CASCADE,
    question_text TEXT NOT NULL,
    question_type VARCHAR(50) NOT NULL,
    options JSONB,
    is_required BOOLEAN DEFAULT false,
    order_index INTEGER NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Таблица для ответов на опрос
CREATE TABLE IF NOT EXISTS survey_responses (
    id SERIAL PRIMARY KEY,
    survey_id INTEGER REFERENCES surveys(id) ON DELETE CASCADE,
    question_id INTEGER REFERENCES survey_questions(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    answer_text TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(survey_id, question_id, user_id)
);

-- Таблица для запросов на психологическую поддержку
CREATE TABLE IF NOT EXISTS support_requests (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    priority VARCHAR(50) NOT NULL DEFAULT 'medium',
    category VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Таблица для сообщений в запросе поддержки
CREATE TABLE IF NOT EXISTS support_messages (
    id SERIAL PRIMARY KEY,
    request_id INTEGER REFERENCES support_requests(id) ON DELETE CASCADE,
    sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    message_text TEXT NOT NULL,
    attachments JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Таблица для назначения специалистов на запросы
CREATE TABLE IF NOT EXISTS support_assignments (
    id SERIAL PRIMARY KEY,
    request_id INTEGER REFERENCES support_requests(id) ON DELETE CASCADE,
    specialist_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(request_id)
);

-- Таблица для файлов
CREATE TABLE IF NOT EXISTS files (
    id SERIAL PRIMARY KEY,
    filename VARCHAR(255) NOT NULL,
    original_name VARCHAR(255) NOT NULL,
    mime_type VARCHAR(100) NOT NULL,
    size INTEGER NOT NULL,
    path TEXT NOT NULL,
    uploaded_by INTEGER REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Таблица для связей файлов с сущностями
CREATE TABLE IF NOT EXISTS file_attachments (
    id SERIAL PRIMARY KEY,
    file_id INTEGER REFERENCES files(id) ON DELETE CASCADE,
    entity_type VARCHAR(50) NOT NULL,
    entity_id INTEGER NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Таблица для периодов отпуска
CREATE TABLE IF NOT EXISTS vacation_periods (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    reason TEXT,
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', '0', '1', '2', 'approved', 'rejected')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Таблица для выбора выходных дней
CREATE TABLE IF NOT EXISTS weekend_selections (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    week_start DATE NOT NULL,
    selected_day INTEGER NOT NULL CHECK (selected_day BETWEEN 1 AND 7),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, week_start, selected_day)
);

-- Таблица для записи к психологу
CREATE TABLE IF NOT EXISTS psychologist_appointments (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    appointment_date DATE NOT NULL,
    appointment_time TIME NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(appointment_date, appointment_time)
);

-- Индексы для оптимизации запросов
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_surveys_created_by ON surveys(created_by);
CREATE INDEX IF NOT EXISTS idx_survey_questions_survey_id ON survey_questions(survey_id);
CREATE INDEX IF NOT EXISTS idx_survey_responses_survey_id ON survey_responses(survey_id);
CREATE INDEX IF NOT EXISTS idx_survey_responses_user_id ON survey_responses(user_id);
CREATE INDEX IF NOT EXISTS idx_survey_responses_question_id ON survey_responses(question_id);
CREATE INDEX IF NOT EXISTS idx_support_requests_user_id ON support_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_support_requests_status ON support_requests(status);
CREATE INDEX IF NOT EXISTS idx_support_messages_request_id ON support_messages(request_id);
CREATE INDEX IF NOT EXISTS idx_support_messages_sender_id ON support_messages(sender_id);
CREATE INDEX IF NOT EXISTS idx_support_assignments_request_id ON support_assignments(request_id);
CREATE INDEX IF NOT EXISTS idx_support_assignments_specialist_id ON support_assignments(specialist_id);
CREATE INDEX IF NOT EXISTS idx_files_uploaded_by ON files(uploaded_by);
CREATE INDEX IF NOT EXISTS idx_file_attachments_file_id ON file_attachments(file_id);
CREATE INDEX IF NOT EXISTS idx_file_attachments_entity ON file_attachments(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_vacation_periods_user_id ON vacation_periods(user_id);
CREATE INDEX IF NOT EXISTS idx_vacation_periods_dates ON vacation_periods(start_date, end_date);
CREATE INDEX IF NOT EXISTS idx_weekend_selections_user_id ON weekend_selections(user_id);
CREATE INDEX IF NOT EXISTS idx_weekend_selections_week ON weekend_selections(week_start);
CREATE INDEX IF NOT EXISTS idx_bookings_user_id ON bookings(user_id);
CREATE INDEX IF NOT EXISTS idx_bookings_cabinet_id ON bookings(cabinet_id);
CREATE INDEX IF NOT EXISTS idx_bookings_seat_id ON bookings(seat_id);
CREATE INDEX IF NOT EXISTS idx_bookings_shift_id ON bookings(shift_id);
CREATE INDEX IF NOT EXISTS idx_bookings_date ON bookings(booking_date);
CREATE INDEX IF NOT EXISTS idx_seats_cabinet_id ON seats(cabinet_id);
CREATE INDEX IF NOT EXISTS idx_psychologist_appointments_user_id ON psychologist_appointments(user_id);
CREATE INDEX IF NOT EXISTS idx_psychologist_appointments_date ON psychologist_appointments(appointment_date);
CREATE INDEX IF NOT EXISTS idx_psychologist_appointments_status ON psychologist_appointments(status);

-- Функция для автоматического обновления updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Триггеры для автоматического обновления updated_at
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'update_users_updated_at') THEN
        CREATE TRIGGER update_users_updated_at
        BEFORE UPDATE ON users
        FOR EACH ROW
        EXECUTE PROCEDURE update_updated_at_column();
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'update_bookings_updated_at') THEN
        CREATE TRIGGER update_bookings_updated_at
        BEFORE UPDATE ON bookings
        FOR EACH ROW
        EXECUTE PROCEDURE update_updated_at_column();
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'update_surveys_updated_at') THEN
        CREATE TRIGGER update_surveys_updated_at
        BEFORE UPDATE ON surveys
        FOR EACH ROW
        EXECUTE PROCEDURE update_updated_at_column();
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'update_support_requests_updated_at') THEN
        CREATE TRIGGER update_support_requests_updated_at
        BEFORE UPDATE ON support_requests
        FOR EACH ROW
        EXECUTE PROCEDURE update_updated_at_column();
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'update_vacation_periods_updated_at') THEN
        CREATE TRIGGER update_vacation_periods_updated_at
        BEFORE UPDATE ON vacation_periods
        FOR EACH ROW
        EXECUTE PROCEDURE update_updated_at_column();
    END IF;
END $$;

-- Таблица для логирования действий администратора
CREATE TABLE IF NOT EXISTS admin_logs (
    id SERIAL PRIMARY KEY,
    admin_id INT NOT NULL,
    action VARCHAR(100) NOT NULL,
    entity_id INT,
    entity_type VARCHAR(50),
    details JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- НАЧАЛЬНЫЕ ДАННЫЕ
-- =============================================================================

-- Добавление смен
DO $$
BEGIN
  -- Проверяем наличие колонки time в таблице shifts
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'shifts' AND column_name = 'time') THEN
    -- Если есть колонка time, проверяем наличие колонки name
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'shifts' AND column_name = 'name') THEN
      -- Есть обе колонки time и name, заполняем все
      INSERT INTO shifts (name, start_time, end_time, time) VALUES
      ('Утренняя', '08:00', '12:00', '08:00'),
      ('Дневная', '13:00', '17:00', '13:00'),
      ('Вечерняя', '18:00', '22:00', '18:00')
      ON CONFLICT DO NOTHING;
    ELSE
      -- Есть только time, но нет name
      INSERT INTO shifts (start_time, end_time, time) VALUES
      ('08:00', '12:00', '08:00'),
      ('13:00', '17:00', '13:00'),
      ('18:00', '22:00', '18:00')
      ON CONFLICT DO NOTHING;
    END IF;
  ELSE
    -- Нет колонки time, проверяем наличие name
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'shifts' AND column_name = 'name') THEN
      -- Есть name, но нет time
      INSERT INTO shifts (name, start_time, end_time) VALUES
      ('Утренняя', '08:00', '12:00'),
      ('Дневная', '13:00', '17:00'),
      ('Вечерняя', '18:00', '22:00')
      ON CONFLICT DO NOTHING;
    ELSE
      -- Нет ни time, ни name, используем только start_time и end_time
      INSERT INTO shifts (start_time, end_time) VALUES
      ('08:00', '12:00'),
      ('13:00', '17:00'),
      ('18:00', '22:00')
      ON CONFLICT DO NOTHING;
    END IF;
  END IF;
END $$;

-- Добавление кабинетов
DO $$
BEGIN
  -- Проверяем наличие колонок name, floor и capacity в таблице cabinets
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'cabinets' AND column_name = 'name') AND
     EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'cabinets' AND column_name = 'floor') AND
     EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'cabinets' AND column_name = 'capacity') THEN
    
    -- Колонки существуют, используем их
    INSERT INTO cabinets (name, floor, capacity) VALUES
    ('Кабинет А', 1, 25),
    ('Кабинет Б', 1, 25)
    ON CONFLICT DO NOTHING;
  ELSE
    -- Не все колонки существуют, проверяем, что таблица существует
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'cabinets') THEN
      -- Таблица существует, но не имеет всех нужных колонок
      -- Просто добавляем записи с доступными колонками, остальные будут добавлены в функции ensureCabinetsColumns
      INSERT INTO cabinets (id) 
      SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM cabinets WHERE id = 1)
      UNION ALL
      SELECT 2 WHERE NOT EXISTS (SELECT 1 FROM cabinets WHERE id = 2);
    END IF;
  END IF;
END $$;

-- Добавление мест в кабинеты
DO $$
BEGIN
  -- Проверяем, что таблица seats существует и имеет колонку cabinet_id и seat_number
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'seats') AND
     EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'seats' AND column_name = 'cabinet_id') AND
     EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'seats' AND column_name = 'seat_number') THEN
    
    -- Проверяем, что записи в таблице cabinets существуют
    IF EXISTS (SELECT 1 FROM cabinets WHERE id = 1) AND EXISTS (SELECT 1 FROM cabinets WHERE id = 2) THEN
      
      -- Проверяем, что места ещё не добавлены
      IF NOT EXISTS (SELECT 1 FROM seats WHERE cabinet_id = 1 AND seat_number = '1') THEN
        -- Добавляем места для кабинета 1
        INSERT INTO seats (cabinet_id, seat_number) VALUES
        (1, '1'), (1, '2'), (1, '3'), (1, '4'), (1, '5'),
        (1, '6'), (1, '7'), (1, '8'), (1, '9'), (1, '10'),
        (1, '11'), (1, '12'), (1, '13'), (1, '14'), (1, '15'),
        (1, '16'), (1, '17'), (1, '18'), (1, '19'), (1, '20'),
        (1, '21'), (1, '22'), (1, '23'), (1, '24'), (1, '25')
        ON CONFLICT DO NOTHING;
      END IF;
      
      IF NOT EXISTS (SELECT 1 FROM seats WHERE cabinet_id = 2 AND seat_number = '1') THEN
        -- Добавляем места для кабинета 2
        INSERT INTO seats (cabinet_id, seat_number) VALUES
        (2, '1'), (2, '2'), (2, '3'), (2, '4'), (2, '5'),
        (2, '6'), (2, '7'), (2, '8'), (2, '9'), (2, '10'),
        (2, '11'), (2, '12'), (2, '13'), (2, '14'), (2, '15'),
        (2, '16'), (2, '17'), (2, '18'), (2, '19'), (2, '20'),
        (2, '21'), (2, '22'), (2, '23'), (2, '24'), (2, '25')
        ON CONFLICT DO NOTHING;
      END IF;
      
    END IF;
  END IF;
END $$; 