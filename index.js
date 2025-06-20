require('dotenv').config();
const http = require('http');
const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');
const { URL } = require('url');
const TelegramBot = require('node-telegram-bot-api');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const PORT = process.env.PORT || 3000;
const TELEGRAM_TOKEN = process.env.TELEGRAM_TOKEN;
const TELEGRAM_BOT_USERNAME = process.env.TELEGRAM_BOT_USERNAME;
const JWT_SECRET = process.env.JWT_SECRET;
const DOMAIN = process.env.DOMAIN || `http://localhost:${PORT}`;

const dbConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};

const pool = mysql.createPool(dbConfig);
const bot = new TelegramBot(TELEGRAM_TOKEN, { polling: true });

// Helper functions
async function hashPassword(password) {
    const saltRounds = 10;
    return await bcrypt.hash(password, saltRounds);
}

async function comparePasswords(password, hash) {
    return await bcrypt.compare(password, hash);
}

function generateToken(user) {
    return jwt.sign(
        { id: user.id, email: user.email },
        JWT_SECRET,
        { expiresIn: '24h' }
    );
}

function verifyToken(token) {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (err) {
        console.error('Token verification failed:', err);
        return null;
    }
}

// Database operations
async function getItems(userId) {
    const connection = await pool.getConnection();
    try {
        const [rows] = await connection.query(
            'SELECT id, text FROM items WHERE user_id = ? ORDER BY created_at DESC',
            [userId]
        );
        return rows;
    } finally {
        connection.release();
    }
}

async function addItem(text, userId) {
    const connection = await pool.getConnection();
    try {
        const [result] = await connection.query(
            'INSERT INTO items (text, user_id) VALUES (?, ?)',
            [text.trim(), userId]
        );
        return result.insertId;
    } finally {
        connection.release();
    }
}

async function deleteItem(id, userId) {
    const connection = await pool.getConnection();
    try {
        const [result] = await connection.query(
            'DELETE FROM items WHERE id = ? AND user_id = ?',
            [id, userId]
        );
        return result.affectedRows > 0;
    } finally {
        connection.release();
    }
}

async function updateItem(id, text, userId) {
    const connection = await pool.getConnection();
    try {
        const [result] = await connection.query(
            'UPDATE items SET text = ? WHERE id = ? AND user_id = ?',
            [text, id, userId]
        );
        return result.affectedRows > 0;
    } finally {
        connection.release();
    }
}

// User management
async function getUserByEmail(email) {
    const connection = await pool.getConnection();
    try {
        const [rows] = await connection.query(
            'SELECT * FROM users WHERE email = ?',
            [email]
        );
        return rows[0];
    } finally {
        connection.release();
    }
}

async function getUserById(id) {
    const connection = await pool.getConnection();
    try {
        const [rows] = await connection.query(
            'SELECT * FROM users WHERE id = ?',
            [id]
        );
        return rows[0];
    } finally {
        connection.release();
    }
}

async function getUserByTelegramId(telegramId) {
    const connection = await pool.getConnection();
    try {
        const [rows] = await connection.query(
            'SELECT * FROM users WHERE telegram_id = ?',
            [telegramId]
        );
        return rows[0];
    } finally {
        connection.release();
    }
}

async function createUser(email, password, firstName, lastName = '') {
    const connection = await pool.getConnection();
    try {
        const passwordHash = await hashPassword(password);
        const [result] = await connection.query(
            'INSERT INTO users (email, password_hash, first_name, last_name) VALUES (?, ?, ?, ?)',
            [email, passwordHash, firstName, lastName]
        );
        return {
            id: result.insertId,
            email,
            first_name: firstName,
            last_name: lastName
        };
    } finally {
        connection.release();
    }
}

// HTML generation
async function generateListHtml(userId) {
    try {
        const items = await getItems(userId);
        if (!items || items.length === 0) {
            return { html: '', count: 0 };
        }

        const html = items.map((item, index) => `
            <li class="task-item" id="task-${item.id}">
                <div class="task-number">${index + 1}</div>
                <div class="task-text">${escapeHtml(item.text)}</div>
                <div class="task-actions">
                    <button class="btn-action btn-edit" onclick="enableEdit(${item.id}, '${escapeSingleQuotes(item.text)}')">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="btn-action btn-delete" onclick="deleteTask(${item.id})">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </li>
        `).join('');

        return { html, count: items.length };
    } catch (err) {
        console.error('Error generating list HTML:', err);
        throw err;
    }
}

function escapeHtml(text) {
    if (typeof text !== 'string') return '';
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function escapeSingleQuotes(text) {
    if (typeof text !== 'string') return '';
    return text.replace(/'/g, "\\'");
}

// Request handling
async function handleRequest(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }

    const url = new URL(req.url, `http://${req.headers.host}`);

    try {
        // Serve static files
        if (url.pathname === '/' && req.method === 'GET') {
            const html = await fs.promises.readFile(path.join(__dirname, 'index.html'), 'utf8');
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(html);
            return;
        }

        if (url.pathname === '/telegram-login' && req.method === 'GET') {
            let html = await fs.promises.readFile(path.join(__dirname, 'telegram-login.html'), 'utf8');
            html = html.replace(/data-telegram-login="[^"]*"/, `data-telegram-login="${TELEGRAM_BOT_USERNAME}"`);
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(html);
            return;
        }

        // API endpoints
        if (req.method === 'POST' || req.method === 'PUT' || req.method === 'DELETE') {
            let body = '';
            req.on('data', chunk => body += chunk.toString());
            
            req.on('end', async () => {
                try {
                    const data = body ? JSON.parse(body) : {};
                    const token = req.headers.authorization?.split(' ')[1];
                    
                    if (url.pathname === '/login') {
                        const { email, password } = data;
                        
                        if (!email || !password) {
                            return sendJsonResponse(res, 400, {
                                success: false,
                                error: 'Email and password are required'
                            });
                        }

                        const user = await getUserByEmail(email);
                        if (!user || !(await comparePasswords(password, user.password_hash))) {
                            return sendJsonResponse(res, 401, {
                                success: false,
                                error: 'Invalid email or password'
                            });
                        }

                        const authToken = generateToken(user);
                        return sendJsonResponse(res, 200, {
                            success: true,
                            token: authToken,
                            user: {
                                id: user.id,
                                email: user.email,
                                firstName: user.first_name,
                                lastName: user.last_name,
                                telegramLinked: !!user.telegram_id
                            }
                        });
                    }
                    else if (url.pathname === '/register') {
                        const { email, password, firstName, lastName } = data;
                        
                        if (!email || !password || !firstName) {
                            return sendJsonResponse(res, 400, {
                                success: false,
                                error: 'Email, password and first name are required'
                            });
                        }

                        if (password.length < 6) {
                            return sendJsonResponse(res, 400, {
                                success: false,
                                error: 'Password must be at least 6 characters'
                            });
                        }

                        const existingUser = await getUserByEmail(email);
                        if (existingUser) {
                            return sendJsonResponse(res, 400, {
                                success: false,
                                error: 'Email already registered'
                            });
                        }

                        const user = await createUser(email, password, firstName, lastName);
                        const authToken = generateToken(user);

                        return sendJsonResponse(res, 200, {
                            success: true,
                            token: authToken,
                            user: {
                                id: user.id,
                                email: user.email,
                                firstName: user.first_name,
                                lastName: user.last_name,
                                telegramLinked: false
                            }
                        });
                    }
                    else if (url.pathname === '/add') {
                        if (!token) {
                            return sendJsonResponse(res, 401, { 
                                success: false, 
                                error: 'Authentication required' 
                            });
                        }

                        const decoded = verifyToken(token);
                        if (!decoded) {
                            return sendJsonResponse(res, 401, { 
                                success: false, 
                                error: 'Invalid token' 
                            });
                        }

                        const { text } = data;
                        if (!text || typeof text !== 'string' || text.trim() === '') {
                            return sendJsonResponse(res, 400, { 
                                success: false, 
                                error: 'Task text cannot be empty' 
                            });
                        }

                        await addItem(text.trim(), decoded.id);
                        const { html, count } = await generateListHtml(decoded.id);

                        return sendJsonResponse(res, 200, { 
                            success: true, 
                            html, 
                            count,
                            message: 'Task added successfully'
                        });
                    }
                    else if (url.pathname.startsWith('/delete/') && req.method === 'DELETE') {
                        if (!token) {
                            return sendJsonResponse(res, 401, { 
                                success: false, 
                                error: 'Authentication required' 
                            });
                        }

                        const decoded = verifyToken(token);
                        if (!decoded) {
                            return sendJsonResponse(res, 401, { 
                                success: false, 
                                error: 'Invalid token' 
                            });
                        }

                        const id = parseInt(url.pathname.split('/')[2]);
                        if (isNaN(id)) {
                            return sendJsonResponse(res, 400, { 
                                success: false, 
                                error: 'Invalid task ID' 
                            });
                        }

                        const deleted = await deleteItem(id, decoded.id);
                        if (!deleted) {
                            return sendJsonResponse(res, 404, { 
                                success: false, 
                                error: 'Task not found' 
                            });
                        }

                        const { html, count } = await generateListHtml(decoded.id);
                        return sendJsonResponse(res, 200, { 
                            success: true, 
                            html, 
                            count,
                            message: 'Task deleted successfully'
                        });
                    }
                    else if (url.pathname.startsWith('/edit/') && req.method === 'PUT') {
                        if (!token) {
                            return sendJsonResponse(res, 401, { 
                                success: false, 
                                error: 'Authentication required' 
                            });
                        }

                        const decoded = verifyToken(token);
                        if (!decoded) {
                            return sendJsonResponse(res, 401, { 
                                success: false, 
                                error: 'Invalid token' 
                            });
                        }

                        const id = parseInt(url.pathname.split('/')[2]);
                        if (isNaN(id)) {
                            return sendJsonResponse(res, 400, { 
                                success: false, 
                                error: 'Invalid task ID' 
                            });
                        }

                        const { text } = data;
                        if (!text || typeof text !== 'string' || text.trim() === '') {
                            return sendJsonResponse(res, 400, { 
                                success: false, 
                                error: 'Task text cannot be empty' 
                            });
                        }

                        const updated = await updateItem(id, text.trim(), decoded.id);
                        if (!updated) {
                            return sendJsonResponse(res, 404, { 
                                success: false, 
                                error: 'Task not found' 
                            });
                        }

                        const { html, count } = await generateListHtml(decoded.id);
                        return sendJsonResponse(res, 200, { 
                            success: true, 
                            html, 
                            count,
                            message: 'Task updated successfully'
                        });
                    }
                    else if (url.pathname === '/telegram-callback' && req.method === 'POST') {
                        if (!token) {
                            return sendJsonResponse(res, 401, { 
                                success: false, 
                                error: 'Authentication required' 
                            });
                        }

                        const decoded = verifyToken(token);
                        if (!decoded) {
                            return sendJsonResponse(res, 401, { 
                                success: false, 
                                error: 'Invalid token' 
                            });
                        }

                        const { user: telegramUser } = data;
                        if (!telegramUser || !telegramUser.id) {
                            return sendJsonResponse(res, 400, { 
                                success: false, 
                                error: 'Invalid Telegram user data' 
                            });
                        }

                        const connection = await pool.getConnection();
                        try {
                            await connection.query(
                                'UPDATE users SET telegram_id = ?, first_name = ?, last_name = ?, username = ?, auth_date = ?, hash = ? WHERE id = ?',
                                [
                                    telegramUser.id,
                                    telegramUser.first_name,
                                    telegramUser.last_name || '',
                                    telegramUser.username || '',
                                    telegramUser.auth_date,
                                    telegramUser.hash,
                                    decoded.id
                                ]
                            );

                            // Notify user in Telegram
                            try {
                                await bot.sendMessage(
                                    telegramUser.id,
                                    "🎉 Ваш Telegram аккаунт успешно привязан к TaskMaster!\n\n" +
                                    "Теперь вы можете:\n" +
                                    "- Управлять задачами через бота\n" +
                                    "- Получать уведомления о новых задачах\n\n" +
                                    "Используйте /start для просмотра команд"
                                );
                            } catch (err) {
                                console.error('Error sending Telegram notification:', err);
                            }
                        } finally {
                            connection.release();
                        }

                        return sendJsonResponse(res, 200, { 
                            success: true,
                            telegramLinked: true
                        });
                    }

                    return sendJsonResponse(res, 404, { 
                        success: false, 
                        error: 'Endpoint not found' 
                    });
                } catch (err) {
                    console.error('API error:', err);
                    return sendJsonResponse(res, 500, { 
                        success: false, 
                        error: 'Internal server error' 
                    });
                }
            });
            return;
        }

        if (url.pathname === '/auth/check' && req.method === 'GET') {
            const token = req.headers.authorization?.split(' ')[1];
            if (!token) {
                return sendJsonResponse(res, 401, { 
                    authenticated: false 
                });
            }

            try {
                const decoded = verifyToken(token);
                if (!decoded) {
                    return sendJsonResponse(res, 401, { 
                        authenticated: false 
                    });
                }

                const user = await getUserById(decoded.id);
                if (!user) {
                    return sendJsonResponse(res, 401, { 
                        authenticated: false 
                    });
                }

                return sendJsonResponse(res, 200, {
                    authenticated: true,
                    user: {
                        id: user.id,
                        email: user.email,
                        firstName: user.first_name,
                        lastName: user.last_name,
                        telegramLinked: !!user.telegram_id
                    }
                });
            } catch (err) {
                return sendJsonResponse(res, 401, { 
                    authenticated: false 
                });
            }
        }

        if (url.pathname === '/list' && req.method === 'GET') {
            const token = req.headers.authorization?.split(' ')[1];
            if (!token) {
                return sendJsonResponse(res, 401, { 
                    success: false, 
                    error: 'Authentication required' 
                });
            }

            try {
                const decoded = verifyToken(token);
                if (!decoded) {
                    return sendJsonResponse(res, 401, { 
                        success: false, 
                        error: 'Invalid token' 
                    });
                }

                const { html, count } = await generateListHtml(decoded.id);
                return sendJsonResponse(res, 200, { 
                    success: true, 
                    html, 
                    count 
                });
            } catch (err) {
                console.error('Error getting task list:', err);
                return sendJsonResponse(res, 500, { 
                    success: false, 
                    error: 'Failed to load tasks' 
                });
            }
        }

        // Not found
        return sendJsonResponse(res, 404, { 
            success: false, 
            error: 'Endpoint not found' 
        });

    } catch (err) {
        console.error('Server error:', err);
        return sendJsonResponse(res, 500, { 
            success: false, 
            error: 'Internal server error' 
        });
    }
}

function sendJsonResponse(res, statusCode, data) {
    res.writeHead(statusCode, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data));
}

// Telegram bot handlers
const userStates = {};

bot.onText(/\/start/, async (msg) => {
    const chatId = msg.chat.id;
    try {
        const user = await getUserByTelegramId(chatId);
        
        if (user) {
            await bot.sendMessage(
                chatId,
                `👋 Привет, ${user.first_name || 'пользователь'}!\n\n` +
                `Ваш аккаунт успешно привязан к TaskMaster.\n\n` +
                `Доступные команды:\n` +
                `/list - Показать все задачи\n` +
                `/add [текст] - Добавить задачу\n` +
                `/edit [номер] - Редактировать задачу\n` +
                `/delete [номер] - Удалить задачу`,
                { parse_mode: 'Markdown' }
            );
        } else {
            await bot.sendMessage(
                chatId,
                `🔗 Для привязки аккаунта:\n\n` +
                `1. Перейдите на сайт ${DOMAIN}\n` +
                `2. Войдите в свой аккаунт\n` +
                `3. Нажмите "Привязать Telegram"\n\n` +
                `После этого вы сможете управлять задачами через бота!`
            );
        }
    } catch (err) {
        console.error('Error handling /start command:', err);
        await bot.sendMessage(chatId, '❗ Произошла ошибка. Пожалуйста, попробуйте позже.');
    }
});

bot.onText(/\/list/, async (msg) => {
    const chatId = msg.chat.id;
    try {
        const user = await getUserByTelegramId(chatId);
        if (!user) {
            return bot.sendMessage(chatId, '❌ Ваш аккаунт не привязан. Сначала привяжите его на сайте.');
        }

        const tasks = await getItems(user.id);
        if (tasks.length === 0) {
            return bot.sendMessage(chatId, '📭 У вас пока нет задач. Добавьте первую с помощью /add [текст]');
        }

        const taskList = tasks.map((task, index) => 
            `${index + 1}. ${task.text}\n` +
            `/edit_${task.id} - Редактировать\n` +
            `/delete_${task.id} - Удалить\n`
        ).join('\n');

        await bot.sendMessage(
            chatId,
            `📋 Ваши задачи:\n\n${taskList}`,
            { parse_mode: 'Markdown' }
        );
    } catch (err) {
        console.error('Error handling /list command:', err);
        await bot.sendMessage(chatId, '❗ Произошла ошибка при загрузке задач.');
    }
});

bot.onText(/\/add (.+)/, async (msg, match) => {
    const chatId = msg.chat.id;
    const text = match[1].trim();
    
    if (!text) {
        return bot.sendMessage(chatId, '❌ Укажите текст задачи: /add [текст]');
    }

    try {
        const user = await getUserByTelegramId(chatId);
        if (!user) {
            return bot.sendMessage(chatId, '❌ Ваш аккаунт не привязан. Сначала привяжите его на сайте.');
        }

        await addItem(text, user.id);
        await bot.sendMessage(chatId, `✅ Задача добавлена: "${text}"`);
    } catch (err) {
        console.error('Error handling /add command:', err);
        await bot.sendMessage(chatId, '❗ Произошла ошибка при добавлении задачи.');
    }
});

bot.onText(/\/edit_(\d+)/, async (msg, match) => {
    const chatId = msg.chat.id;
    const taskId = parseInt(match[1]);

    try {
        const user = await getUserByTelegramId(chatId);
        if (!user) {
            return bot.sendMessage(chatId, '❌ Ваш аккаунт не привязан. Сначала привяжите его на сайте.');
        }

        // Проверяем существование задачи
        const tasks = await getItems(user.id);
        const taskToEdit = tasks.find(task => task.id === taskId);

        if (!taskToEdit) {
            return bot.sendMessage(chatId, '❌ Задача не найдена.');
        }

        // Сохраняем состояние для редактирования
        userStates[chatId] = {
            action: 'edit',
            taskId: taskId
        };

        await bot.sendMessage(
            chatId,
            `✏️ Введите новый текст для задачи:\n\n"${taskToEdit.text}"`,
            { 
                reply_markup: {
                    force_reply: true,
                    selective: true
                }
            }
        );
    } catch (err) {
        console.error('Error handling /edit command:', err);
        await bot.sendMessage(chatId, '❗ Произошла ошибка при редактировании задачи.');
    }
});

// Обработчик ответа на запрос редактирования
bot.on('message', async (msg) => {
    if (!msg.text || !msg.reply_to_message) return;

    const chatId = msg.chat.id;
    const userState = userStates[chatId];

    if (userState && userState.action === 'edit') {
        const newText = msg.text.trim();
        if (!newText) {
            return bot.sendMessage(chatId, '❌ Текст задачи не может быть пустым.');
        }

        try {
            const user = await getUserByTelegramId(chatId);
            if (!user) {
                return bot.sendMessage(chatId, '❌ Ваш аккаунт не привязан. Сначала привяжите его на сайте.');
            }

            const updated = await updateItem(userState.taskId, newText, user.id);
            if (updated) {
                delete userStates[chatId];
                await bot.sendMessage(chatId, `✅ Задача успешно обновлена:\n\n"${newText}"`);
            } else {
                await bot.sendMessage(chatId, '❌ Не удалось обновить задачу.');
            }
        } catch (err) {
            console.error('Error handling edit reply:', err);
            await bot.sendMessage(chatId, '❗ Произошла ошибка при обновлении задачи.');
        }
    }
});

bot.onText(/\/delete_(\d+)/, async (msg, match) => {
    const chatId = msg.chat.id;
    const taskId = parseInt(match[1]);

    try {
        const user = await getUserByTelegramId(chatId);
        if (!user) {
            return bot.sendMessage(chatId, '❌ Ваш аккаунт не привязан. Сначала привяжите его на сайте.');
        }

        const deleted = await deleteItem(taskId, user.id);
        if (deleted) {
            await bot.sendMessage(chatId, '✅ Задача успешно удалена');
        } else {
            await bot.sendMessage(chatId, '❌ Задача не найдена или уже удалена');
        }
    } catch (err) {
        console.error('Error handling /delete command:', err);
        await bot.sendMessage(chatId, '❗ Произошла ошибка при удалении задачи.');
    }
});

// Start server
const server = http.createServer(handleRequest);
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Telegram bot username: ${TELEGRAM_BOT_USERNAME}`);
    console.log(`Domain: ${DOMAIN}`);
});

// Cleanup on exit
process.on('SIGINT', async () => {
    console.log('Shutting down server...');
    try {
        await pool.end();
        server.close(() => {
            console.log('Server stopped');
            process.exit(0);
        });
    } catch (err) {
        console.error('Error during shutdown:', err);
        process.exit(1);
    }
});
