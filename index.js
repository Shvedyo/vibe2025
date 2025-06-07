const http = require('http');
const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');
const url = require('url');
const PORT = 3000;

// Database configuration
const dbConfig = {
    host: 'localhost',
    user: 'root',
    password: '', // ваш пароль MySQL
    database: 'todolist'
};

const pool = mysql.createPool(dbConfig);

// Database functions
async function getItems() {
    const [rows] = await pool.query('SELECT * FROM items ORDER BY id DESC');
    return rows;
}

async function addItem(text) {
    const [result] = await pool.query('INSERT INTO items (text) VALUES (?)', [text]);
    return { id: result.insertId, text };
}

async function deleteItem(id) {
    await pool.query('DELETE FROM items WHERE id = ?', [id]);
    return true;
}

async function updateItem(id, newText) {
    await pool.query('UPDATE items SET text = ? WHERE id = ?', [newText, id]);
    return { id, text: newText };
}

// HTML generation
async function generateHtmlRows() {
    const items = await getItems();
    return items.map(item => `
        <tr data-id="${item.id}">
            <td>${item.id}</td>
            <td class="task-text">${item.text}</td>
            <td>
                <button class="edit-btn" onclick="startEdit(${item.id})">✏️</button>
                <button class="delete-btn" onclick="deleteItem(${item.id})">🗑️</button>
            </td>
        </tr>
    `).join('');
}

// Request handler
async function handleRequest(req, res) {
    const parsedUrl = url.parse(req.url, true);

    if (req.method === 'GET' && parsedUrl.pathname === '/') {
        try {
            const html = await fs.promises.readFile(path.join(__dirname, 'index.html'), 'utf8');
            const processedHtml = html.replace('{{rows}}', await generateHtmlRows());
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(processedHtml);
        } catch (err) {
            console.error(err);
            res.writeHead(500, { 'Content-Type': 'text/plain' });
            res.end('Server Error');
        }
    }
    else if (req.method === 'POST' && parsedUrl.pathname === '/api/items') {
        let body = '';
        req.on('data', chunk => body += chunk.toString());
        req.on('end', async () => {
            try {
                const { text } = JSON.parse(body);
                const newItem = await addItem(text);
                res.writeHead(201, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(newItem));
            } catch (error) {
                console.error(error);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Failed to add item' }));
            }
        });
    }
    else if (req.method === 'PUT' && parsedUrl.pathname === '/api/items') {
        let body = '';
        req.on('data', chunk => body += chunk.toString());
        req.on('end', async () => {
            try {
                const { id, text } = JSON.parse(body);
                const updatedItem = await updateItem(id, text);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(updatedItem));
            } catch (error) {
                console.error(error);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Failed to update item' }));
            }
        });
    }
    else if (req.method === 'DELETE' && parsedUrl.pathname === '/api/items') {
        const id = parsedUrl.query.id;
        try {
            await deleteItem(id);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true }));
        } catch (error) {
            console.error(error);
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Failed to delete item' }));
        }
    }
    else {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
    }
}

// Start server
const server = http.createServer(handleRequest);
server.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
