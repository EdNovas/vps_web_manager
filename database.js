const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');

let pool = null;

const init = async (config) => {
    pool = mysql.createPool({
        host: config.host || '127.0.0.1',
        user: config.user,
        password: config.password,
        database: config.database,
        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 0
    });

    try {
        const connection = await pool.getConnection();

        // 1. Create Users Table
        await connection.query(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // 2. Create/Update Sessions Table
        await connection.query(`
            CREATE TABLE IF NOT EXISTS sessions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                owner_id INT,
                ip VARCHAR(255) NOT NULL,
                user VARCHAR(255) NOT NULL,
                password VARCHAR(255),
                label VARCHAR(255),
                last_connected TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY unique_session (owner_id, ip, user)
            )
        `);
        
        // Migration: Add owner_id if it doesn't exist (for old databases)
        const [columns] = await connection.query("SHOW COLUMNS FROM sessions LIKE 'owner_id'");
        if (columns.length === 0) {
            await connection.query("ALTER TABLE sessions ADD COLUMN owner_id INT AFTER id");
            // Assign existing sessions to user ID 1 (Admin) temporarily if needed
            await connection.query("UPDATE sessions SET owner_id = 1 WHERE owner_id IS NULL"); 
            console.log('Migration: Added owner_id column to sessions table');
        }

        // Migration: Add password column if missing
        const [passCols] = await connection.query("SHOW COLUMNS FROM sessions LIKE 'password'");
        if (passCols.length === 0) {
            await connection.query("ALTER TABLE sessions ADD COLUMN password VARCHAR(255) AFTER user");
        }
        
        connection.release();
        console.log('Database initialized successfully');
    } catch (err) {
        console.error('Database Initialization Error:', err);
    }
};

module.exports = {
    init,

    // --- User Management ---
    createUser: async (username, plainPassword) => {
        try {
            const hash = await bcrypt.hash(plainPassword, 10);
            const [result] = await pool.execute(
                'INSERT INTO users (username, password_hash) VALUES (?, ?)', 
                [username, hash]
            );
            return result.insertId;
        } catch (err) {
            console.error('Create User Error:', err);
            return null; // Likely duplicate username
        }
    },

    verifyUser: async (username, plainPassword) => {
        try {
            const [rows] = await pool.execute('SELECT * FROM users WHERE username = ?', [username]);
            if (rows.length === 0) return null;
            
            const user = rows[0];
            const match = await bcrypt.compare(plainPassword, user.password_hash);
            return match ? { id: user.id, username: user.username } : null;
        } catch (err) {
            console.error('Verify User Error:', err);
            return null;
        }
    },

    // --- Session Management (Scoped to Owner) ---
    saveSession: async (ownerId, ip, user, password, label = '') => {
        try {
            const sql = `
                INSERT INTO sessions (owner_id, ip, user, password, label) 
                VALUES (?, ?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE 
                    last_connected = CURRENT_TIMESTAMP,
                    password = VALUES(password),
                    label = VALUES(label)
            `;
            const [result] = await pool.execute(sql, [ownerId, ip, user, password, label]);
            return result;
        } catch (err) {
            console.error('Save Session Error:', err);
            return null;
        }
    },

    getSessions: async (ownerId) => {
        try {
            const [rows] = await pool.query('SELECT * FROM sessions WHERE owner_id = ? ORDER BY last_connected DESC', [ownerId]);
            return rows;
        } catch (err) {
            console.error('Get Sessions Error:', err);
            return [];
        }
    },

    deleteSession: async (id, ownerId) => {
        try {
            const [result] = await pool.execute('DELETE FROM sessions WHERE id = ? AND owner_id = ?', [id, ownerId]);
            return result;
        } catch (err) {
            console.error('Delete Session Error:', err);
            return null;
        }
    },

    updateSession: async (id, ownerId, ip, user, password, label) => {
        try {
            const sql = `UPDATE sessions SET ip = ?, user = ?, password = ?, label = ? WHERE id = ? AND owner_id = ?`;
            const [result] = await pool.execute(sql, [ip, user, password, label, id, ownerId]);
            return result;
        } catch (err) {
            console.error('Update Session Error:', err);
            return null;
        }
    },

    updateLabel: async (id, ownerId, label) => {
        try {
            const [result] = await pool.execute('UPDATE sessions SET label = ? WHERE id = ? AND owner_id = ?', [label, id, ownerId]);
            return result;
        } catch (err) {
            console.error('Update Label Error:', err);
            return null;
        }
    }
};