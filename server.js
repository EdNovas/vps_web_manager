const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { Client } = require('ssh2');
const session = require('express-session');
const path = require('path');
const { exec } = require('child_process'); // Native Node module, no install needed
const fs = require('fs');
const db = require('./database');

// --- CONFIGURATION ---
const ADMIN_SECRET_KEY = 'YOUR_ADMIN_SECRET_KEY'; // <--- CHANGE THIS for User Creation
const dbConfig = {
    host: '127.0.0.1',  // Replace with your database host (usually 127.0.0.1)
    user: 'YOUR_DATABASE_USERNAME',      // Replace with your database username
    password: 'YOUR_DATABASE_PASSWORD',  // Replace with your database password
    database: 'YOUR_DATABASE_NAME'       // Replace with your database name
};

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Initialize DB
db.init(dbConfig);

// Middleware
app.use(express.json());
app.use(session({
    secret: 'vps-manager-secret-salt-change-me',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// --- AUTH MIDDLEWARE ---
const requireAuth = (req, res, next) => {
    if (req.session && req.session.userId) {
        next();
    } else {
        res.status(401).json({ error: 'Unauthorized' });
    }
};

// --- ROUTES ---

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'vps_manager.html'));
});

// Authentication Routes
app.get('/api/me', (req, res) => {
    if (req.session.userId) {
        res.json({ loggedIn: true, username: req.session.username });
    } else {
        res.json({ loggedIn: false });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await db.verifyUser(username, password);
    if (user) {
        req.session.userId = user.id;
        req.session.username = user.username;
        res.json({ success: true, user });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

// Admin Route (Protected by Secret Key, not Session)
app.post('/api/admin/users', async (req, res) => {
    const { adminSecret, username, password } = req.body;

    if (adminSecret !== ADMIN_SECRET_KEY) {
        return res.status(403).json({ error: 'Invalid Admin Secret' });
    }

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and Password required' });
    }

    const newUserId = await db.createUser(username, password);
    if (newUserId) {
        res.json({ success: true, message: 'User created' });
    } else {
        res.status(400).json({ error: 'User already exists or error occurred' });
    }
});


// --- NATIVE SYSTEM PING (No Module Required) ---
app.post('/api/ping', requireAuth, (req, res) => {
    const { ip } = req.body;
    
    // Basic security check to ensure it looks like an IP or hostname (prevents command injection)
    if (!ip || !/^[a-zA-Z0-9.\-_]+$/.test(ip)) {
        return res.status(400).json({ error: 'Invalid IP address' });
    }

    // Run standard Linux ping: -c 1 (count 1), -W 2 (wait 2 seconds max)
    const command = `ping -c 1 -W 2 ${ip}`;

    exec(command, (error, stdout, stderr) => {
        if (error) {
            // If ping returns error code (host unreachable), we send alive: false
            return res.json({ alive: false, error: 'Unreachable' });
        }

        // Parse the time from the output (e.g., "time=24.5 ms")
        const timeMatch = stdout.match(/time=([\d\.]+)/);
        const time = timeMatch ? parseFloat(timeMatch[1]) : '<1';

        res.json({ 
            alive: true, 
            time: time, 
            output: stdout 
        });
    });
});
// -------------------------

// Protected Session API Routes (Scoped to Logged In User)
app.get('/api/sessions', requireAuth, async (req, res) => {
    const sessions = await db.getSessions(req.session.userId);
    res.json(sessions);
});

app.post('/api/sessions', requireAuth, async (req, res) => {
    const { ip, user, password, label } = req.body;
    if (!ip || !user) return res.status(400).json({ error: 'IP and User required' });

    await db.saveSession(req.session.userId, ip, user, password, label);
    res.json({ success: true });
});

app.delete('/api/sessions/:id', requireAuth, async (req, res) => {
    await db.deleteSession(req.params.id, req.session.userId);
    res.json({ success: true });
});

app.put('/api/sessions/:id/label', requireAuth, async (req, res) => {
    const { label } = req.body;
    await db.updateLabel(req.params.id, req.session.userId, label);
    res.json({ success: true });
});

app.put('/api/sessions/:id', requireAuth, async (req, res) => {
    const { ip, user, password, label } = req.body;
    await db.updateSession(req.params.id, req.session.userId, ip, user, password, label);
    res.json({ success: true });
});

// --- SSH Logic ---
io.on('connection', (socket) => {
    // Note: For a production app, we should share session with socket.io 
    // to verify auth here too, but for now we rely on the frontend 
    // being behind the login screen.

    let conn = new Client();
    let stream = null;

    socket.on('start-ssh', (credentials) => {
        conn.on('ready', () => {
            socket.emit('status', '\x1b[32m[System] Connected. Opening interactive shell...\x1b[0m\r\n');
            conn.shell((err, s) => {
                if (err) return socket.emit('data', '\r\nError: ' + err.message + '\r\n');
                stream = s;
                stream.on('data', (data) => socket.emit('data', data.toString('utf-8')));
                stream.on('close', () => {
                    socket.emit('status', '\r\n[System] Connection closed.\r\n');
                    conn.end();
                });
            });
        }).on('error', (err) => {
            socket.emit('status', '\r\n[System] Connection Error: ' + err.message + '\r\n');
        }).connect({
            host: credentials.ip,
            port: 22,
            username: credentials.user,
            password: credentials.pass,
            readyTimeout: 20000,
            algorithms: {
                kex: ['diffie-hellman-group1-sha1', 'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521', 'diffie-hellman-group-exchange-sha256', 'diffie-hellman-group14-sha1'],
                cipher: ['aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-gcm', 'aes128-cbc', '3des-cbc']
            }
        });
    });

    socket.on('data', (data) => {
        if (stream) stream.write(data);
    });

    socket.on('resize', (data) => {
        if (stream) stream.setWindow(data.rows, data.cols, data.height, data.width);
    });

    socket.on('disconnect', () => {
        if (conn) conn.end();
    });
});

server.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
});
