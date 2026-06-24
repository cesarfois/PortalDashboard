const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const COOKIE_SECRET = process.env.COOKIE_SECRET || 'secure-portal-secret-key-98765';

// Ensure data directory exists
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir);
}

// Database initialization
const dbPath = path.join(dataDir, 'portal.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Failed to connect to SQLite database:', err);
  } else {
    console.log('Connected to SQLite database at', dbPath);
    initDb();
  }
});

function initDb() {
  db.serialize(() => {
    // Users table
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        name TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0,
        is_active INTEGER DEFAULT 1
      )
    `);

    // Permissions table
    db.run(`
      CREATE TABLE IF NOT EXISTS permissions (
        user_id INTEGER,
        dashboard_key TEXT NOT NULL,
        PRIMARY KEY (user_id, dashboard_key),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    // Create default admin if no users exist
    db.get('SELECT COUNT(*) as count FROM users', (err, row) => {
      if (err) {
        console.error('Error checking user count:', err);
        return;
      }
      if (row.count === 0) {
        const adminUsername = 'admin';
        const adminPassword = 'admin123';
        const salt = bcrypt.genSaltSync(10);
        const hash = bcrypt.hashSync(adminPassword, salt);
        
        db.run(
          `INSERT INTO users (username, password_hash, name, is_admin, is_active) VALUES (?, ?, ?, ?, ?)`,
          [adminUsername, hash, 'Administrador Padrão', 1, 1],
          function(insertErr) {
            if (insertErr) {
              console.error('Failed to create default admin user:', insertErr);
            } else {
              console.log('Default admin user created successfully (admin / admin123)');
            }
          }
        );
      }
    });
  });
}

// Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser(COOKIE_SECRET));

// Session validation middleware
function requireAuth(req, res, next) {
  const userId = req.signedCookies.userId;
  if (!userId) {
    return res.status(401).redirect('/login');
  }

  db.get('SELECT * FROM users WHERE id = ? AND is_active = 1', [userId], (err, user) => {
    if (err || !user) {
      res.clearCookie('userId', { domain: '.processcloud.app' });
      res.clearCookie('username', { domain: '.processcloud.app' });
      return res.status(401).redirect('/login');
    }
    req.user = user;
    next();
  });
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (!req.user.is_admin) {
      return res.status(403).send('Acesso negado. Apenas administradores.');
    }
    next();
  });
}

// Static pages routing
app.get('/login', (req, res) => {
  if (req.signedCookies.userId) {
    return res.redirect('/portal');
  }
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/portal', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'portal.html'));
});

app.get('/admin', requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Serve styles and static JS
app.use(express.static(path.join(__dirname, 'public')));

// Redirect root to portal
app.get('/', (req, res) => {
  res.redirect('/portal');
});

// Authentication APIs
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Usuário e senha são obrigatórios.' });
  }

  db.get('SELECT * FROM users WHERE username = ?', [username.trim().toLowerCase()], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Erro interno no servidor.' });
    }
    if (!user) {
      return res.status(401).json({ error: 'Usuário ou senha incorretos.' });
    }
    if (!user.is_active) {
      return res.status(403).json({ error: 'Este usuário está inativo. Contate o administrador.' });
    }

    const passwordMatch = bcrypt.compareSync(password, user.password_hash);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Usuário ou senha incorretos.' });
    }

    // Set signed cookies
    const cookieOptions = {
      httpOnly: true,
      signed: true,
      maxAge: 24 * 60 * 60 * 1000, // 1 day
      domain: '.processcloud.app',
      secure: true,
      sameSite: 'lax'
    };
    res.cookie('userId', user.id, cookieOptions);
    res.cookie('username', user.username, cookieOptions);

    res.json({ success: true, redirect: '/portal' });
  });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('userId', { domain: '.processcloud.app' });
  res.clearCookie('username', { domain: '.processcloud.app' });
  res.json({ success: true, redirect: '/login' });
});

app.get('/api/auth/me', (req, res) => {
  const userId = req.signedCookies.userId;
  if (!userId) {
    return res.status(401).json({ authenticated: false });
  }

  db.get('SELECT id, username, name, is_admin FROM users WHERE id = ? AND is_active = 1', [userId], (err, user) => {
    if (err || !user) {
      return res.status(401).json({ authenticated: false });
    }

    db.all('SELECT dashboard_key FROM permissions WHERE user_id = ?', [user.id], (permErr, rows) => {
      if (permErr) {
        return res.status(500).json({ error: 'Erro ao buscar permissões.' });
      }
      const permissions = rows.map(r => r.dashboard_key);
      res.json({
        authenticated: true,
        user: {
          id: user.id,
          username: user.username,
          name: user.name,
          is_admin: !!user.is_admin,
          permissions
        }
      });
    });
  });
});

// Nginx auth_request callback endpoint
app.get('/api/auth/verify', (req, res) => {
  const userId = req.signedCookies.userId;
  if (!userId) {
    return res.status(401).send('Não autenticado');
  }

  db.get('SELECT is_admin, is_active FROM users WHERE id = ?', [userId], (err, user) => {
    if (err || !user || !user.is_active) {
      return res.status(401).send('Sessão inválida ou usuário inativo');
    }

    // If the user is admin, allow access to all paths
    if (user.is_admin) {
      return res.status(200).send('OK');
    }

    // Identify which dashboard the user is requesting
    const originalHost = req.headers['x-original-host'] || '';
    const originalUri = req.headers['x-original-uri'] || '';
    let reqDashboard = null;

    if (originalHost === 'learn.processcloud.app') {
      reqDashboard = 'learn';
    } else if (originalUri.startsWith('/compras')) {
      reqDashboard = 'compras';
    } else if (originalUri.startsWith('/importacao')) {
      reqDashboard = 'importacao';
    } else if (originalUri.startsWith('/pedido-de-pagamento') || originalUri.startsWith('/pagamentos')) {
      reqDashboard = 'pagamentos';
    } else if (originalUri.startsWith('/faturacao-servicos')) {
      reqDashboard = 'faturacao';
    } else if (originalUri.startsWith('/pedido-de-transporte')) {
      reqDashboard = 'transporte';
    } else if (originalUri.startsWith('/workflow-kpi-analytics') || originalUri.startsWith('/kpi-analytics')) {
      reqDashboard = 'kpi-analytics';
    }

    // If requested URI is not matching one of the controlled dashboards, deny by default or adjust as needed
    if (!reqDashboard) {
      return res.status(403).send('Não autorizado');
    }

    // Check permissions
    db.get(
      'SELECT 1 FROM permissions WHERE user_id = ? AND dashboard_key = ?',
      [userId, reqDashboard],
      (permErr, row) => {
        if (permErr || !row) {
          return res.status(403).send('Acesso não autorizado para este dashboard');
        }
        return res.status(200).send('OK');
      }
    );
  });
});

// User Management APIs (Admin Only)
app.get('/api/admin/users', requireAdmin, (req, res) => {
  const query = `
    SELECT u.id, u.username, u.name, u.is_admin, u.is_active, 
           group_concat(p.dashboard_key) as permissions
    FROM users u
    LEFT JOIN permissions p ON u.id = p.user_id
    GROUP BY u.id
  `;
  db.all(query, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Erro ao buscar usuários.' });
    }
    const formatted = rows.map(r => ({
      id: r.id,
      username: r.username,
      name: r.name,
      is_admin: !!r.is_admin,
      is_active: !!r.is_active,
      permissions: r.permissions ? r.permissions.split(',') : []
    }));
    res.json(formatted);
  });
});

app.post('/api/admin/users', requireAdmin, (req, res) => {
  const { username, password, name, is_admin, is_active, permissions } = req.body;
  if (!username || !password || !name) {
    return res.status(400).json({ error: 'Nome, usuário e senha são obrigatórios.' });
  }

  const salt = bcrypt.genSaltSync(10);
  const hash = bcrypt.hashSync(password, salt);

  db.serialize(() => {
    db.run('BEGIN TRANSACTION');

    db.run(
      `INSERT INTO users (username, password_hash, name, is_admin, is_active) VALUES (?, ?, ?, ?, ?)`,
      [username.trim().toLowerCase(), hash, name.trim(), is_admin ? 1 : 0, is_active ? 1 : 0],
      function(err) {
        if (err) {
          db.run('ROLLBACK');
          if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ error: 'Este nome de usuário já está cadastrado.' });
          }
          return res.status(500).json({ error: 'Erro ao cadastrar usuário.' });
        }

        const newUserId = this.lastID;

        if (permissions && Array.isArray(permissions) && permissions.length > 0) {
          const stmt = db.prepare('INSERT INTO permissions (user_id, dashboard_key) VALUES (?, ?)');
          permissions.forEach(key => {
            stmt.run(newUserId, key);
          });
          stmt.finalize();
        }

        db.run('COMMIT', (commitErr) => {
          if (commitErr) {
            db.run('ROLLBACK');
            return res.status(500).json({ error: 'Erro ao finalizar transação.' });
          }
          res.json({ success: true, userId: newUserId });
        });
      }
    );
  });
});

app.put('/api/admin/users/:id', requireAdmin, (req, res) => {
  const userId = req.params.id;
  const { name, is_admin, is_active, permissions } = req.body;

  if (!name) {
    return res.status(400).json({ error: 'O nome é obrigatório.' });
  }

  // Prevent self-deactivation or self-demotion from admin
  if (parseInt(userId) === req.user.id) {
    if (!is_active || !is_admin) {
      return res.status(400).json({ error: 'Você não pode desativar ou remover o privilégio admin de si mesmo.' });
    }
  }

  db.serialize(() => {
    db.run('BEGIN TRANSACTION');

    db.run(
      `UPDATE users SET name = ?, is_admin = ?, is_active = ? WHERE id = ?`,
      [name.trim(), is_admin ? 1 : 0, is_active ? 1 : 0, userId],
      (err) => {
        if (err) {
          db.run('ROLLBACK');
          return res.status(500).json({ error: 'Erro ao atualizar dados do usuário.' });
        }

        // Refresh permissions: delete existing and insert new
        db.run('DELETE FROM permissions WHERE user_id = ?', [userId], (delErr) => {
          if (delErr) {
            db.run('ROLLBACK');
            return res.status(500).json({ error: 'Erro ao atualizar permissões.' });
          }

          if (permissions && Array.isArray(permissions) && permissions.length > 0) {
            const stmt = db.prepare('INSERT INTO permissions (user_id, dashboard_key) VALUES (?, ?)');
            permissions.forEach(key => {
              stmt.run(userId, key);
            });
            stmt.finalize();
          }

          db.run('COMMIT', (commitErr) => {
            if (commitErr) {
              db.run('ROLLBACK');
              return res.status(500).json({ error: 'Erro ao finalizar transação.' });
            }
            res.json({ success: true });
          });
        });
      }
    );
  });
});

app.put('/api/admin/users/:id/password', requireAdmin, (req, res) => {
  const userId = req.params.id;
  const { password } = req.body;

  if (!password || password.trim().length < 4) {
    return res.status(400).json({ error: 'A senha deve conter pelo menos 4 caracteres.' });
  }

  const salt = bcrypt.genSaltSync(10);
  const hash = bcrypt.hashSync(password, salt);

  db.run(
    'UPDATE users SET password_hash = ? WHERE id = ?',
    [hash, userId],
    (err) => {
      if (err) {
        return res.status(500).json({ error: 'Erro ao redefinir a senha.' });
      }
      res.json({ success: true });
    }
  );
});

app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
  const userId = req.params.id;

  // Prevent self-deletion
  if (parseInt(userId) === req.user.id) {
    return res.status(400).json({ error: 'Você não pode excluir a si mesmo.' });
  }

  db.serialize(() => {
    db.run('BEGIN TRANSACTION');
    db.run('DELETE FROM permissions WHERE user_id = ?', [userId], (err) => {
      if (err) {
        db.run('ROLLBACK');
        return res.status(500).json({ error: 'Erro ao excluir permissões do usuário.' });
      }
      db.run('DELETE FROM users WHERE id = ?', [userId], (err) => {
        if (err) {
          db.run('ROLLBACK');
          return res.status(500).json({ error: 'Erro ao excluir o usuário.' });
        }
        db.run('COMMIT', (commitErr) => {
          if (commitErr) {
            db.run('ROLLBACK');
            return res.status(500).json({ error: 'Erro ao finalizar transação de exclusão.' });
          }
          res.json({ success: true });
        });
      });
    });
  });
});

// Start Server
app.listen(PORT, () => {
  console.log(`Auth Portal server running on port ${PORT}`);
});
