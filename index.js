const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const db = require('./database'); // Pastikan koneksi DB Anda benar

const app = express();
const port = 3000;
const saltRounds = 10; // Kekuatan hashing untuk password admin

app.use(express.json());
// Melayani file statis dari folder 'public'
app.use(express.static(path.join(__dirname, 'public')));

// --- FUNGSI UTILITY ---

function generateApiKey() {
    const randomBytes = crypto.randomBytes(16).toString('hex').toUpperCase();
    return `Hikmatyar-${randomBytes.slice(0, 8)}-${randomBytes.slice(8, 16)}-${randomBytes.slice(16, 24)}-${randomBytes.slice(24, 32)}`;
}

// --- ROUTE UNTUK MENAMPILKAN HALAMAN HTML ---

// ✅ PERBAIKAN: Memastikan path sesuai dengan nama file Anda (loginadmin.html)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/loginadmin.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'loginadmin.html'));
});

app.get('/dashboardadmin.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboardadmin.html'));
});

// --- ROUTE API UTAMA (index.html) ---

// --- ROUTE: CEK API KEY VALIDASI ---
app.post('/cekapi', (req, res) => {
    const { api_key } = req.body
  
    if (!api_key) {
      return res.status(400).json({ error: 'API key wajib dikirim' })
    }
  
    const sql = 'SELECT * FROM apikeys WHERE api_key = ?'
    db.query(sql, [api_key], (err, results) => {
      if (err) {
        console.error('❌ Error cek API key:', err)
        return res.status(500).json({ error: 'Terjadi kesalahan server' })
      }
  
      if (results.length > 0) {
        res.json({ valid: true, service_name: results[0].service_name, created_at: results[0].created_at })
      } else {
        res.json({ valid: false, message: 'API key tidak ditemukan' })
      }
    })
  })

// ROUTE 1: CREATE API KEY (Menghasilkan dan menyimpan key)
app.post('/create', (req, res) => {
    const { service_name } = req.body;
    if (!service_name) return res.status(400).json({ error: 'Service name wajib diisi' });

    const apiKey = generateApiKey();

    const sql = `
        INSERT INTO apikeys (api_key, service_name) 
        VALUES (?, ?)
    `; 
    
    db.query(sql, [apiKey, service_name], (err) => {
        if (err) {
             console.error('Database Error:', err);
             return res.status(500).json({ error: 'Gagal menyimpan API Key ke database' });
        }
        res.json({ apiKey, message: 'API Key berhasil dibuat & disimpan!' });
    });
});

// ROUTE 2: GET API KEYS (Mengambil keys yang belum terpakai untuk dropdown)
app.get('/get-apikeys', (req, res) => {
    // Query untuk mengambil API Keys yang BELUM digunakan oleh User mana pun
    const sql = `
        SELECT a.api_key, a.service_name 
        FROM apikeys a
        LEFT JOIN users u ON a.api_key = u.api_key
        WHERE u.api_key IS NULL
    `;
    
    db.query(sql, (err, results) => {
        if (err) return res.status(500).json({ error: "Gagal mengambil API keys" });
        res.json(results);
    });
});

// ROUTE 3: SAVE USER (Menyimpan user dengan key yang sudah ada)
app.post('/save-user', (req, res) => {
    const { first_name, last_name, email, api_key } = req.body;
    if (!first_name || !last_name || !email || !api_key)
        return res.status(400).json({ success: false, message: "Semua field wajib diisi dan API Key harus dipilih" });

    // 1. Cek apakah API Key sudah terdaftar di apikeys table (validasi)
    const checkValidKeySql = "SELECT api_key FROM apikeys WHERE api_key = ?";
    db.query(checkValidKeySql, [api_key], (err, validResult) => {
        if (err) return res.status(500).json({ success: false, message: "Server error saat validasi API Key" });
        if (validResult.length === 0) return res.status(400).json({ success: false, message: "API Key tidak valid atau tidak ada" });
        
        // 2. Simpan User
        const insertSql = `
            INSERT INTO users (first_name, last_name, email, api_key)
            VALUES (?, ?, ?, ?)
        `;
        db.query(insertSql, [first_name, last_name, email, api_key], (err, resultUser) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY' && err.sqlMessage.includes('email')) {
                    return res.status(400).json({ success: false, message: "Email sudah terdaftar!" });
                }
                return res.status(500).json({ success: false, message: "Gagal menyimpan user ke database" });
            }

            res.json({
                success: true,
                message: "User berhasil disimpan!",
                user_id: resultUser.insertId
            });
        });
    });
});


// --- ROUTE API ADMIN ---

// ROUTE: REGISTER ADMIN
app.post('/admin/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.json({ success: false, message: "Email & Password wajib diisi" });

    try {
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const sql = "INSERT INTO admins (email, password) VALUES (?, ?)"; 
        db.query(sql, [email, hashedPassword], (err) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') return res.json({ success: false, message: "Email sudah terdaftar" });
                console.error("Register Error:", err);
                return res.status(500).json({ success: false, message: "Server error" });
            }
            res.json({ success: true, message: "Admin berhasil didaftarkan!" });
        });
    } catch (error) {
        console.error("Bcrypt Hashing Error:", error);
        res.status(500).json({ success: false, message: "Server error saat memproses password." });
    }
});

// ROUTE: ADMIN LOGIN
app.post('/admin/login', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.json({ success: false, message: "Email & Password wajib diisi" });

    const sql = "SELECT password FROM admins WHERE email = ?";
    db.query(sql, [email], async (err, result) => { 
        if (err) return res.status(500).json({ success: false, message: "Server error" });
        if (result.length === 0) return res.json({ success: false, message: "Email atau Password salah" });

        const hashedPassword = result[0].password;

        try {
            const isMatch = await bcrypt.compare(password, hashedPassword);
            if (isMatch) {
                res.json({ success: true, message: "Login berhasil!" });
            } else {
                res.json({ success: false, message: "Email atau Password salah" });
            }
        } catch (compareError) {
            console.error("Bcrypt Compare Error:", compareError);
            res.status(500).json({ success: false, message: "Server error saat memproses login." });
        }
    });
});

// ROUTE: ADMIN - LIST USER
app.get('/admin/users', (req, res) => {
    const sql = "SELECT id, first_name, last_name, email, api_key, created_at FROM users";
    db.query(sql, (err, results) => {
        if (err) return res.status(500).json({ error: "Gagal mengambil data user" });
        res.json(results);
    });
});

// ROUTE: ADMIN - LIST APIKEY
app.get('/admin/apikeys', (req, res) => {
    const sql = "SELECT id, service_name, api_key, created_at, out_of_date FROM apikeys";
    db.query(sql, (err, results) => {
        if (err) return res.status(500).json({ error: "Gagal mengambil API keys" });
        res.json(results);
    });
});

// ROUTE: ADMIN - HAPUS USER
app.delete('/admin/users/:id', (req, res) => {
    const userId = req.params.id;
    const sql = "DELETE FROM users WHERE id = ?";
    db.query(sql, [userId], (err, result) => {
        if (err) {
            console.error('Delete User Error:', err);
            return res.status(500).json({ success: false, message: "Gagal menghapus user." });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: "User tidak ditemukan." });
        }
        res.json({ success: true, message: "User berhasil dihapus!" });
    });
});

// ROUTE: ADMIN - HAPUS API KEY
app.delete('/admin/apikeys/:id', (req, res) => {
    const apiKeyId = req.params.id;
    const sql = "DELETE FROM apikeys WHERE id = ?";
    db.query(sql, [apiKeyId], (err, result) => {
        if (err) {
            console.error('Delete API Key Error:', err);
            if (err.code === 'ER_ROW_IS_REFERENCED_2') {
                return res.status(400).json({ success: false, message: "Gagal: API Key masih digunakan oleh satu atau lebih User. Hapus User terlebih dahulu." });
            }
            return res.status(500).json({ success: false, message: "Gagal menghapus API Key." });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: "API Key tidak ditemukan." });
        }
        res.json({ success: true, message: "API Key berhasil dihapus!" });
    });
});


// JALANKAN SERVER
app.listen(port, () => {
    console.log(`🚀 Server berjalan di http://localhost:${port}`);
});