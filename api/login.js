const { neon } = require('@neondatabase/serverless');
const crypto = require('crypto');

// Sama dengan hashPassword() di aplikasi: 'sha256$' + sha256(username + ':' + password)
function hashPassword(username, plain) {
  return 'sha256$' + crypto.createHash('sha256').update(username + ':' + plain).digest('hex');
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method tidak diizinkan.' });

  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username dan password wajib diisi.' });

  const sql = neon(process.env.DATABASE_URL);
  const uname = String(username).trim().slice(0, 100);
  const ip = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  const ua = String(req.headers['user-agent'] || '').slice(0, 300);

  // Pencatatan tidak boleh menggagalkan login
  const log = async (userId, role, status, reason) => {
    try {
      await sql`INSERT INTO login_activity (user_id, username_input, role, status, failure_reason, ip_address, user_agent)
                VALUES (${userId}, ${uname}, ${role}, ${status}, ${reason}, ${ip}, ${ua})`;
    } catch (e) { console.error('Gagal mencatat login:', e.message); }
  };

  try {
    // Batasi percobaan: 5 kali gagal dalam 15 menit
    const recent = await sql`SELECT COUNT(*)::int AS n FROM login_activity
                             WHERE username_input = ${uname} AND status = 'failed'
                             AND created_at > now() - interval '15 minutes'`;
    if (recent[0].n >= 5) {
      return res.status(429).json({ error: 'Terlalu banyak percobaan. Coba lagi 15 menit lagi.' });
    }

    const rows = await sql`SELECT id, role, username, password, name, profile FROM users WHERE username = ${uname} LIMIT 1`;
    const user = rows[0];

    if (!user) {
      await log(null, null, 'failed', 'user_not_found');
      return res.status(401).json({ error: 'Username atau Password salah!' });
    }
    if (user.password !== hashPassword(user.username, String(password))) {
      await log(user.id, user.role, 'failed', 'wrong_password');
      return res.status(401).json({ error: 'Username atau Password salah!' });
    }

    await log(user.id, user.role, 'success', null);
    // Role dikirim dari database. Data tambahan akun (profile) digabung agar dashboard tetap lengkap.
    const { password: _pw, profile, ...base } = user;
    return res.status(200).json({ user: { ...(profile || {}), ...base } });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Terjadi kesalahan server.' });
  }
};
