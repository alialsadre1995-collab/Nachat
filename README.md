# Render Chat Backend (No Public)

- Backend-only: **no `public/` folder**. Use a separate frontend.
- Fixed admin by default: **Admin / 1200@** (override via env).
- Features: JWT auth, Socket.IO, roles (user/mod/admin), bans (userId/deviceId/ip).

## Run
```
cp .env.example .env
npm install
npm start
```
Server on http://localhost:10000

## Important env
- `JWT_SECRET` — set a long random secret.
- `FRONTEND_ORIGIN` — set your frontend URL (or `*` for dev). If multiple, comma-separate.
- `FIXED_ADMIN_USER`, `FIXED_ADMIN_PASS` — override default admin.
- `TRUST_PROXY=true` — recommended on Render.

## Client (example)
```
POST /api/login-pass  { username, password, deviceId? }
→ { token, userId, role, deviceId, username }

const socket = io(BACKEND_URL, { auth: { token } });
socket.emit('chat:msg', { text: 'hello' });
```

## Notes
- In-memory storage (MVP). Add DB for persistence in production.
