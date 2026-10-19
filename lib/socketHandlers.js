// lib/socketHandlers.js — all Socket.IO wiring in one testable place.
//
// Logged-in sockets are verified from their JWT (lib/socketAuth.js) and join
// their own private room. Guests (no token) may still connect for public
// features (game rooms, leaderboard).

const { authenticateSocket } = require('./socketAuth');
const { setIo, userRoom } = require('./realtime');

function registerSocketHandlers(io) {
  io.use(authenticateSocket);
  setIo(io);

  io.on('connection', (socket) => {
    console.log('User connected 🔥');

    // Private per-user room. The id is the VERIFIED one from the JWT.
    if (socket.data.userId) socket.join(userRoom(socket.data.userId));
    socket.emit('realtime:ready', { authenticated: Boolean(socket.data.userId) });

    socket.on('joinRoom', (roomId) => {
      if (typeof roomId !== 'string' || roomId.length === 0 || roomId.length > 100) return;
      // Clients may NEVER join private user rooms (would leak notifications).
      if (roomId.startsWith('user:')) return;
      socket.join(roomId);
    });

    socket.on('makeMove', ({ roomId, board, player } = {}) => {
      if (typeof roomId !== 'string' || roomId.length === 0 || roomId.length > 100) return;
      if (roomId.startsWith('user:')) return;
      socket.to(roomId).emit('moveMade', { board, player });
    });

    socket.on('disconnect', () => {
      console.log('User disconnected 💤');
    });
  });
}

module.exports = { registerSocketHandlers };
