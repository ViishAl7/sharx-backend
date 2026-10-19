// lib/realtime.js — holds the Socket.IO server so any service can push to a user.
//
// Every authenticated socket joins exactly ONE private room: `user:<id>`.
// The id comes from the verified JWT (see socket auth in index.js), never from
// anything the client sends. Services call emitToUser(userId, event, payload).

let ioInstance = null;

function setIo(io) {
  ioInstance = io;
}

function getIo() {
  return ioInstance;
}

function userRoom(userId) {
  return `user:${Number(userId)}`;
}

/** Fire-and-forget push. Never throws; returns false if realtime is not up. */
function emitToUser(userId, event, payload) {
  try {
    if (!ioInstance) return false;
    ioInstance.to(userRoom(userId)).emit(event, payload);
    return true;
  } catch (err) {
    console.error('[realtime] emit failed:', err.message);
    return false;
  }
}

/** Disconnect every socket of a user (e.g. after password reset / tokenVersion bump). */
function disconnectUser(userId) {
  try {
    if (ioInstance) ioInstance.in(userRoom(userId)).disconnectSockets(true);
  } catch (err) {
    console.error('[realtime] disconnect failed:', err.message);
  }
}

module.exports = { setIo, getIo, userRoom, emitToUser, disconnectUser };
