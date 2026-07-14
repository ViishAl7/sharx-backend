const jwt = require("jsonwebtoken");
const JWT_SECRET = process.env.JWT_SECRET;

// FIX: if JWT_SECRET is ever unset at runtime (env misconfigured on a
// specific deploy target), jwt.verify(token, undefined) throws a generic
// low-level error that still got reported back as a plain 401 "Invalid
// token" — indistinguishable from a real bad/expired token, making a
// config bug look like a client-side auth bug. Fail loudly and
// distinctly in the logs so it's obvious what's actually wrong.
if (!JWT_SECRET) {
  console.error("❌ [authMiddleware] JWT_SECRET is not set — all authenticated routes will reject every request.");
}

module.exports = function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "No token provided" });
  }
  const token = authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).json({ message: "No token provided" });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};
