 const jwt = require('jsonwebtoken');

const verifyJWT = (req, res, next) => {
    // const authHeader = req.headers.authorization || req.headers.Authorization;
    const authHeader = req.headers['authorization']
    if (!authHeader) return res.sendStatus(401);
    const token = authHeader.split(' ')[1];
    console.log(token)
    jwt.verify(
        token,
        process.env.JWT_SEC,
        (err, decoded) => {
            if (err) return res.sendStatus(403) //invalid token
            req.user = decoded.username
            next();
        }
    );
}

module.exports = verifyJWT