const verifyAdmin = (req, res, next) => {
    if (!req?.admin) return res.sendStatus(401)
    next()
    // return (req, res, next) => {
    //     if (!req?.admin) return res.sendStatus(401)
    //     next()
    // }
}

module.exports = verifyAdmin
