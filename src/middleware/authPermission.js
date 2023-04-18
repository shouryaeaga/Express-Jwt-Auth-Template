const jwt = require("jsonwebtoken")

const isAuthorized = (req, res, next) => {
    const access_token = req.cookies.access_token
    if (!access_token) {
        return res.status(401).send("Unauthorized")
    }
    try {
        const {sub, type} = jwt.verify(access_token, process.env.ACCESS_JWT_SECRET_KEY)
        if (type === 'access') {
            next()
        } else {
            return res.status(400).send("Requires an access token, HINT: Not a refresh token")
        }
    } catch (error) {
        return res.send(error)
    }
}

module.exports = isAuthorized