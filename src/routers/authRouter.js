const router = require("express").Router()
const pool = require("../database/db")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const crypto = require("crypto")
const sendEmail=require("../utils/sendEmail")

/*
    Signup endpoint
*/
router.post("/register", async (req, res) => {
    const {username, email, password, active} = req.body
    if (!username || !email || !password || !active) {
        return res.status(400).send("Must send a json body with username, email, password and whether they are active")
    }
    
    const hash = await bcrypt.hash(password, 10)

    user = pool.query(
        "INSERT INTO users (username, email, password, active) VALUES ($1, $2, $3, $4) RETURNING *",
        [username, email, hash, active],
        async (error, results) => {
            if (error) {
                res.send(`There was an error: ${error}`)
                throw error
            }
            res.send(results.rows)
        }
    )
})

/* 
    Full login with refresh token and access token
*/
router.post("/login", async (req, res) => {
    const {username, password} = req.body
    if (!username || !password ) {
        return res.send("Must send a grant type equal to password, username and password in json format")
    }
    console.log(`${username} is trying to login`)

    user = pool.query('SELECT * FROM users WHERE username = $1;', [username], async (error, results) => {
        if (error) {
            console.log(error)
            return res.status(401).json({error: error})
        }

        // FYI: hashing happens before checking if user exists to stop attackers from doing a timing attack
        result = await bcrypt.compare(password, results.rows[0].password)

        if (results.rowCount == 0) {
            return res.send(`Invalid credentials`)
        }

        if (results.rows[0].active == false) {
            return res.send("You are not an active user")
        }

        if (result) {
            const access_token = jwt.sign({sub: username, type: 'access'}, process.env.ACCESS_JWT_SECRET_KEY, {expiresIn: '15m'})
            const refresh_token = jwt.sign({sub: username, type: 'refresh'}, process.env.REFRESH_JWT_SECRET_KEY, {expiresIn: '14d'})
            res.cookie("access_token", access_token, {httpOnly: true, maxAge: 15*60*1000})
            res.cookie("refresh_token", refresh_token, {httpOnly: true, maxAge: 14*24*60*60*1000})
            pool.query("UPDATE users SET refresh_token=$1 WHERE username=$2 RETURNING *", [refresh_token, username], async (error, results) => {
                if (error) {
                    console.log("There was an error")
                    return res.status(500).send("Internal server error")
                }
                res.cookie('access_token', access_token, {httpOnly: true})
                res.cookie('refresh_token', refresh_token, {httpOnly: true})
                return res.send("Logged in ")
            })
            
        } else {
            return res.send("Invalid credentials")
        }
    })
})

/*
    Refresh token endpoint
*/
router.get("/refresh_tokens", async (req, res) => {
    const refresh_token = req.cookies.refresh_token
    if (!refresh_token) {
        res.status(400).send("Must send a refresh token in cookies")
    }

    try {
        pool.query("SELECT * FROM users WHERE refresh_token=$1", [refresh_token], (error, results) => {
            if (error) {
                console.log(error)
                return res.status(500).send("Internal server error")
            }
            console.log(results.rows)
            if (results.rowCount !== 0) {
                try {
                    const {sub, type} = jwt.verify(refresh_token, process.env.REFRESH_JWT_SECRET_KEY)
        
                    if (type === 'refresh') {
                        const access_token = jwt.sign({sub: sub, type: 'access'}, process.env.ACCESS_JWT_SECRET_KEY, {expiresIn: '15m'})
                        const refresh_token = jwt.sign({sub: sub, type: 'refresh'}, process.env.REFRESH_JWT_SECRET_KEY, {expiresIn: '14d'})
                        
                        // invalidate previous refresh tokens
                        pool.query("UPDATE users SET refresh_token=$1 WHERE username=$2 RETURNING *", [refresh_token, sub], async (error, results) => {
                            if (error) {
                                console.log("There was an error")
                                return res.status(500).send("Internal server error")
                            }
                            res.cookie('access_token', access_token, {httpOnly: true})
                            res.cookie('refresh_token', refresh_token, {httpOnly: true})
                            return res.send("Refreshed tokens" + refresh_token)
                        })
                    } else {
                        return res.send("You need to send a refresh token, HINT: not an access token")
                    }
                } catch (error) {
                    return res.send(error)
                }
                
            } else {
                res.send("Invalid refresh token")
            }
        })
    } catch (error) {
        console.log(error)
        return res.status(401).send("Not authorized")
    }
})

router.post("/forgot_password", (req, res) => {
    const {email} = req.body

    if (!email) {
        return res.status(400).send("Must send an email key in json")
    }

    pool.query("SELECT * FROM users WHERE email=$1", [email], (error, results) => {
        if (error) {
            console.log(error)
            return res.status(500).send(error)
        }
        if (results.rowCount === 0) {
            return res.status(404).send("User with email not found")
        }
        const user_id = results.rows[0].id
        const token = crypto.randomBytes(32).toString("hex")
        pool.query("INSERT INTO password_tokens (user_id, token) VALUES ($1, $2) RETURNING *", [user_id, token], (error, results) => {
            if (error) {
                console.log(error)
                return res.status(500).send(error)
            }
            const link = `${process.env.BASE_URL}/auth/forgot_password/${user_id}/${token}`
            sendEmail(email, "Password reset", link)
            return res.send("Email sent")
        })
    })
})

router.post("/forgot_password/:user_id/:token", async (req, res) => {
    if (!req.body.password) {
        return res.status(400).send("Invalid body for request")
    }
    pool.query("SELECT * FROM users WHERE id=$1", [req.params.user_id], async (error, results) => {
        if (error) {
            return res.status(500).send(error)
        }
        if (results.rowCount === 0) {
            return res.status(404).send("Invalid or expired link")
        }
        pool.query("SELECT * FROM password_tokens WHERE user_id=$1", [results.rows[0].id], async (error, results) => {
            if (error) {
                return res.status(500).send(error)
            }
            if (results.rowCount === 0) {
                return res.status(404).send("Invalid or expired link")
            }
            hashed_password = await bcrypt.hash(req.body.password, 10)
            pool.query("UPDATE users SET password=$1 WHERE id=$2", [hashed_password, req.params.user_id], (error, results) => {
                if (error) {
                    return res.status(500).send(error)
                }
                return res.send("Password changed")
            })
        })
    })
})

module.exports = router