const express = require("express")
const app = express()
const cookieParser = require("cookie-parser")
const authMiddleware = require("./middleware/authPermission")
const loggingMiddleware = require("./middleware/loggingMiddleware")
require('dotenv').config()

// Controllers
const authController = require("./routers/authRouter")

app.use(express.json())
app.use(cookieParser())
app.use(loggingMiddleware)
app.use("/auth", authController)

// Test to see if authorization middleware works
app.get("/", authMiddleware, (req, res) => {
    res.send("Super secret")
})

app.listen(process.env.PORT, () => console.log(`Server listening on\x1b[31m PORT: ${process.env.PORT}`))