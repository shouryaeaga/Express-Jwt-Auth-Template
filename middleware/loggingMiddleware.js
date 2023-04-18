const logger = (req, res, next) => {
    res.on('finish', function() {
         if (this.statusCode >= 400){
            console.log(`\x1b[32m ${req.method} \x1b[0m'${req.originalUrl}' \x1b[31m Status: ${this.statusCode}`)
         }
        else {
            console.log(`\x1b[32m ${req.method} \x1b[0m'${req.originalUrl}' \x1b[32m Status: ${this.statusCode}`)
        }
    })
    
    next()
}

module.exports = logger