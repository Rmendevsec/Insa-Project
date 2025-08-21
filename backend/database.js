const {Sequlize} = require("sequlize")

let sequlize = new Sequlize({
    dialect: "seqlite",
    storage: "db.sqlite"
})

module.exports = sequlize