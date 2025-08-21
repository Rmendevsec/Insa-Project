const express = require("express")
const cors = require("cors")
const bodyParser = require("body-parser")
const {spawn} = require("child_process")

const app = express()
app.use(cors())
app.use(express.json())
app.use(bodyParser.json())

const PORT = 5000
app.listen(PORT, ()=>{
    console.log(`server is running on port {PORT}`)
})

app.post("/scan", (req,res)=>{
    const {url, vuln}=req.body

    if (vuln === "xss"){
        const process=spawn("python", ["../XSS/xss.py", url])
        let output = ""

        process.stdout.on("data", (data=>{
            output += data.tostring()

        }))

        process.stderr.on("data", data=>{
            output += data.tostring()

        })
        process.on("close", ()=>{
            res.json({output})
        })

    }else{
        res.json({err: "Unsupported vulnerability"})
    }
})

