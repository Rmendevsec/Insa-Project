import React,{useState} from 'react'
import axios from "axios"
function App() {
  const [url, setUrl] = useState('')
  const [result, setResult] = useState("")
  const baseURL = "http://localhost:5000"
  const handleScanner = async () =>{
    try {
      const res = await axios.post(`${baseURL}/scan`, {
        url: url,
        vuln:"xss"
      })
      setResult(res.data.output)
    } catch (error) {
      setResult("error:"+error.message)
    }
  }
  return (
    <div className='p-6'>
      <h1 className='text-xl font-bold'>Vulnerability Scanner</h1>
      <input type='text' placeholder='enter url'value={url} onChange={e => setUrl(e.target.value)} className='border p-2 rounded'/>
      <button onClick={handleScanner} className='bg-blue-300 text-white px-4 rounded'>Scan XSS</button>
      <pre className='mt-4 bg-green-900 rounded text-white' >{result}</pre>
      
    
    
    </div>
  )
}

export default App