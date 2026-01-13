import express from "express"
import axios from "axios"

const port = 3000
const app = express()
const apiKey = 'REMOVED'

app.use(express.urlencoded({ extended: true }));

app.get("/", (req, res) => {
  res.render("index.ejs", {showResults: false})
})

app.use(express.static("public"))

app.post("/upload", async (req, res) => {
  const config = {
    headers: {
      accept: 'application/json',
      'x-apikey': apiKey
    }
  }

  const url = new URL(req.body.link)
  const domain = url.hostname

  try {
    const result = await axios.get(`https://www.virustotal.com/api/v3/domains/${domain}`, config)
    console.log(result.data)

    const attributes = result.data.data.attributes

    res.render("index.ejs", {
      showResults: true,
      harmless: attributes.total_votes.harmless,
      malicious: attributes.total_votes.malicious,
      vendor: attributes.last_analysis_results
    })

  } catch (error) {
    console.log(error.response.data)
    res.render("index.ejs", {content: JSON.stringify(error.response.data)})
  }
})

app.listen(port, () => {
  console.log(`Server running on port ${port}`)
})
