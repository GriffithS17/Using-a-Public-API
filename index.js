import express from "express"
import axios from "axios"

const port = 3000
const app = express()
const apiKey = 'REMOVED'

app.use(express.urlencoded({ extended: true }));

app.get("/", (req, res) => {
  res.render("index.ejs", {showResults: false, error: null})
})

app.use(express.static("public"))

function normalizeUrl(input) {
  if (!/^https?:\/\//i.test(input)) {
    return 'https://' + input
  }
  return input
}

function verifyThreatLevel(a){
  var threatLevel

  if (a == 'harmless' || a == 'clean'){
    threatLevel = 3
  }
  else if (a == 'suspicious'){
    threatLevel = 2
  }
  else if (a == 'undetected' || a == 'unrated'){
    threatLevel = 4
  }
  else{
    threatLevel = 1
  }

  return threatLevel
}

app.post("/upload", async (req, res) => {
  const config = {
    headers: {
      accept: 'application/json',
      'x-apikey': apiKey
    }
  }

  const normalized = normalizeUrl(req.body.link)

  const url = new URL(normalized)
  const domain = url.hostname

  try {
    const result = await axios.get(`https://www.virustotal.com/api/v3/domains/${domain}`, config)
    console.log(result.data)

    const attributes = result.data.data.attributes

    const vendor = attributes.last_analysis_results

    const sortedVendors = Object.keys(vendor).sort((a, b) => {
      const scoreA = verifyThreatLevel(vendor[a].result)
      const scoreB = verifyThreatLevel(vendor[b].result)

      return scoreA - scoreB
    })

    res.render("index.ejs", {
      showResults: true,
      harmless: attributes.total_votes.harmless,
      malicious: attributes.total_votes.malicious,
      vendor: vendor,
      sortedVendors: sortedVendors,
      name: result.data.data.id,
      error: null
    })

  } catch (error) {
    console.log(error.response?.data)
    res.render("index.ejs", {
      showResults: false,
      error: "Failed to analyze this URL. It is not a valid domain."
    })
  }
})

app.listen(port, () => {
  console.log(`Server running on port ${port}`)
})
