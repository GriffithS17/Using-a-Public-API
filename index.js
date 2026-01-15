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

app.post("/upload", async (req, res) => {
  const config = {
    headers: {
      accept: 'application/json',
      'x-apikey': apiKey
    }
  }

  let url = normalizeUrl(req.body.link)

  if (isValid(url)){
    url = new URL(url)
    console.log(url)
  } else {
    return res.render("index.ejs", {
      showResults: false,
      error: `${url} is not a valid URL.`
    })
  }

  const domain = url.hostname

  if (!isValidDomain(domain)) {
    return res.render("index.ejs", {
      showResults: false,
      error: `${domain} is not a valid domain.`
    })
  }

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

function normalizeUrl(input) {
  if (!/^https?:\/\//i.test(input)) {
    input = "https://" + input
  }

  return input
}

function isValid(url) {
  try {
    new URL(url);
    return true;
  } catch (e) {
    return false;
  }
}

function isValidDomain(domain) {
  const domainRegex =
    /^(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$/

  return domainRegex.test(domain)
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
