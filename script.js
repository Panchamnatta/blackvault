const apiKey = '096df6a98b9a3a43dbf1a8990c427355f47170986db964765c235c26225a4f59';

function isValidURL(input) {
  try {
    let testInput = input.trim();
    if (!/^https?:\/\//i.test(testInput)) {
      testInput = 'https://' + testInput;
    }
    const url = new URL(testInput);
    return !!url.hostname && /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(url.hostname);
  } catch (_) {
    return false;
  }
}

async function scan() {
  document.getElementById("summaryChart").style.display = "none";
  const input = document.getElementById("urlInput").value.trim();
  const file = document.getElementById("fileInput").files[0];
  const resultDiv = document.getElementById("result");
  const heatmap = document.getElementById("heatmap");
  const summary = document.getElementById("summary");

  resultDiv.style.display = "block";
  resultDiv.textContent = "Scanning...";
  resultDiv.className = "result";
  heatmap.innerHTML = "";
  summary.innerHTML = "";

  try {
    let clean = 0, malicious = 0, unrated = 0, total = 0;

    if (input && /^\d{1,3}(\.\d{1,3}){3}$/.test(input)) {
      // IP Address
      const ipRes = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${input}`, {
        headers: { "x-apikey": apiKey }
      });
      const ipData = await ipRes.json();
      const lastAnalysis = ipData.data.attributes.last_analysis_stats;

      if (lastAnalysis.malicious > 0 || lastAnalysis.suspicious > 0) {
        resultDiv.classList.add("red");
        resultDiv.textContent = `Malicious!!, Suspicious!`;
      } else {
        resultDiv.classList.add("green");
        resultDiv.textContent = `Clean! Harmless`;
      }

      const results = ipData.data.attributes.last_analysis_results;
      total = Object.keys(results).length;

      for (const scanner in results) {
        const category = results[scanner].category;
        const div = document.createElement("div");
        div.classList.add("scanner-tile");
        div.textContent = scanner;

        if (category === "malicious" || category === "suspicious") {
          div.classList.add("malicious");
          malicious++;
        } else if (category === "undetected" || category === "harmless") {
          div.classList.add("clean");
          clean++;
        } else {
          div.classList.add("undetected");
          unrated++;
        }

        div.onclick = () => {
          const detail = results[scanner];
          document.getElementById("modalDetails").innerHTML = `<pre>${JSON.stringify(detail, null, 2)}</pre>`;
          document.getElementById("modal").style.display = "flex";
        };

        heatmap.appendChild(div);
      }

    } else {
      let analysisId;

      if (input && isValidURL(input)) {
        let normalizedURL = input;
        if (!/^https?:\/\//i.test(normalizedURL)) {
          normalizedURL = 'https://' + normalizedURL;
        }

        const res = await fetch("https://www.virustotal.com/api/v3/urls", {
          method: "POST",
          headers: {
            "x-apikey": apiKey,
            "Content-Type": "application/x-www-form-urlencoded"
          },
          body: new URLSearchParams({ url: normalizedURL })
        });
        const data = await res.json();
        if (!data.data?.id) throw new Error("No ID in response");
        analysisId = data.data.id;

      } else if (file) {
        const formData = new FormData();
        formData.append("file", file);
        const upload = await fetch("https://www.virustotal.com/api/v3/files", {
          method: "POST",
          headers: { "x-apikey": apiKey },
          body: formData
        });
        const data = await upload.json();
        if (!data.data?.id) throw new Error("No ID in response");
        analysisId = data.data.id;

      } else {
        resultDiv.classList.add("red");
        resultDiv.textContent = "Please provide a URL, IP address, or file.";
        return;
      }

      await new Promise(r => setTimeout(r, 3000)); // Wait for analysis

      const analysis = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
        headers: { "x-apikey": apiKey }
      });
      const result = await analysis.json();
      const stats = result.data.attributes.stats;

      if (stats.malicious > 0 || stats.suspicious > 0) {
        resultDiv.classList.add("red");
        resultDiv.textContent = `Malicious: ${stats.malicious}, Suspicious: ${stats.suspicious}`;
      } else {
        resultDiv.classList.add("green");
        resultDiv.textContent = `Clean! Harmless`;
      }

      const results = result.data.attributes.results;
      total = Object.keys(results).length;

      for (const scanner in results) {
        const category = results[scanner].category;
        const div = document.createElement("div");
        div.classList.add("scanner-tile");
        div.textContent = scanner;

        if (category === "malicious" || category === "suspicious") {
          div.classList.add("malicious");
          malicious++;
        } else if (category === "undetected" || category === "harmless") {
          div.classList.add("clean");
          clean++;
        } else {
          div.classList.add("undetected");
          unrated++;
        }

        div.onclick = () => {
          const detail = results[scanner];
          document.getElementById("modalDetails").innerHTML = `<pre>${JSON.stringify(detail, null, 2)}</pre>`;
          document.getElementById("modal").style.display = "flex";
        };

        heatmap.appendChild(div);
      }
    }

    // Summary section
    summary.innerHTML = `
      <p>Total Scanners: <strong>${total}</strong></p>
      <p style="color:#00ff00;">Clean: ${clean}</p>
      <p style="color:#ff0000;">Malicious/Suspicious: ${malicious}</p>
      <p>Unrated: ${unrated}</p>`;

    // Chart section
    document.getElementById('summaryChart').style.display = "block";
    const ctx = document.getElementById('summaryChart').getContext('2d');
    if (window.summaryChart instanceof Chart) window.summaryChart.destroy();

    window.summaryChart = new Chart(ctx, {
      type: 'pie',
      data: {
        labels: ['Clean', 'Malicious/Suspicious', 'Unrated'],
        datasets: [{
          data: [clean, malicious, unrated],
          backgroundColor: ['#00ff00', '#ff0000', '#888888'],
        }]
      },
      options: {
        responsive: true,
        plugins: {
          legend: {
            labels: { color: '#fff' }
          }
        }
      }
    });

  } catch (err) {
    console.error(err);
    resultDiv.classList.add("red");
    resultDiv.textContent = "Error scanning. Check console.";
  }
}
