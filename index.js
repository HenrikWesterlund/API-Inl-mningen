const express = require("express");
const app = express();
const port = 3000;
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const mysql = require("mysql2");
const path = require("path");

const secretKey = "hemlig_nyckel_test";

// Skapa MySQL-anslutning med felhantering
const connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "api_db",
});

function verifyToken(req, res, next) {
  const token =
    req.headers.authorization && req.headers.authorization.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied: No token provided" });
  }

  try {
    const decoded = jwt.verify(token, secretKey);
    req.user = decoded;
    next(); // Token är giltig, fortsätt till nästa middleware/route-handler
  } catch (err) {
    return res.status(401).json({ error: "Access denied: Invalid token" });
  }
}

// Middleware för att hantera JSON-data
app.use(express.json());

// Servera statiska filer från "public" mappen
// app.use(express.static(path.join(__dirname, "public")));

// Root route som serverar HTML-filen från "public" mappen
app.get("/", (req, res) => {
  // res.sendFile(path.join(__dirname, "public", "index.html"));
  res.send(`
  <h1>API Dokumentation</h1>

  <h2>Gränssnitt</h2>
  <h3>API Routes</h3>
  <ul>
    <li><strong>GET /users:</strong> Returnerar en lista av alla användare.</li>
    <li><strong>GET /user/:id:</strong> Returnerar en användare angiven av det ID som anges.</li>
    <li><strong>POST /user:</strong> Skapar en ny användare.</li>
    <li><strong>PUT /user/:id:</strong> Uppdaterar en användare angiven av det ID som anges. Kräver inloggning (användning av verifyToken-middleware).</li>
    <li><strong>POST /login:</strong> Loggar in en användare och returnerar en JWT-token.</li>
    <li><strong>GET /protected-route:</strong> Kräver inloggning (användning av verifyToken-middleware).</li>
  </ul>

  <h2>Endpoints</h2>

  <h3>GET /users</h3>
  <p>Returnerar en lista över alla användare från databasen.</p>
  <p><strong>Exempel på svar:</strong></p>
  <ul>
    <li>Status: 200 OK</li>
    <li>Innehåll: JSON med en lista över användare</li>
  </ul>

  <h3>GET /user/:id</h3>
  <p>Returnerar en användare baserat på det angivna ID:et.</p>
  <p><strong>Exempel på svar:</strong></p>
  <ul>
    <li>Status: 200 OK</li>
    <li>Innehåll: JSON med användarinformation</li>
  </ul>
  <p><strong>Möjliga fel:</strong></p>
  <ul>
    <li>Status: 404 Not Found</li>
    <li>Innehåll: JSON med ett felmeddelande</li>
  </ul>

  <h3>POST /user</h3>
  <p>Skapar en ny användare med det angivna användarnamnet och lösenordet.</p>
  <p><strong>Innehåll:</strong> JSON med <code>username</code> och <code>password</code></p>
  <p><strong>Exempel på svar:</strong></p>
  <ul>
    <li>Status: 201 Created</li>
    <li>Innehåll: JSON med den nya användarens ID, användarnamn och det krypterade lösenordet</li>
  </ul>
  <p><strong>Möjliga fel:</strong></p>
  <ul>
    <li>Status: 400 Bad Request</li>
    <li>Innehåll: JSON med ett felmeddelande</li>
  </ul>

  <h3>PUT /user/:id</h3>
  <p>Uppdaterar en användare baserat på det angivna ID:et. Kräver autentisering (JWT-token).</p>
  <p><strong>Innehåll:</strong> JSON med <code>username</code> och <code>password</code></p>
  <p><strong>Exempel på svar:</strong></p>
  <ul>
    <li>Status: 200 OK</li>
    <li>Innehåll: JSON med den uppdaterade användarens information</li>
  </ul>
  <p><strong>Möjliga fel:</strong></p>
  <ul>
    <li>Status: 401 Unauthorized (om token är ogiltig)</li>
    <li>Status: 404 Not Found (om användaren inte finns)</li>
  </ul>

  <h3>POST /login</h3>
  <p>Loggar in en användare med användarnamn och lösenord, och returnerar en JWT-token.</p>
  <p><strong>Innehåll:</strong> JSON med <code>username</code> och <code>password</code></p>
  <p><strong>Exempel på svar:</strong></p>
  <ul>
    <li>Status: 200 OK</li>
    <li>Innehåll: JSON med en JWT-token</li>
  </ul>
  <p><strong>Möjliga fel:</strong></p>
  <ul>
    <li>Status: 404 Not Found (om användaren inte finns)</li>
    <li>Status: 401 Unauthorized (om lösenordet är fel)</li>
  </ul>

  <h3>GET /protected-route</h3>
  <p>Returnerar ett meddelande om att åtkomst har beviljats, samt information om användaren. Kräver autentisering (JWT-token).</p>
  <p><strong>Exempel på svar:</strong></p>
  <ul>
    <li>Status: 200 OK</li>
    <li>Innehåll: JSON med ett meddelande och användarinformation</li>
  </ul>

  <h2>Felmeddelanden</h2>
  <p>Alla endpoints kan returnera JSON som innehåller ett felmeddelande i fallet av ett fel, såsom statuskoderna 400, 401, 404 och 500. Felmeddelanden innehåller vanligtvis en kort förklaring av vad som gick fel.</p>

  <h2>Säkerhet</h2>
  <ul>
    <li>Använd JWT-token för att autentisera användare för skyddade rutter.</li>
    <li>Lösenord krypteras med bcrypt innan de lagras i databasen.</li>
    <li>Förvara inte känslig information i klartext i koden, såsom <code>secretKey</code>. Använd istället miljövariabler.</li>
  </ul>
`);
});

app.get("/livetest", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/protected-route", verifyToken, (req, res) => {
  // Din kod här
  res.json({ message: "Access granted", user: req.user });
});

// POST /user för att skapa en ny användare
app.post("/user", async (req, res) => {
  const { username, password } = req.body;

  try {
    // Kryptera lösenordet
    const hashedPassword = await bcrypt.hash(password, 10);

    // SQL-fråga för att lägga till användaren i databasen
    const query = "INSERT INTO user (username, password) VALUES (?, ?)";
    connection.query(query, [username, hashedPassword], (err, results) => {
      if (err) {
        // Hantera fel under SQL-frågan
        res.status(400).json({ error: err.message });
      } else {
        // Användare framgångsrikt tillagd
        res
          .status(201)
          .json({ id: results.insertId, username, password, hashedPassword });
      }
    });
  } catch (error) {
    // Hantera fel under lösenordskryptering
    res.status(500).json({ error: "Fel under lösenordskryptering" });
    console.error(error);
  }
});

// GET /resurs route för att returnera alla resurser
app.get("/users", (req, res) => {
  const query = "SELECT * FROM user";
  connection.query(query, (err, results) => {
    if (err) {
      res.status(500).json({ error: err.message });
    } else {
      res.json(results);
      // console.log(results);
    }
  });
});

// GET /resurs/:id route för att returnera en resurs efter id
app.get("/user/:id", (req, res) => {
  const query = "SELECT * FROM user WHERE id = ?";
  connection.query(query, [req.params.id], (err, results) => {
    if (err) {
      res.status(500).json({ error: err.message });
    } else if (results.length === 0) {
      res.status(404).json({ error: "User not found" });
    } else {
      res.json(results[0]);
    }
  });
});

// PUT /user/:id för att uppdatera en användare
app.put("/user/:id", verifyToken, async (req, res) => {
  const userId = req.params.id;
  const { username, password } = req.body;

  // Kryptera lösenordet innan uppdatering
  const hashedPassword = await bcrypt.hash(password, 10);

  // SQL-fråga för att uppdatera användaren
  const query = "UPDATE user SET username = ?, password = ? WHERE id = ?";
  connection.query(
    query,
    [username, hashedPassword, userId],
    (err, results) => {
      if (err) {
        res.status(500).json({ error: err.message });
      } else {
        if (results.affectedRows > 0) {
          // SQL-fråga för att hämta den uppdaterade användaren
          const selectQuery = "SELECT id, username FROM user WHERE id = ?";
          connection.query(
            selectQuery,
            [userId],
            (selectErr, selectResults) => {
              if (selectErr) {
                res.status(500).json({ error: selectErr.message });
              } else {
                res.json(selectResults[0]);
              }
            }
          );
        } else {
          res.status(404).json({ error: "User not found" });
        }
      }
    }
  );
});

// POST /login för inloggning
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  // SQL-fråga för att hitta användaren med det tillhandahållna användarnamnet
  const query = "SELECT * FROM user WHERE username = ?";
  connection.query(query, [username], async (err, results) => {
    if (err) {
      res.status(500).json({ error: err.message });
    } else if (results.length === 0) {
      res.status(404).json({ error: "User not found" });
    } else {
      const user = results[0];
      const isPasswordCorrect = await bcrypt.compare(password, user.password);

      if (isPasswordCorrect) {
        // Generera en JWT-token
        const token = jwt.sign(
          { id: user.id, username: user.username },
          secretKey,
          { expiresIn: "1h" } // Tokenet gäller i 1 timme
        );

        // Returnera token
        res.json({ token });
      } else {
        res.status(401).json({ error: "Incorrect password" });
      }
    }
  });
});

// Starta servern
app.listen(port, () => {
  console.log(`Servern körs på http://localhost:${port}`);
});
