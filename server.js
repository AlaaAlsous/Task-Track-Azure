import express from "express";
import fs from "fs";
import session from "express-session";
import bcryptjs from "bcryptjs";
import path from "node:path";
import sql from "mssql";
import dotenv from "dotenv";
dotenv.config();

let sessionSecret = process.env.SESSIONSECRET;
let sqlConnectionString = process.env.SqlConnectionString;

async function loadSecretsAndStart() {
  if (sessionSecret && sqlConnectionString) {
    console.log("Running locally");
    await connectToSql();
    startServer();
    return;
  }

  const keyVaultName = "kv-task-track";
  const { DefaultAzureCredential } = await import("@azure/identity");
  const { SecretClient } = await import("@azure/keyvault-secrets");
  const credential = new DefaultAzureCredential();
  const vaultUrl = `https://${keyVaultName}.vault.azure.net`;
  const client = new SecretClient(vaultUrl, credential);

  const sessionSecretObj = await client.getSecret("SESSIONSECRET");
  if (!sessionSecretObj.value)
    throw new Error("SESSIONSECRET is missing in Key Vault");
  sessionSecret = sessionSecretObj.value;

  const sqlSecretObj = await client.getSecret("SqlConnectionString");
  if (!sqlSecretObj.value)
    throw new Error("SqlConnectionString is missing in Key Vault");
  sqlConnectionString = sqlSecretObj.value;
  await connectToSql();
  console.log("Finished connecting to SQL, starting server");
  startServer();
}

let db;
async function connectToSql() {
  try {
    db = await sql.connect(sqlConnectionString);
    console.log("Connected to Azure SQL Database/SQL Server!");

    await db.request().query(`
      IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'users')
      CREATE TABLE users (
        id INT IDENTITY(1,1) PRIMARY KEY,
        username NVARCHAR(50) NOT NULL UNIQUE,
        passwordHash NVARCHAR(255) NOT NULL
      );
      IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'tasks')
      CREATE TABLE tasks (
        id INT IDENTITY(1,1) PRIMARY KEY,
        userId INT NOT NULL,
        taskText NVARCHAR(100) NOT NULL,
        priority NVARCHAR(10) NOT NULL,
        deadline DATETIME NULL,
        category NVARCHAR(20) NOT NULL,
        done BIT NOT NULL,
        FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
      );
    `);
  } catch (err) {
    throw new Error("Could not connect to SQL: " + err.message);
  }
}

loadSecretsAndStart();

function startServer() {
  console.log("Starting server...");
  const app = express();
  const port = process.env.PORT || 3000;
  console.log("Listening on port:", port);

  app.get("/", (req, res) => {
    res.sendFile("index.html", { root: "public" });
  });

  app.set("trust proxy", 1);
  app.use(express.static("public"));
  app.use(express.json());

  const isProd = false;
  app.use(
    session({
      name: "sid",
      secret: sessionSecret,
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        secure: isProd,
        sameSite: isProd ? "none" : "lax",
        maxAge: 1000 * 60 * 60 * 24 * 7,
      },
    }),
  );

  app.post("/api/auth/register", async (req, res) => {
    try {
      const { username, password } = req.body;
      if (!username || !password) {
        return res
          .status(400)
          .json({ error: "Username and password are required." });
      }
      const result = await db
        .request()
        .input("username", sql.NVarChar(50), username)
        .query("SELECT id FROM users WHERE LOWER(username) = LOWER(@username)");
      if (result.recordset.length > 0) {
        return res.status(409).json({ error: "User already exists." });
      }
      const passwordHash = await bcryptjs.hash(String(password), 10);
      const insertResult = await db
        .request()
        .input("username", sql.NVarChar(50), username)
        .input("passwordHash", sql.NVarChar(255), passwordHash)
        .query(
          "INSERT INTO users (username, passwordHash) OUTPUT INSERTED.id VALUES (@username, @passwordHash)",
        );
      const userId = insertResult.recordset[0].id;
      req.session.userId = userId;
      res.status(201).json({ id: userId, username });
    } catch (err) {
      res.status(500).json({ error: "Internal server error." });
    }
  });

  app.post("/api/auth/login", async (req, res) => {
    try {
      const { username, password } = req.body;
      if (!username || !password) {
        return res
          .status(400)
          .json({ error: "Username and password are required." });
      }
      const result = await db
        .request()
        .input("username", sql.NVarChar(50), username)
        .query(
          "SELECT id, passwordHash FROM users WHERE LOWER(username) = LOWER(@username)",
        );
      if (result.recordset.length === 0) {
        return res
          .status(401)
          .json({ error: "Username or password is incorrect." });
      }
      const user = result.recordset[0];
      const valid = await bcryptjs.compare(String(password), user.passwordHash);
      if (!valid) {
        return res
          .status(401)
          .json({ error: "Username or password is incorrect." });
      }
      req.session.userId = user.id;
      res.json({ id: user.id, username });
    } catch (err) {
      res.status(500).json({ error: "Internal server error." });
    }
  });

  app.post("/api/auth/logout", (req, res) => {
    req.session.destroy((err) => {
      if (err) return res.status(500).json({ error: "Could not logout." });
      res.clearCookie("sid");
      res.status(204).end();
    });
  });

  app.get("/api/auth/me", async (req, res) => {
    if (!req.session.userId) {
      return res.status(401).json({ error: "The user is not logged in." });
    }
    try {
      const result = await db
        .request()
        .input("id", sql.Int, req.session.userId)
        .query("SELECT id, username FROM users WHERE id = @id");
      if (result.recordset.length === 0) {
        return res.status(401).json({ error: "The user is not logged in." });
      }
      const user = result.recordset[0];
      res.json({ id: user.id, username: user.username });
    } catch (err) {
      res.status(500).json({ error: "Internal server error." });
    }
  });

  function requireAuth(req, res, next) {
    if (!req.session.userId) {
      return res.status(401).json({ error: "The user is not logged in." });
    }
    next();
  }

  app.get("/api/tasks", requireAuth, async (req, res) => {
    try {
      const result = await db
        .request()
        .input("userId", sql.Int, req.session.userId).query(`
          SELECT *,
            ROW_NUMBER() OVER (ORDER BY id) AS userTaskNumber
          FROM tasks
          WHERE userId = @userId
          ORDER BY id
        `);
      res.json(result.recordset);
    } catch {
      res
        .status(500)
        .json({ error: "Internal server error. Please try again later." });
    }
  });

  app.post("/api/tasks", requireAuth, async (req, res) => {
    try {
      const { taskText, deadline, priority, category } = req.body;
      if (!taskText || !String(taskText).trim()) {
        return res.status(400).json({ error: "Task text is required." });
      }
      const allowedPriorities = new Set(["Low", "Medium", "High"]);
      const allowedCategories = new Set([
        "Private",
        "Work",
        "School",
        "No Category",
      ]);
      const priorityVal = allowedPriorities.has(priority) ? priority : "Low";
      const categoryVal = allowedCategories.has(category)
        ? category
        : "No Category";
      const insertResult = await db
        .request()
        .input("userId", sql.Int, req.session.userId)
        .input("taskText", sql.NVarChar(100), String(taskText).trim())
        .input("priority", sql.NVarChar(10), priorityVal)
        .input("deadline", sql.DateTime, deadline || null)
        .input("category", sql.NVarChar(20), categoryVal)
        .input("done", sql.Bit, false)
        .query(`INSERT INTO tasks (userId, taskText, priority, deadline, category, done)
                OUTPUT INSERTED.*
                VALUES (@userId, @taskText, @priority, @deadline, @category, @done)`);
      res.status(201).json(insertResult.recordset[0]);
    } catch {
      res
        .status(500)
        .json({ error: "Internal server error. Please try again later." });
    }
  });

  app.patch("/api/tasks/:id", requireAuth, async (req, res) => {
    try {
      const taskId = Number(req.params.id);
      const { done, taskText, priority, deadline, category } = req.body;

      const result = await db
        .request()
        .input("id", sql.Int, taskId)
        .input("userId", sql.Int, req.session.userId)
        .query("SELECT * FROM tasks WHERE id = @id AND userId = @userId");
      if (result.recordset.length === 0) {
        return res.status(404).json({ error: "Task not found." });
      }
      const task = result.recordset[0];

      let updates = [];
      let params = { id: taskId, userId: req.session.userId };
      if (typeof done === "boolean") {
        updates.push("done = @done");
        params.done = done;
      }
      if (typeof taskText === "string") {
        const trimmed = taskText.trim();
        if (!trimmed)
          return res.status(400).json({ error: "Task text is required." });
        updates.push("taskText = @taskText");
        params.taskText = trimmed;
      }
      if (typeof priority === "string") {
        const allowedPriorities = new Set(["Low", "Medium", "High"]);
        if (!allowedPriorities.has(priority))
          return res.status(400).json({ error: "Invalid priority value." });
        updates.push("priority = @priority");
        params.priority = priority;
      }
      if (category !== undefined) {
        if (category === null) {
          updates.push("category = @category");
          params.category = "No Category";
        } else if (typeof category === "string") {
          const allowedCategories = new Set([
            "Private",
            "Work",
            "School",
            "No Category",
          ]);
          if (!allowedCategories.has(category))
            return res.status(400).json({ error: "Invalid category value." });
          updates.push("category = @category");
          params.category = category;
        }
      }
      if (deadline !== undefined) {
        if (deadline === null || deadline === "") {
          updates.push("deadline = @deadline");
          params.deadline = null;
        } else if (typeof deadline === "string") {
          const valid = /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(deadline);
          if (!valid)
            return res.status(400).json({ error: "Invalid deadline format." });
          updates.push("deadline = @deadline");
          params.deadline = deadline;
        }
      }
      if (updates.length === 0) {
        return res.json(task);
      }

      let reqSql = db
        .request()
        .input("id", sql.Int, params.id)
        .input("userId", sql.Int, params.userId);
      if ("done" in params) reqSql = reqSql.input("done", sql.Bit, params.done);
      if ("taskText" in params)
        reqSql = reqSql.input("taskText", sql.NVarChar(100), params.taskText);
      if ("priority" in params)
        reqSql = reqSql.input("priority", sql.NVarChar(10), params.priority);
      if ("category" in params)
        reqSql = reqSql.input("category", sql.NVarChar(20), params.category);
      if ("deadline" in params)
        reqSql = reqSql.input("deadline", sql.DateTime, params.deadline);
      await reqSql.query(
        `UPDATE tasks SET ${updates.join(", ")} WHERE id = @id AND userId = @userId`,
      );

      const updated = await db
        .request()
        .input("id", sql.Int, taskId)
        .query("SELECT * FROM tasks WHERE id = @id");
      res.json(updated.recordset[0]);
    } catch {
      res
        .status(500)
        .json({ error: "Internal server error. Please try again later." });
    }
  });

  app.delete("/api/tasks/:id", requireAuth, async (req, res) => {
    try {
      const taskId = Number(req.params.id);
      const result = await db
        .request()
        .input("id", sql.Int, taskId)
        .input("userId", sql.Int, req.session.userId)
        .query("DELETE FROM tasks WHERE id = @id AND userId = @userId");
      if (result.rowsAffected[0] === 0) {
        return res.status(404).json({ error: "Task not found" });
      }
      res.status(204).end();
    } catch {
      res
        .status(500)
        .json({ error: "Internal server error. Please try again later." });
    }
  });

  app.use((req, res) => {
    res.status(404).sendFile("404.html", { root: "public" });
  });

  app.listen(port, () => {
    console.log(`http://localhost:${port}`);
  });
}
