import express from "express";
import mysql from "mysql2";
import cors from "cors";
import bcrypt from "bcrypt";
import session from "express-session";
import dotenv from "dotenv";
import MySQLStoreFactory from "express-mysql-session";
import crypto from "crypto";
import nodemailer from "nodemailer";

const app = express();

dotenv.config();

app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true,
  })
);

app.use(express.json());

const MySQLStore = MySQLStoreFactory(session);

const sessionStore = new MySQLStore({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
      httpOnly: true,
      secure: false,
      maxAge: 24 * 60 * 60 * 1000,
    },
  })
);

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

app.post("/signup", async function (req, res) {
  let newUser = req.body;
  try {
    const hashedPassword = await bcrypt.hash(newUser.password, 10);

    db.query(
      `INSERT INTO users (user_first_name, user_last_name, gender, email, password) VALUES(?, ?, ?, ?,?)`,
      [
        newUser.user_first_name,
        newUser.user_last_name,
        newUser.gender,
        newUser.email,
        hashedPassword,
      ],
      (error, result, fields) => {
        if (error) {
          console.log(error);
          if (error.errno === 1062) {
            res.status(409).json({
              errorno: error.errno,
              message: "Account with this email already exists!",
            });
          } else {
            res
              .status(404)
              .json({ errorno: error.errno, message: error.message });
          }
        } else {
          const userId = result.insertId;

          const token = crypto.randomBytes(32).toString("hex");

          const expiresAt = new Date(Date.now() + 60 * 60 * 1000);

          db.query(
            `INSERT INTO action_tokens (user_id, token, type, expires_at) VALUES (?, ?, 'verify_email', ?)`,
            [userId, token, expiresAt],
            async (err) => {
              if (err) {
                console.log(err);
                return res.status(500).json({ message: "Token error" });
              }

              const transporter = nodemailer.createTransport({
                service: "gmail",
                auth: {
                  user: process.env.EMAIL_USER,
                  pass: process.env.EMAIL_PASS,
                },
              });

              const verifyLink = `http://localhost:5173/verify-email?token=${token}`;

              await transporter.sendMail({
                from: process.env.EMAIL_USER,
                to: newUser.email,
                subject: "Please confirm your email",
                html: `
                  <h2>Thank you for registration in DuckTrack!</h2>
                  <p>Click the link below to confirm your email and complete registration:</p>
                  <a href="${verifyLink}">${verifyLink}</a>
                `,
              });

              res.status(200).json({
                message: "Account created! Please check your email to verify.",
              });
            }
          );
        }
      }
    );
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: "Error" });
  }
});

app.post("/verify-email", (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ message: "Missing token" });
  }

  db.query(
    `SELECT * FROM action_tokens WHERE token = ? AND type = 'verify_email' AND expires_at > NOW()`,
    [token],
    (err, results) => {
      if (err || results.length === 0) {
        return res.status(400).json({ message: "Invalid or expired token" });
      }

      const userId = results[0].user_id;

      db.query(`UPDATE users SET is_verified = 1 WHERE user_id = ?`, [userId]);

      db.query(`DELETE FROM action_tokens WHERE token = ?`, [token]);

      res.status(200).json({ message: "Email verified successfully!" });
    }
  );
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }

  db.query(
    `SELECT * FROM users WHERE email = ?`,
    [email],
    async (error, result) => {
      if (error) {
        console.error("Database query error:", error);
        return res.status(500).json({ message: "Internal server error" });
      }

      if (result.length === 0) {
        return res
          .status(401)
          .json({ found: false, message: "Wrong credentials!" });
      }

      const user = result[0];
      const match = await bcrypt.compare(password, user.password);

      if (!match) {
        return res
          .status(401)
          .json({ found: false, message: "Wrong credentials!" });
      }

      req.session.user = {
        user_id: user.user_id,
        user_first_name: user.user_first_name,
        user_last_name: user.user_last_name,
        gender: user.gender,
      };

      res.status(200).json({
        message: "Logged in",
        user: req.session.user,
      });
    }
  );
});

app.get("/me", (req, res) => {
  if (req.session.user) {
    res.json({ loggedIn: true, user: req.session.user });
  } else {
    res.json({ loggedIn: false });
  }
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.send({ message: "Logged out" });
  });
});

app.post("/new-application", function (req, res) {
  let newApplication = req.body;

  db.query(
    `INSERT INTO job_applications (position_name, employer_name, application_date, employment_type, source, job_description, job_link, users_user_id, work_mode, status, notes) 
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      newApplication.position_name,
      newApplication.employer_name,
      newApplication.application_date,
      newApplication.employment_type,
      newApplication.source,
      newApplication.job_description,
      newApplication.job_link,
      newApplication.user_id,
      newApplication.work_mode,
      newApplication.status,
      newApplication.notes,
    ],
    (error, result, fields) => {
      if (error) {
        console.log(error);
        if (error.errno === 1062) {
          res
            .status(409)
            .json({ errorno: error.errno, message: "Repeated entry!" });
        } else {
          res
            .status(404)
            .json({ errorno: error.errno, message: error.message });
        }
      } else {
        res.status(200).json({ message: "New application created!" });
      }
    }
  );
});

app.get("/my-applications", (req, res) => {
  const user_id = req.query.user_id;
  const search = req.query.search;
  const sort = req.query.sort || "created_at";
  const order = req.query.order === "asc" ? "ASC" : "DESC";
  const status = req.query.status;

  if (!user_id) {
    return res.status(400).json({ message: "User ID is required" });
  }

  let query = `SELECT * FROM job_applications WHERE users_user_id = ?`;
  const params = [user_id];

  if (search) {
    let searchPattern = `%${search}%`;
    query += ` AND (position_name LIKE ? OR employer_name LIKE ? OR status LIKE ?)`;
    params.push(searchPattern, searchPattern, searchPattern);
  }

  if (status) {
    query += ` AND status = ?`;
    params.push(status);
  }

  if (["position_name", "employer_name", "created_at"].includes(sort)) {
    query += ` ORDER BY ${sort} ${order}`;
  } else {
    query += ` ORDER BY created_at DESC`;
  }

  db.query(query, params, (error, results) => {
    if (error) {
      console.error("Database query error:", error);
      return res.status(500).json({ message: "Internal server error" });
    }

    res.status(200).json({ applications: results });
  });
});

app.get("/my-applications/:id", function (req, res) {
  let applicationId = Number(req.params.id);
  db.query(
    `SELECT * FROM job_applications WHERE application_id=${applicationId}`,
    (error, result, fields) => {
      res.status(200).json(result[0]);
    }
  );
});

app.patch("/my-applications/:id", function (req, res) {
  let applicationId = Number(req.params.id);
  let updatedApplication = req.body;
  let dateOfUpdate = new Date();

  db.query(
    `UPDATE job_applications 
     SET position_name = ?, employer_name = ?, application_date = ?, employment_type = ?, source = ?, job_description = ?, job_link = ?, work_mode = ?, status = ?,updated_at = ?, notes = ?
     WHERE application_id = ?`,
    [
      updatedApplication.position_name,
      updatedApplication.employer_name,
      updatedApplication.application_date,
      updatedApplication.employment_type,
      updatedApplication.source,
      updatedApplication.job_description,
      updatedApplication.job_link,
      updatedApplication.work_mode,
      updatedApplication.status,
      dateOfUpdate,
      updatedApplication.notes,
      applicationId,
    ],
    (error, result, fields) => {
      if (error) {
        console.log(error);
        if (error.errno === 1062) {
          res
            .status(409)
            .json({ errno: error.errno, message: "Repeated entry!" });
        } else {
          res.status(500).json({ errno: error.errno, message: error.message });
        }
      } else {
        res.status(200).json({
          message: "Application updated!",
          affectedRows: result.affectedRows,
        });
      }
    }
  );
});

app.get("/get-user/:id", (req, res) => {
  const userId = req.params.id;
  const query = `SELECT * FROM users WHERE user_id = ${userId}`;

  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).send("Error fetching user data");
    }

    res.json(results[0]);
  });
});

app.patch("/update-profile", async (req, res) => {
  const { user_id, firstName, lastName, gender, currentPassword, newPassword } =
    req.body;

  try {
    db.query(
      `UPDATE users SET user_first_name = ?, user_last_name = ?, gender = ? WHERE user_id = ?`,
      [firstName, lastName, gender, user_id]
    );

    if (currentPassword && newPassword) {
      db.query(
        `SELECT password FROM users WHERE user_id = ?`,
        [user_id],
        async (err, result) => {
          if (err || result.length === 0) {
            return res.status(404).json({ message: "User not found." });
          }

          const storedHash = result[0].password;

          const isMatch = await bcrypt.compare(currentPassword, storedHash);

          if (!isMatch) {
            return res
              .status(403)
              .json({ message: "Current password is incorrect." });
          }

          const hashedNewPassword = await bcrypt.hash(newPassword, 10);

          db.query(
            `UPDATE users SET password = ? WHERE user_id = ?`,
            [hashedNewPassword, user_id],
            (err2) => {
              if (err2) {
                console.error(err2);
                return res
                  .status(500)
                  .json({ message: "Error updating password." });
              }

              return res
                .status(200)
                .json({ message: "Profile and password updated." });
            }
          );
        }
      );
    } else {
      return res.status(200).json({ message: "Profile updated successfully." });
    }
  } catch (error) {
    console.error("Error updating profile:", error);
    res.status(500).json({ message: "Server error." });
  }
});

app.delete("/my-applications/:id", function (req, res) {
  let applicationId = Number(req.params.id);

  if (typeof applicationId !== "number") {
    res.status(404).json({ message: "Inexistent application" });
  } else {
    db.query(
      `DELETE FROM job_applications WHERE application_id = ?`,
      [applicationId],
      (error, result, fields) => {
        res.status(200).json({ message: "Application deleted" });
      }
    );
  }
});

app.use((req, res, next) => {
  res.status(404).send("Wrong route!");
});

app.listen(3000, () => {
  console.log(`Listening on http://localhost:3000`);
});
