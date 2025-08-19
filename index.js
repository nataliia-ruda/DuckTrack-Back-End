import express from "express";
import mysql from "mysql2";
import cors from "cors";
import bcrypt from "bcrypt";
import session from "express-session";
import dotenv from "dotenv";
import MySQLStoreFactory from "express-mysql-session";
import crypto from "crypto";
import nodemailer from "nodemailer";
import cron from "node-cron";

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

const markGhostedApplications = () => {
  const sql = `
    UPDATE job_applications
    JOIN users ON job_applications.users_user_id = users.user_id
    SET job_applications.status = 'ghosted'
    WHERE 
      job_applications.status = 'applied'
      AND users.auto_ghost_enabled = 1
      AND DATEDIFF(NOW(), job_applications.updated_at) > 21;
  `;

  db.query(sql, (err, result) => {
    if (err) {
      console.error("Error updating status applications:", err);
    } else {
      console.log(
        `Successfully changed status of ${result.affectedRows} applications.`
      );
    }
  });
};

cron.schedule(
  "0 3 * * *",
  () => {
    console.log("Running applications status check at 3:00 AM...");
    markGhostedApplications();
  },
  {
    scheduled: true,
    timezone: "Europe/Berlin",
  }
);

function getUserEmailById(userId) {
  return new Promise((resolve, reject) => {
    db.query(`SELECT email FROM users WHERE user_id = ?`, [userId], (e, r) => {
      if (e || r.length === 0) return reject(e || new Error("User not found"));
      resolve(r[0].email);
    });
  });
}

function makeTransporter() {
  return nodemailer.createTransport({
    service: "gmail",
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
  });
}

app.post("/signup", async function (req, res) {
  let newUser = req.body;

  const pw = newUser?.password ?? "";
  const strong =
    pw.length >= 8 &&
    /[A-Z]/.test(pw) &&
    /[^\w\s]/.test(pw) &&
    pw.trim() === pw;
  if (!strong) {
    return res.status(400).json({
      errorno: 0,
      message:
        "Password must be at least 8 characters, include an uppercase and a special character, and not start or end with a space.",
    });
  }

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

      if (!user.is_verified) {
        return res.status(403).json({
          verified: false,
          user_id: user.user_id,
          email: user.email,
          message: "Please verify your email before continuing.",
        });
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

app.post("/resend-verification", (req, res) => {
  const { email, user_id } = req.body;

  if (!email || !user_id) {
    return res.status(400).json({ message: "Missing email or user ID" });
  }

  db.query(
    `SELECT * FROM users WHERE user_id = ? AND email = ?`,
    [user_id, email],
    async (err, results) => {
      if (err || results.length === 0) {
        return res.status(404).json({ message: "User not found" });
      }

      const user = results[0];
      if (user.is_verified) {
        return res
          .status(400)
          .json({ message: "This email is already verified" });
      }

      const token = crypto.randomBytes(32).toString("hex");
      const expiresAt = new Date(Date.now() + 60 * 60 * 1000);

      db.query(
        `INSERT INTO action_tokens (user_id, token, type, expires_at) VALUES (?, ?, 'verify_email', ?)`,
        [user_id, token, expiresAt],
        async (err2) => {
          if (err2) {
            console.error("Token saving error:", err2);
            return res.status(500).json({ message: "Token generation failed" });
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
            to: email,
            subject: "Verify your email (resend)",
            html: `
            <h2>Hello again from DuckTrack!</h2>
            <p>You requested a new email verification link. Click the link below to verify your account:</p>
            <a href="${verifyLink}">${verifyLink}</a>
          `,
          });

          return res.status(200).json({
            message:
              "Verification email has been resent! Please check your inbox.",
          });
        }
      );
    }
  );
});

app.get("/me", (req, res) => {
  const sessUser = req.session.user;
  if (!sessUser) return res.json({ loggedIn: false });

  db.query(
    `SELECT user_id FROM users WHERE user_id = ?`,
    [sessUser.user_id],
    (e, r) => {
      if (e || r.length === 0) {
        req.session.destroy(() => {
          res.clearCookie("connect.sid");
          return res.json({ loggedIn: false });
        });
      } else {
        res.json({ loggedIn: true, user: sessUser });
      }
    }
  );
});

app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: "Email is required" });
  }

  db.query(
    `SELECT * FROM users WHERE email = ?`,
    [email],
    async (err, results) => {
      if (err) {
        console.error("DB error:", err);
        return res.status(500).json({ message: "Server error" });
      }

      if (results.length === 0) {
        return res.status(404).json({
          message: "We didn't find your account. Please, check email again.",
        });
      }

      const user = results[0];
      const token = crypto.randomBytes(32).toString("hex");
      const expiresAt = new Date(Date.now() + 60 * 60 * 1000);
      db.query(
        `INSERT INTO action_tokens (user_id, token, type, expires_at) VALUES (?, ?, 'reset_password', ?)`,
        [user.user_id, token, expiresAt],
        async (err2) => {
          if (err2) {
            console.error("Token DB error:", err2);
            return res.status(500).json({ message: "Server error" });
          }

          const transporter = nodemailer.createTransport({
            service: "gmail",
            auth: {
              user: process.env.EMAIL_USER,
              pass: process.env.EMAIL_PASS,
            },
          });

          const resetLink = `http://localhost:5173/reset-password?token=${token}`;

          await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: "DuckTrack - Password Reset",
            html: `
            <h2>Reset Your Password</h2>
            <p>Click below to set a new password:</p>
            <a href="${resetLink}">${resetLink}</a>
            <p>If you didn't request this, you can ignore this email.</p>
          `,
          });

          return res
            .status(200)
            .json({ message: "Reset email sent. Check your inbox." });
        }
      );
    }
  );
});

app.post("/reset-password", async (req, res) => {
  const { token, password } = req.body;

  if (!token || !password) {
    return res.status(400).json({ message: "Token and password are required" });
  }

  const strong =
    typeof password === "string" &&
    password.length >= 8 &&
    /[A-Z]/.test(password) &&
    /[^\w\s]/.test(password);
  if (!strong) {
    return res.status(400).json({
      message:
        "Password must be at least 8 characters and include an uppercase letter and a special character.",
    });
  }

  db.query(
    `SELECT * FROM action_tokens WHERE token = ? AND type = 'reset_password' AND expires_at > NOW()`,
    [token],
    async (err, results) => {
      if (err || results.length === 0) {
        return res.status(400).json({ message: "Invalid or expired token" });
      }

      const userId = results[0].user_id;
      const hashedPassword = await bcrypt.hash(password, 10);

      db.query(
        `UPDATE users SET password = ? WHERE user_id = ?`,
        [hashedPassword, userId],
        (err2) => {
          if (err2) {
            console.error("Password update error:", err2);
            return res.status(500).json({ message: "Server error" });
          }

          db.query(`DELETE FROM action_tokens WHERE token = ?`, [token]);

          res
            .status(200)
            .json({ message: "Password has been reset successfully!" });
        }
      );
    }
  );
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
    `SELECT * FROM job_applications WHERE application_id = ?`,
    [applicationId],
    (error, results) => {
      if (error) {
        console.error("Error fetching application:", error);
        return res.status(500).json({ message: "Server error" });
      }

      if (!results || results.length === 0) {
        return res.status(404).json({ message: "Application not found" });
      }

      res.status(200).json(results[0]);
    }
  );
});

app.patch("/interviews/:id", (req, res) => {
  const { id } = req.params;
  const { interview_date, location, contact_person, notes, type } = req.body;

  const sql = `
    UPDATE interviews
    SET interview_date = ?, location = ?, contact_person = ?, notes = ?, type = ?, updated_at = NOW()
    WHERE interview_id = ?
  `;

  db.query(
    sql,
    [interview_date, location, contact_person, notes, type || null, id],
    (err, result) => {
      if (err)
        return res.status(500).json({ message: "Failed to update interview" });
      res.status(200).json({ message: "Interview updated!" });
    }
  );
});

app.post("/interviews", (req, res) => {
  const { application_id, date, location, contact, notes, type } = req.body;

  if (!application_id || !date) {
    return res
      .status(400)
      .json({ message: "Application ID and date are required." });
  }

  db.beginTransaction((err) => {
    if (err) {
      console.error("TX begin error:", err);
      return res.status(500).json({ message: "Server error" });
    }

    const insertInterview = `
      INSERT INTO interviews 
        (application_id, interview_date, location, contact_person, notes, type, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, NOW(), NOW())
    `;

    db.query(
      insertInterview,
      [application_id, date, location, contact, notes, type || null],
      (insErr, result) => {
        if (insErr) {
          console.error("Error saving interview:", insErr);
          return db.rollback(() =>
            res.status(500).json({ message: "Failed to save interview." })
          );
        }

        const updateApplication = `
          UPDATE job_applications
          SET status = 'interviewing', updated_at = NOW()
          WHERE application_id = ?
            AND status NOT IN ('rejected','withdrawn','offer')
        `;

        db.query(updateApplication, [application_id], (updErr) => {
          if (updErr) {
            console.error("Error updating application status:", updErr);
            return db.rollback(() =>
              res.status(500).json({ message: "Failed to link interview." })
            );
          }

          db.commit((commitErr) => {
            if (commitErr) {
              console.error("TX commit error:", commitErr);
              return db.rollback(() =>
                res.status(500).json({ message: "Server error" })
              );
            }
            res.status(201).json({ message: "Interview saved successfully!" });
          });
        });
      }
    );
  });
});

app.get("/interviews", (req, res) => {
  const userId = req.session?.user?.user_id;

  if (!userId) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const query = `
    SELECT i.*, j.position_name, j.employer_name 
    FROM interviews i
    JOIN job_applications j ON i.application_id = j.application_id
    WHERE j.users_user_id = ?
    ORDER BY i.interview_date ASC
  `;

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error("Error fetching interviews:", err);
      return res.status(500).json({ message: "Failed to fetch interviews." });
    }

    res.status(200).json({ interviews: results });
  });
});

app.delete("/interviews/:id", (req, res) => {
  const { id } = req.params;
  db.query(`DELETE FROM interviews WHERE interview_id = ?`, [id], (err) => {
    if (err) return res.status(500).json({ message: "Delete failed" });
    res.status(200).json({ message: "Interview deleted" });
  });
});

app.get("/my-employers", (req, res) => {
  const user_id = req.session.user?.user_id;
  if (!user_id) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const query = `
    SELECT 
      MAX(application_id) AS application_id,
      employer_name
    FROM job_applications
    WHERE users_user_id = ?
    GROUP BY employer_name
    ORDER BY employer_name ASC
  `;

  db.query(query, [user_id], (err, results) => {
    if (err) {
      console.error("Error fetching employers:", err);
      return res.status(500).json({ message: "Internal server error" });
    }

    res.status(200).json({ employers: results });
  });
});

const sendInterviewReminders = () => {
  const sql = `
    SELECT i.interview_id, i.application_id, u.email, u.user_first_name, j.position_name, j.employer_name, i.interview_date 
    FROM interviews i
    JOIN job_applications j ON i.application_id = j.application_id
    JOIN users u ON j.users_user_id = u.user_id
    WHERE DATE(i.interview_date) = CURDATE() + INTERVAL 1 DAY
      AND i.reminder_sent = 0
  `;

  db.query(sql, async (err, results) => {
    if (err) {
      console.error("Error fetching interviews for reminder:", err);
      return;
    }

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    for (const row of results) {
      const formattedDate = new Date(row.interview_date).toLocaleString(
        "de-DE",
        {
          dateStyle: "full",
          timeStyle: "short",
        }
      );

      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: row.email,
        subject: "DuckTrack - Interview Reminder ",
        html: `
          <h3>Hello ${row.user_first_name}!</h3>
          <p>This is a reminder about your upcoming interview:</p>
          <ul>
            <li><strong>Position:</strong> ${row.position_name}</li>
            <li><strong>Employer:</strong> ${row.employer_name}</li>
            <li><strong>Date & Time:</strong> ${formattedDate}</li>
          </ul>
          <p>Don't forget to prepare and may the force of the duck be with you!</p>
        `,
      };

      try {
        await transporter.sendMail(mailOptions);
        console.log(`Reminder sent to ${row.email}`);

        db.query(
          `UPDATE interviews SET reminder_sent = 1 WHERE interview_id = ?`,
          [row.interview_id],
          (err2) => {
            if (err2) {
              console.error("Failed to update reminder_sent:", err2);
            } else {
              console.log(
                `reminder_sent updated for interview ID ${row.interview_id}`
              );
            }
          }
        );
      } catch (emailErr) {
        console.error(`Failed to send reminder to ${row.email}:`, emailErr);
      }
    }
  });
};

cron.schedule(
  "0 7 * * *", // every day at 7:00 AM
  () => {
    console.log("Running interview reminder check...");
    sendInterviewReminders();
  },
  {
    scheduled: true,
    timezone: "Europe/Berlin",
  }
);

cron.schedule(
  "0 * * * *", // hourly
  () => {
    console.log("Cleaning up expired tokens...");
    db.query(`DELETE FROM action_tokens WHERE expires_at <= NOW()`);
  },
  {
    scheduled: true,
    timezone: "Europe/Berlin",
  }
);

app.get("/get-user/:id", (req, res) => {
  const userId = req.params.id;

  db.query(
    `SELECT user_first_name, user_last_name, email, gender, auto_ghost_enabled FROM users WHERE user_id = ?`,
    [userId],
    (err, results) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ message: "Server error." });
      }

      if (results.length === 0) {
        return res.status(404).json({ message: "User not found." });
      }

      res.status(200).json(results[0]);
    }
  );
});

app.patch("/update-profile", async (req, res) => {
  const {
    user_id,
    firstName,
    lastName,
    gender,
    autoGhostEnabled,
    currentPassword,
    newPassword,
  } = req.body;

  try {
    db.query(
      `UPDATE users SET user_first_name = ?, user_last_name = ?, gender = ?, auto_ghost_enabled = ? WHERE user_id = ?`,
      [firstName, lastName, gender, autoGhostEnabled ? 1 : 0, user_id],
      (err) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ message: "Error updating profile." });
        }

        if (currentPassword && newPassword) {
          const strong =
            typeof newPassword === "string" &&
            newPassword.length >= 8 &&
            /[A-Z]/.test(newPassword) &&
            /[^\w\s]/.test(newPassword);
          if (!strong) {
            return res.status(400).json({
              message:
                "Password must be at least 8 characters and include an uppercase letter and a special character.",
            });
          }
          db.query(
            `SELECT password FROM users WHERE user_id = ?`,
            [user_id],
            async (err2, result) => {
              if (err2 || result.length === 0) {
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
                (err3) => {
                  if (err3) {
                    console.error(err3);
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
          return res
            .status(200)
            .json({ message: "Profile updated successfully." });
        }
      }
    );
  } catch (error) {
    console.error("Error updating profile:", error);
    res.status(500).json({ message: "Server error." });
  }
});

app.patch("/my-applications/:id", (req, res) => {
  const applicationId = Number(req.params.id);
  const {
    position_name,
    employer_name,
    application_date,
    employment_type,
    source,
    job_description,
    job_link,
    work_mode,
    status,
    notes,
  } = req.body;

  const sql = `
    UPDATE job_applications
    SET 
      position_name = ?, 
      employer_name = ?, 
      application_date = ?, 
      employment_type = ?, 
      source = ?, 
      job_description = ?, 
      job_link = ?, 
      work_mode = ?, 
      status = ?, 
      notes = ?, 
      updated_at = NOW()
    WHERE application_id = ?
  `;

  db.query(
    sql,
    [
      position_name,
      employer_name,
      application_date,
      employment_type,
      source,
      job_description,
      job_link,
      work_mode,
      status,
      notes,
      applicationId,
    ],
    (error, result) => {
      if (error) {
        console.error("Error updating application:", error);
        return res
          .status(500)
          .json({ message: "Failed to update application" });
      }

      res.status(200).json({ message: "Application updated successfully!" });
    }
  );
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

app.post("/request-delete-account", async (req, res) => {
  const userId = req.session?.user?.user_id;
  if (!userId) return res.status(401).json({ message: "Unauthorized" });

  db.query(
    `DELETE FROM action_tokens WHERE user_id = ? AND type = 'delete_account'`,
    [userId],
    async (delErr) => {
      if (delErr) {
        console.error(delErr);
        return res.status(500).json({ message: "Server error" });
      }

      const token = crypto.randomBytes(32).toString("hex");
      const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24h

      db.query(
        `INSERT INTO action_tokens (user_id, token, type, expires_at) VALUES (?, ?, 'delete_account', ?)`,
        [userId, token, expiresAt],
        async (insErr) => {
          if (insErr) {
            console.error(insErr);
            return res.status(500).json({ message: "Server error" });
          }

          try {
            const email = await getUserEmailById(userId);
            const transporter = makeTransporter();

            const confirmLink = `http://localhost:3000/confirm-delete-account?token=${token}`;

            await transporter.sendMail({
              from: process.env.EMAIL_USER,
              to: email,
              subject: "DuckTrack – Confirm account deletion",
              html: `
                <h2>Confirm account deletion</h2>
                <p>This will permanently delete your DuckTrack account and all related data (applications, interviews, settings).</p>
                <p>If you didn't request this, you can ignore this email.</p>
                <p><a href="${confirmLink}">Yes, delete my account</a></p>
              `,
            });

            return res.status(200).json({
              message:
                "We sent you an email with a confirmation link to delete your account.",
            });
          } catch (e) {
            console.error("Mail error:", e);
            return res.status(500).json({ message: "Failed to send email" });
          }
        }
      );
    }
  );
});

app.get("/confirm-delete-account", (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).send("Missing token");

  db.query(
    `SELECT * FROM action_tokens WHERE token = ? AND type = 'delete_account' AND expires_at > NOW()`,
    [token],
    (tokErr, tokRows) => {
      if (tokErr || tokRows.length === 0)
        return res.status(400).send("Invalid or expired link");
      const userId = tokRows[0].user_id;

      db.beginTransaction((txErr) => {
        if (txErr) {
          console.error(txErr);
          return res.status(500).send("Server error");
        }

        const deleteInterviews = `
          DELETE i FROM interviews i
          JOIN job_applications j ON i.application_id = j.application_id
          WHERE j.users_user_id = ?`;
        const deleteApplications = `DELETE FROM job_applications WHERE users_user_id = ?`;
        const deleteTokens = `DELETE FROM action_tokens WHERE user_id = ?`;
        const deleteUser = `DELETE FROM users WHERE user_id = ?`;

        db.query(deleteInterviews, [userId], (e1) => {
          if (e1) return rollback(e1, res);

          db.query(deleteApplications, [userId], (e2) => {
            if (e2) return rollback(e2, res);

            db.query(deleteTokens, [userId], (e3) => {
              if (e3) return rollback(e3, res);

              db.query(deleteUser, [userId], (e4) => {
                if (e4) return rollback(e4, res);

                db.commit((commitErr) => {
                  if (commitErr) return rollback(commitErr, res);

                  db.query(
                    `DELETE FROM action_tokens WHERE token = ?`,
                    [token],
                    () => {
                      return res.redirect(
                        "http://localhost:5173/account-deleted"
                      );
                    }
                  );
                });
              });
            });
          });
        });

        function rollback(err, res) {
          console.error("Delete account rollback:", err);
          db.rollback(() => res.status(500).send("Failed to delete account"));
        }
      });
    }
  );
});

app.use((req, res, next) => {
  res.status(404).send("Wrong route!");
});

app.listen(3000, () => {
  console.log(`Listening on http://localhost:3000`);
});
