import express from "express";
import mysql from "mysql2";
import cors from "cors";
import bcrypt from "bcrypt";

const app = express();

app.use(
  cors({
    origin: "*",
  })
);

app.use(express.json());

const db = mysql.createConnection({
  host: "localhost",
  user: "",
  password: "",
  database: "",
});

app.post("/signup", async function (req, res) {
  let newUser = req.body;
  try {
    const hashedPassword = await bcrypt.hash(newUser.password, 10);

    db.query(
      `INSERT INTO users (user_first_name, user_last_name, email, password) VALUES(?, ?, ?, ?)`,
      [
        newUser.user_first_name,
        newUser.user_last_name,
        newUser.email,
        hashedPassword,
      ],
      (error, result, fields) => {
        if (error) {
          console.log(error);
          if (error.errno === 1062) {
            res
              .status(409)
              .json({
                errorno: error.errno,
                message: "Account with this email already exists!",
              });
          } else {
            res
              .status(404)
              .json({ errorno: error.errno, message: error.message });
          }
        } else {
          res
            .status(200)
            .json({ message: "Account was successfully created!" });
        }
      }
    );
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: "Error" });
  }
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

      res.status(200).json({
        found: true,
        data: {
          user_id: user.user_id,
          user_first_name: user.user_first_name,
          user_last_name: user.user_last_name,
        },
      });
    }
  );
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
      newApplication.notes
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
        res
          .status(200)
          .json({
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



app.patch("/update-profile/:id", function (req, res) {
  const userId = req.params.user_id;
  let updatedProfile = req.body;
    db.query(
      `UPDATE users 
       SET user_first_name = ?, user_last_name = ?, email = ?, employment_type = ?,
       photo = ?,
       WHERE user_id= ?`,
      [  updatedProfile.user_first_name,
         updatedProfile.user_last_name,
         updatedProfile.email, 
         updatedProfile.photo,
         userId,
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
        res.status(200).json({ message: "New Application created!" });
      }
    }
  );
});

app.delete('/my-applications/:id', function(req,res) {
  let applicationId=Number(req.params.id);
 
  if (typeof applicationId !== 'number') {
      res.status(404).json({ message: "Inexistent application" });
  } else {

      db.query(`DELETE FROM job_applications WHERE application_id = ?`, [applicationId], (error, result, fields) => {
          res.status(200).json({ message: "Application deleted" });
      });
  }
});









app.use((req, res, next) => {
  res.status(404).send("Wrong route!");
});

app.listen(3000, () => {
  console.log(`Listening on http://localhost:3000`);
});
