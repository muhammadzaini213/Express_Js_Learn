const express = require("express");
const cors = require("cors");
const mysql = require("mysql");
const path = require("path");
const app = express();
require('dotenv').config();

var corsOptions = {
 // origin: "http://localhost:8081"
  origin: true
};

app.use(express.json());

app.use(express.urlencoded({ extended: true }));


app.get("/", (req, res) => {
 res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const connection = mysql.createConnection({
  host: 'sql12.freesqldatabase.com',
  user: 'sql12725260',
  password: '7RLxBbNh9P',
  database: 'sql12725260'
})

connection.connect((err) => {
  if (err) {
    console.error('Error connecting to the database')
    return;
  }
  console.log('Connected to the database.');
});


app.post("/api/v1/register", (req, res) => {
 const full_name = req.body.full_name;
 const wa_number = req.body.wa_number;
 const education = req.body.education;
 const email = req.body.email;
 const password = req.body.password;

 console.log("Registering...")

 if(!full_name || !wa_number ||
    !education || !email || ! password){

    res.send("Error, null credential");
    console.log("Please enter full credential");
    return;
   }

const query = `INSERT INTO users (id, username, email, password, fullname, education, wa_number, createdAt, updatedAt) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;

const values = [
  '124567890',
  full_name,
  email,
  password,
  full_name,
  education,
  wa_number,
  '2024-08-19 00:00:00',
  '2024-08-19 00:00:00'
];

connection.query(query, values, (err, results) => {
  if (err) {
    console.error('Error inserting data into the database:', err);
    res.status(500).send("Error registering user");
    return;
  }
  console.log("Register success");
  res.status(200).send("Registration successful");
});

app.post("api/v1/login", (req, res) => {
 const email = req.body.email;
 const password = req.body.password

 //make sure email and password are the same
})

app.put("api/v1/reset-password", (req, res) => {
 const email = req.body.email;
 const otp = req.body.otp;
 const new_password = req.body.new_password;
})


const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`)
});
