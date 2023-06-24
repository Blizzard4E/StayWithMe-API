const express = require("express");
const bodyParser = require("body-parser");
const morgan = require("morgan");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const jwt_decode = require("jwt-decode");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const { createClient } = require("@supabase/supabase-js");
const app = express();
const port = 3000;

const userRoutes = require("./routes/users");
const adminRoutes = require("./routes/admins");
const hotelRoutes = require("./routes/hotels");
require("dotenv").config();

app.use(morgan("combined"));
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cors());
app.use("/users", userRoutes);
app.use("/admins", adminRoutes);
app.use("/hotels", hotelRoutes);

app.listen(port, () => {
    console.log(`API listening on port ${port}`);
});

// Create a single supabase client for interacting with your database
const supabase = createClient(process.env.URL, process.env.API_KEY);
//console.log('Supabase Instance: ', supabase)

app.get("/", async (req, res) => {
    res.send("StayWithMe API");
});
