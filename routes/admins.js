const express = require("express");
const router = express.Router();
const { createClient } = require("@supabase/supabase-js");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const jwt_decode = require("jwt-decode");
require("dotenv").config();
const supabase = createClient(process.env.SUPA_URL, process.env.API_KEY);
const saltRounds = 10;
const accessTokenExpirationTime = "1h"; // 15 minutes

function checkEmail(email) {
    return new Promise(async (resolve, reject) => {
        const adminsCheck = await supabase
            .from("admins")
            .select()
            .eq("email", email);

        if (adminsCheck.data.length <= 0) {
            console.log("No account with this email exist");
            reject({
                status: 401,
                message: "No account with this email exist",
            });
        } else {
            resolve({
                status: 200,
                message: "Admin with this email exist",
                data: adminsCheck.data[0],
            });
        }
    });
}

function authToken(token) {
    return new Promise((resolve, reject) => {
        jwt.verify(token, process.env.TOKEN_SECRET, async (err, decoded) => {
            if (err) {
                return reject({ status: 401, message: "Invalid Token" });
            }
            const emailCheck = await checkEmail(decoded.email).catch((err) => {
                return reject(err);
            });
            resolve(emailCheck);
        });
    });
}

router.post("/all", async (req, res) => {
    if (req.body.token) {
        const tokenCheck = await authToken(req.body.token).catch((err) => {
            return res.send(err);
        });
        if (tokenCheck) {
            delete req.body["token"];
            const adminsList = await supabase
                .from("admins")
                .select("username, role");

            if (adminsList.error) {
                return res.send({
                    status: 401,
                    message: adminsList.error,
                });
            }
            return res.send({
                status: 200,
                message: "Successfully get all admins",
                data: adminsList.data,
            });
        }
    } else return res.send({ status: 401, message: "Unauthorized Access" });
});

router.post("/signUp", async (req, res) => {
    if (req.body.admin_role) {
        if (req.body.admin_role == 0) {
            return res.send({ status: 401, message: "Unauthorized Access" });
        }
        if (req.body.email && req.body.password && req.body.username) {
            const emailCheck = await checkEmail(req.body.email).catch((err) => {
                bcrypt.hash(
                    req.body.password,
                    saltRounds,
                    async (errHash, hash) => {
                        if (errHash) {
                            return res.send({
                                status: 401,
                                message: "Cannot hash password",
                            });
                        }
                        const { error } = await supabase.from("admins").insert({
                            username: req.body.username,
                            password: hash,
                            email: req.body.email,
                        });
                        if (error) {
                            return res.send({
                                status: 401,
                                message: error,
                            });
                        }
                        return res.send({
                            status: 200,
                            message: "New admin account created",
                        });
                    }
                );
            });
            if (emailCheck) {
                return res.send({ status: 401, message: emailCheck.message });
            }
        } else
            return res.send({ status: 401, message: "Invalid request body" });
    } else return res.send({ status: 401, message: "Unauthorized Access" });
});

router.post("/bannedHotels", async (req, res) => {
    if (req.body.token) {
        const tokenCheck = await authToken(req.body.token).catch((err) => {
            return res.send(err);
        });
        if (tokenCheck) {
            delete req.body["token"];
            const bannedHotels = await supabase
                .from("hotels")
                .select(
                    "id, name, images, email, description, country, googleMap, ratings"
                )
                .eq("banned", true);

            if (bannedHotels.error) {
                return res.send({
                    status: 401,
                    message: bannedHotels.error,
                });
            }
            return res.send({
                status: 200,
                message: "Successfully get banned hotels",
                data: bannedHotels.data,
            });
        }
    } else return res.send({ status: 401, message: "Unauthorized Access" });
});

router.post("/bannedUsers", async (req, res) => {
    if (req.body.token) {
        const tokenCheck = await authToken(req.body.token).catch((err) => {
            return res.send(err);
        });
        if (tokenCheck) {
            delete req.body["token"];
            const bannedUsers = await supabase
                .from("users")
                .select("id, username, profile_pic, bio, email")
                .eq("banned", true);

            if (bannedUsers.error) {
                return res.send({
                    status: 401,
                    message: bannedUsers.error,
                });
            }
            return res.send({
                status: 200,
                message: "Successfully get banned users",
                data: bannedUsers.data,
            });
        }
    } else return res.send({ status: 401, message: "Unauthorized Access" });
});

router.post("/unbanHotel", async (req, res) => {
    if (req.body.token) {
        const tokenCheck = await authToken(req.body.token).catch((err) => {
            return res.send(err);
        });
        if (tokenCheck) {
            delete req.body["token"];
            const { error } = await supabase
                .from("hotels")
                .update({ banned: false })
                .eq("id", req.body.hotel_id);

            if (error) {
                return res.send({
                    status: 401,
                    message: error,
                });
            }
            return res.send({
                status: 200,
                message: "Successfully unban hotel",
            });
        }
    } else return res.send({ status: 401, message: "Unauthorized Access" });
});

router.post("/banHotel", async (req, res) => {
    if (req.body.token) {
        const tokenCheck = await authToken(req.body.token).catch((err) => {
            return res.send(err);
        });
        if (tokenCheck) {
            delete req.body["token"];
            const { error } = await supabase
                .from("hotels")
                .update({ banned: true })
                .eq("id", req.body.hotel_id);

            if (error) {
                return res.send({
                    status: 401,
                    message: error,
                });
            }
            return res.send({
                status: 200,
                message: "Successfully ban hotel",
            });
        }
    } else return res.send({ status: 401, message: "Unauthorized Access" });
});

router.post("/unbanUser", async (req, res) => {
    if (req.body.token) {
        const tokenCheck = await authToken(req.body.token).catch((err) => {
            return res.send(err);
        });
        if (tokenCheck) {
            delete req.body["token"];
            const { error } = await supabase
                .from("users")
                .update({ banned: false })
                .eq("id", req.body.user_id);

            if (error) {
                return res.send({
                    status: 401,
                    message: error,
                });
            }
            return res.send({
                status: 200,
                message: "Successfully unban user",
            });
        }
    } else return res.send({ status: 401, message: "Unauthorized Access" });
});

router.post("/banUser", async (req, res) => {
    if (req.body.token) {
        const tokenCheck = await authToken(req.body.token).catch((err) => {
            return res.send(err);
        });
        if (tokenCheck) {
            delete req.body["token"];
            const { error } = await supabase
                .from("users")
                .update({ banned: true })
                .eq("id", req.body.user_id);

            if (error) {
                return res.send({
                    status: 401,
                    message: error,
                });
            }
            const reportData = await supabase
                .from("reports")
                .delete()
                .eq("id", req.body.report_id);
            if (reportData.error) {
                return res.send({
                    status: 401,
                    message: reportData.error,
                });
            }
            return res.send({
                status: 200,
                message: "Successfully ban user",
            });
        }
    } else return res.send({ status: 401, message: "Unauthorized Access" });
});

router.post("/ratings", async (req, res) => {
    if (req.body.token) {
        const tokenCheck = await authToken(req.body.token).catch((err) => {
            return res.send(err);
        });
        if (tokenCheck) {
            delete req.body["token"];
            const ratingsData = await supabase
                .from("reviews")
                .select(
                    "*, hotel_id(id, banned, name, images, email, description, country, googleMap, ratings)"
                )
                .lte("ratings", 3)
                .order("created_at", { ascending: true });

            if (ratingsData.error) {
                return res.send({
                    status: 401,
                    message: "Cannot get ratings",
                });
            } else {
                return res.send({
                    status: 200,
                    message: "Successfully get ratings",
                    ratingsData: ratingsData.data,
                });
            }
        }
    } else return res.send({ status: 401, message: "Unauthorized Access" });
});

router.post("/reports", async (req, res) => {
    if (req.body.token) {
        const tokenCheck = await authToken(req.body.token).catch((err) => {
            return res.send(err);
        });
        if (tokenCheck) {
            delete req.body["token"];
            const reportsData = await supabase
                .from("reports")
                .select(
                    "*, user_id(id, banned, username, profile_pic, email, bio),review_id ( feedback)"
                )
                .order("created_at", { ascending: true });

            if (reportsData.error) {
                return res.send({
                    status: 401,
                    message: "Cannot get bookings",
                });
            } else {
                return res.send({
                    status: 200,
                    message: "Successfully get bookings",
                    reportsData: reportsData.data,
                });
            }
        }
    } else return res.send({ status: 401, message: "Unauthorized Access" });
});

router.post("/login", async (req, res) => {
    console.log(req.body);
    if (req.body.email && req.body.password) {
        const emailCheck = await checkEmail(req.body.email).catch((err) => {
            return res.send(err);
        });
        console.log(emailCheck.data);
        if (emailCheck.data) {
            bcrypt
                .compare(req.body.password, emailCheck.data.password)
                .then((result) => {
                    if (result) {
                        delete emailCheck.data["password"];
                        let payload = emailCheck.data;

                        const accessToken = jwt.sign(
                            payload,
                            process.env.TOKEN_SECRET,
                            {
                                expiresIn: accessTokenExpirationTime,
                            }
                        );
                        console.log("Made access token");
                        console.log("Sent to Admin");
                        return res.send({
                            status: 200,
                            message: emailCheck.message,
                            accessToken: accessToken,
                        });
                    } else {
                        return res.send({
                            status: 401,
                            message: "Wrong Password",
                        });
                    }
                });
        }
    }
});

module.exports = router;
