const express = require('express')
const bodyParser = require('body-parser')
const morgan = require('morgan')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser')
const {createClient} = require('@supabase/supabase-js')
const app = express()
const port = 3000
const saltRounds = 10;

const accessTokenExpirationTime = '15m'; // 15 minutes
const accessTokenCookieTime =  60 * 60 * 1000; // 1 Hour
const refreshTokenExpirationTime = '100d'; // 200 days
const refreshTokenCookieTime = 100 * 24 * 60 * 60 * 1000; // 200 days
const accessTokenExpirationTimeAdmin = '1h'; // 15 minutes
const accessTokenCookieTimeAdmin =  120 * 60 * 1000; // 2 Hour
require('dotenv').config();

app.use(morgan('combined'));
app.use(cookieParser());
app.use(bodyParser.urlencoded({extended: true}));
app.use(bodyParser.json());

app.listen(port, () => {
  console.log(`API listening on port ${port}`)
})

// Create a single supabase client for interacting with your database
const supabase = createClient(process.env.URL, process.env.API_KEY)
//console.log('Supabase Instance: ', supabase)

app.get('/', async (req, res) => {
    res.send("StayWithMe API")
})

app.post('/users/signUp', async(req, res) => {
    const { data } = await supabase
        .from('users')
        .select('email')
        .eq('email', req.body.email)

    if(data.length > 0) res.send({ status: 401, message: "Email already exist"})
    else {
        let user = req.body;
        user.banned = false;

        bcrypt.hash(user.password, saltRounds, async(err, hash) => {
            console.log(err)
            user.password = hash;
            const { error } = await supabase
                .from('users')
                .insert(req.body)
                
            if(error) res.send({ status: 401, message: "Fail to create user"})
            else {
                const jwt = require('jsonwebtoken');
                const payload = {
                    username: user.username,
                    email: user.email,
                    profile_pic: user.profile_pic,
                    banned: user.banned,
                    bio: user.bio
                };

                const accessToken = jwt.sign(payload, process.env.TOKEN_SECRET, { expiresIn: accessTokenExpirationTime });
                const refreshToken = jwt.sign(payload, process.env.TOKEN_SECRET, { expiresIn: refreshTokenExpirationTime });

                res.cookie('accessToken', accessToken, {expires: new Date(Date.now() + accessTokenCookieTime)})
                res.cookie('refreshToken', refreshToken, {expires: new Date(Date.now() + refreshTokenCookieTime)})

                res.send({ status: 200, message: "Successfully created a user"})
            }
        });
    }
})

app.post('/users/login', async(req, res) => {
    const { error } = await supabase
        .from('users')
        .select('email')
        .eq('email', req.body.email)

    if(error) res.send("Email does not exist")
    else {
        let user = req.body;
        const { data } = await supabase
            .from('users')
            .select()
            .eq('email', req.body.email)

        if(data.length > 0) {
            bcrypt.compare(user.password, data[0].password).then((result) => {
                if(result) {
                    const payload = {
                        username: data[0].username,
                        email: data[0].email,
                        profile_pic: data[0].profile_pic,
                        banned: data[0].banned,
                        bio: data[0].bio
                    };

                    const accessToken = jwt.sign(payload, process.env.TOKEN_SECRET, { expiresIn: accessTokenExpirationTime });
                    const refreshToken = jwt.sign(payload, process.env.TOKEN_SECRET, { expiresIn: refreshTokenExpirationTime });

                    res.cookie('accessToken', accessToken, {expires: new Date(Date.now() + accessTokenCookieTime)});
                    res.cookie('refreshToken', refreshToken, {expires: new Date(Date.now() + refreshTokenCookieTime)});

                    res.send({ status: 200, message: "Successfully logged in"})
                }
                else res.send({ status: 401, message: "Wrong Password"})
            });
        }
        else res.send({ status: 401, message: "User with that email does not exist"})
    }
})

app.post('/users/autoLogin', async(req, res) => {
    let token = req.cookies.refreshToken;
    jwt.verify(token, process.env.TOKEN_SECRET, (err, decoded) => {
        if (err) {
            res.send(err);
        } else { 
            const payload = {
                username: decoded.username,
                email: decoded.email,
                profile_pic: decoded.profile_pic,
                banned: decoded.banned,
                bio: decoded.bio
            };

            const accessToken = jwt.sign(payload, process.env.TOKEN_SECRET, { expiresIn: accessTokenExpirationTime });
            const refreshToken = jwt.sign(payload, process.env.TOKEN_SECRET, { expiresIn: refreshTokenExpirationTime });

            res.cookie('accessToken', accessToken, {expires: new Date(Date.now() + accessTokenCookieTime)});
            res.cookie('refreshToken', refreshToken, {expires: new Date(Date.now() + refreshTokenCookieTime)});

            res.send({ status: 200, message: "Successfully automatically logged in"})
        }
    });
})

app.post('/admins/login', async(req, res) => {
    const { error } = await supabase
        .from('admins')
        .select('email')
        .eq('email', req.body.email)

    if(error) res.send("Email does not exist")
    else {
        let admin = req.body;
        const { data } = await supabase
            .from('admins')
            .select()
            .eq('email', req.body.email)

        if(data.length > 0) {
            bcrypt.compare(admin.password, data[0].password).then((result) => {
                if(result) {
                    const payload = {
                        username: data[0].username,
                        email: data[0].email,
                        role: data[0].role
                    };

                    const accessToken = jwt.sign(payload, process.env.TOKEN_SECRET, { expiresIn: accessTokenExpirationTimeAdmin });

                    res.cookie('accessToken', accessToken, {expires: new Date(Date.now() + accessTokenCookieTimeAdmin)});

                    res.send({ status: 200, message: "Successfully logged in"})
                }
                else res.send({ status: 401, message: "Wrong Password"})
            });
        }
        else res.send({ status: 401, message: "User with that email does not exist"})
    }
})

app.post('/admins/create', async(req, res) => {
    let token = req.cookies.accessToken;
    jwt.verify(token, process.env.TOKEN_SECRET, async (err, decoded) => {
        if (err) {
            res.send(err);
        } 
        else if(decoded.role == 2) {
            const { data } = await supabase
                .from('admins')
                .select('email')
                .eq('email', req.body.email)
    
            if(data.length > 0) res.send({ status: 401, message: "Email already exist"})
            else {
                let admin = req.body;
        
                bcrypt.hash(admin.password, saltRounds, async(err, hash) => {
                console.log(err)
                admin.password = hash;
                const { error } = await supabase
                    .from('admins')
                    .insert(req.body)
                    
                if(error) res.send({ status: 401, message: "Fail to create admin"})
                else res.send({ status: 200, message: "Successfully created a user"})
                });
            }
        }
        else {
            res.send({ status: 440, message: "Unauthorized Access"})
        }
    });
})



app.get('/users', async (req, res) => {
    const { data, error } = await supabase
        .from('users')
        .select()

    if(data) res.send(data)
    else res.send(error)
})

app.get('/users/:id', async (req, res) => {
    const { data } = await supabase
        .from('users')
        .select()
        .eq('id', req.params.id)

    if(data.length > 0) res.send(data[0])
    else res.send("User does not exist")
})

app.post('/users/update', async (req, res) => {
    const { error } = await supabase
        .from('users')
        .update(req.body)
        .eq('id', req.body.id)

    if(error) res.send("User was not updated")
    else res.send("User was updated")
})