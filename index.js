const https = require('https');
const fs = require('fs');
const express = require('express')
const app = express()
app.use(express.json());
const swaggerUi = require('swagger-ui-express');
require('dotenv').config()

YAML = require('yamljs');
const swaggerDocument = YAML.load('swagger.yml');

app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));
app.use(express.static(__dirname + '/public'));

const { OAuth2Client } = require('google-auth-library');
const googleOAuth2Client = new OAuth2Client('804118527347-jogucm1dolsnmboh5s7n0ih4vhq3ls8s.apps.googleusercontent.com');

Array.prototype.findById = function (id) {
    return this.findBy('id', id)
}
Array.prototype.findBy = function (field, value) {
    return this.find(function (x) {
        return x[field] === value;
    })
}

// getdatafromgooglejwt
async function getDataFromGoogleJWT(token) {
    const ticket = await googleOAuth2Client.verifyIdToken({
        idToken: token,
        audience: '804118527347-jogucm1dolsnmboh5s7n0ih4vhq3ls8s.apps.googleusercontent.com'
    });
    const payload = ticket.getPayload();
    return payload;
}

app.post('/Oauth2Login', async (req, res) => {
    try {
        const dataFromGoogleJwt = await getDataFromGoogleJWT(req.body.credential);

        let user = users.findBy('sub', dataFromGoogleJwt.sub);
        if (!user) {
            user = createUser({
                email: dataFromGoogleJwt.name, sub: dataFromGoogleJwt.sub
            });
        }

        const newSession = createSession(user.id);

        // Fetch tasks associated with the user
        const userTasks = tasks.filter(task => task.userId === user.id);

        return res.status(201).send({
            sessionToken: newSession.sessionToken,
            isAdmin: user.isAdmin,
            tasks: userTasks
        });
    } catch (err) {
        return res.status(400).send({ error: 'Login unsuccessful' });
    }
});


let sessions = [
    { sessionToken: '123', userId: 1 }
];
const users = [
    { email: 'admin', password: 'p', isAdmin: true, id: 1, sub: '108033093276487236746' },
    { email: 'user', password: 'p', isAdmin: false, id: 2 }
];
let tasks = [];

// create user for Oauth2 google login
function createUser(user) {
    user.id = users.length + 1;
    users.push(user);
    return user;
}

// create session for Oauth2 google login
function createSession(userId) {
    const sessionToken = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    const newSession = {
        sessionToken: sessionToken,
        userId: userId
    }
    sessions.push(newSession);
    return newSession;
}


//create a new user account and a new session for the user using Oauth2 google login
app.post('/users', async (req, res) => {
    if (!req.body.email || !req.body.password) {
        return res.status(400).send({ error: 'One or all params are missing' })
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(req.body.email)) {
        return res.status(400).send({ error: 'Invalid email' })
    }
    let user = users.find((user) => user.email === req.body.email);
    if (user) {
        return res.status(400).send({ error: 'Email already exists' })
    }
    user = createUser(req.body);
    const newSession = createSession(user.id);
    res.status(201).send(
        { sessionToken: newSession.sessionToken }
    )
})

app.post('/sessions', (req, res) => {
    if (!req.body.email || !req.body.password) {
        return res.status(400).send({ error: 'One or all params are missing' })
    }
    const user = users.find((user) => user.email === req.body.email && user.password === req.body.password);
    if (!user) {
        return res.status(401).send({ error: 'Unauthorized: email or password is incorrect' })
    }
    //generate 32 character random string
    const sessionToken = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);


    let newSession = {
        sessionToken: sessionToken,
        userId: user.id
    }
    sessions.push(newSession)
    res.status(201).send(
        { sessionToken: sessionToken, isAdmin: user.isAdmin }
    )
})

// Endpoint for getting all tasks
app.get('/tasks', requireAuth, (req, res) => {
    res.send(tasks.filter((task) => task.userId === req.user.id))
})

app.delete('/sessions', requireAuth, (req, res) => {
    sessions = sessions.filter((session) => session.sessionToken !== req.sessionToken);
    res.status(204).end()
})

let httpsServer = https.createServer({
    key: fs.readFileSync("key.pem"),
    cert: fs.readFileSync("cert.pem"),
},
    app)
    .listen(process.env.PORT, () => {
        console.log(`App running at https://localhost:${process.env.PORT}. Documentation at https://localhost:${process.env.PORT}/docs`);
    });
app.use(function (err, req, res, next) {
    console.error(err.stack);
    const status = err.status || 500;
    res.status(status).send({ error: err.message });
});

//Endpoint for creating a new task
app.post('/tasks', requireAuth, (req, res) => {
    if (!req.body.name || !req.body.dueDate || !req.body.description) {
        return res.status(400).send({ error: 'One or all params are missing' })
    }
    let newTask = {
        id: tasks.length + 1,
        name: req.body.name,
        dueDate: req.body.dueDate,
        description: req.body.description,
        userId: req.user.id
    }
    tasks.push(newTask)
    res.status(201).send(
        newTask
    )
})

//Endpoint for deleting a task
app.delete('/tasks/:id', requireAuth, (req, res) => {
    const task = tasks.find((task) => task.id === parseInt(req.params.id));
    if (!task) {
        return res.status(404).send({ error: 'Task not found' })
    }
    if (task.userId !== req.user.id) {
        return res.status(403).send({ error: 'Forbidden' })
    }
    tasks = tasks.filter((task) => task.id !== parseInt(req.params.id));
    res.status(204).end()
})

//Endpoint for editing a task
app.put('/tasks/:id', requireAuth, (req, res) => {
    if (!req.body.name || !req.body.dueDate || !req.body.description) {
        return res.status(400).send({ error: 'One or all params are missing' })
    }
    const task = tasks.find((task) => task.id === parseInt(req.params.id));
    if (!task) {
        return res.status(404).send({ error: 'Task not found' })
    }
    if (task.userId !== req.user.id) {
        return res.status(403).send({ error: 'Forbidden' })
    }
    task.name = req.body.name;
    task.dueDate = req.body.dueDate;
    task.description = req.body.description;
    res.status(200).send(
        task
    )
})

function requireAuth(req, res, next) {

    if (!req.headers.authorization) {
        return res.status(401).send({ error: 'Missing authorization header' })
    }

    if (!req.headers.authorization.startsWith('Bearer ')) {
        return res.status(401).send({ error: 'Authorization header must start with Bearer followed by a space and the session sessionToken' })
    }

    const sessionToken = req.headers.authorization.split(' ')[1];
    const session = sessions.find((session) => session.sessionToken === (sessionToken));
    if (!session) {
        return res.status(401).send({ error: 'Invalid session' })
    }

    const user = users.find((user) => user.id === session.userId);

    if (!user) {
        return res.status(401).send({ error: 'Invalid user' })
    }

    req.user = user;
    req.sessionToken = sessionToken;

    next()
}