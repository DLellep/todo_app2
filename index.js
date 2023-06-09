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
const readline = require("readline");
let loggedInUser;

//store user data 
app.use(function (req, res, next) {
    let sessionToken = getsessionToken(req);
    if (sessionToken) {
        const sessionUser = sessions.find(session => session.sessionToken === (sessionToken));
        if (sessionUser) {
            loggedInUser = users.findById(sessionUser.userId);
            loggedInUser.sessionToken = loggedInUser.sessionToken;
        }
    } else loggedInUser = {};
    next();
});
function login(user, req) {
    const session = createSession(user.id);
    loggedInUser = { ...user, sessionToken: session.sessionToken };
}
function log(eventName, extraData) {
    // Create timestamp
    const timeStamp = new Date(Date.now() + 3 * 60 * 60 * 1000).toISOString().replace(/T/, ' ').replace(/\..+/, '');
    // Parse extraData and eventName to JSON and escape the delimiter with backslash
    extraData = JSON.stringify(extraData).replace(/　/g, '\\　');
    // trim only quotes from extraData
    extraData = extraData.replace(/^"(.*)"$/, '$1');
    // Write to file
    fs.appendFile('./log.txt', loggedInUser.id + '　' + timeStamp + '　' + eventName + '　' + extraData + ' \r\n', function (err) {
        if (err) throw err;
    });
}

function getsessionToken(req) {
    const authorization = req.headers.authorization;
    if (!authorization) return null;
    const parts = authorization.split(' ');
    if (parts.length !== 2) return null;
    const scheme = parts[0];
    const credentials = parts[1];
    if (/^Bearer$/i.test(scheme)) {
        return credentials;
    }
    return null;
}

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

        const dataFromGoogleJwt = await getDataFromGoogleJWT(req.body.credential)

        let user = users.findBy('sub', dataFromGoogleJwt.sub);
        if (!user) {
            user = createUser({
                username: dataFromGoogleJwt.name, email: dataFromGoogleJwt.email, sub: dataFromGoogleJwt.sub
            })
        }
        login(user, req);
        log("Oauth2Login", `Google user ${dataFromGoogleJwt.name} (${dataFromGoogleJwt.email}) logged in as local user ${user.email}`, user);
        return res.status(201).send(
            { sessionToken: loggedInUser.sessionToken, isAdmin: user.isAdmin }
        )
    } catch (err) {
        return res.status(400).send({ error: 'Login unsuccessful' });
    };
});


let sessions = [
    { sessionToken: '123', userId: 1 }
];
const users = [
    { email: 'admin', password: 'p', isAdmin: true, id: 1, sub: '108033093276487236746' },
    { email: 'user', password: 'p', isAdmin: false, id: 2 }
];
let tasks = [];

let logs = [];

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
    login(user, req);
    log("login", `User ${user.email} logged in`);
    res.status(201).send(
        { sessionToken: sessionToken, isAdmin: user.isAdmin }
    )
})

// Endpoint for getting all logs
app.get('/logs', requireAuth, (req, res) => {
    if (!loggedInUser.isAdmin) {
        return res.status(403).send({ error: 'This action requires signing in as an admin' });
    }

    const lines = [];
    const lineReader = readline.createInterface({
        input: fs.createReadStream('./log.txt'),
        crlfDelay: Infinity
    });

    lineReader.on('line', (line) => {
        const fields = line.split('　'); // Split the line using '　' delimiter

        // Remove backslash from escaped '　'
        for (let i = 0; i < fields.length; i++) {
            fields[i] = fields[i].replace(/\\/g, '');
        }
        // Find user by id
        const user = users.findBy('id', parseInt(fields[0]))

        // Add the line to the lines array
        lines.push({
            user: `${user?.email} (${fields[0]})`,
            timeStamp: fields[1],
            eventName: fields[2],
            extraData: fields[3]
        });
    });

    lineReader.on('close', () => {
        // Sort lines by timestamp descending
        lines.sort((a, b) => {
            return new Date(b.timeStamp) - new Date(a.timeStamp);
        });
        res.send(lines); // Return the lines array once all lines are processed
    });
});

// Endpoint for getting all tasks
app.get('/tasks', requireAuth, async (req, res) => {
    // Delay for 2 seconds to test 
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    res.send(tasks.filter((task) => task.userId === req.user.id))
})

app.delete('/sessions', requireAuth, (req, res) => {
    sessions = sessions.filter((session) => session.sessionToken !== req.sessionToken);
    log("logout", `User ${loggedInUser.email} logged out`);
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
    log("createTask", newTask);
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
    log("deleteTask", `Task ${task.id} deleted`, loggedInUser);
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
    let taskOriginal = JSON.parse(JSON.stringify(task));

    function diff(obj1, obj2) {

        // function get unique keys from timeOriginal and time
        function getUniqueKeys(obj1, obj2) {
            let keys = Object.keys(obj1).concat(Object.keys(obj2));
            return keys.filter(function (item, pos) {
                return keys.indexOf(item) === pos;
            });
        }

        let result = {};
        for (let k of getUniqueKeys(obj1, obj2)) {
            if (obj1[k] !== obj2[k]) {
                result[k] = obj2[k];
            }
        }
        return result;
    }
    log("editTask", { id: task.id, diff: diff(taskOriginal, req.body) });


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
    console.log(sessionToken)
    console.log(sessions)
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