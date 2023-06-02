const express = require('express')
const app = express()
app.use(express.json());
const swaggerUi = require('swagger-ui-express');
require('dotenv').config()

YAML = require('yamljs');
const swaggerDocument = YAML.load('swagger.yml');

app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));
app.use(express.static(__dirname + '/public'));

let sessions = [
    { sessionToken: '123', userId: 1 }
];
const users = [
    { username: 'admin', password: 'password', isAdmin: true, id: 1 },
    { username: 'user', password: 'password', isAdmin: false, id: 2 }
];
let tasks = [
    {
        id: 1,
        name: 'Task 1',
        dueDate: '2021-02-12 11:22:33',
        description: 'Description for task 1',
        userId: 1,
    },
    {
        id: 2,
        name: 'Task 2',
        dueDate: '2022-03-44 22:11:22',
        description: 'Description for task 2',
        userId: 2,
    },
    {
        id: 3,
        name: 'Task 3',
        dueDate: '2022-03-44 22:11:22',
        description: 'Description for task 3',
        userId: 1,
        completed: false
    },
];
app.post('/sessions', (req, res) => {
    if (!req.body.username || !req.body.password) {
        return res.status(400).send({ error: 'One or all params are missing' })
    }
    const user = users.find((user) => user.username === req.body.username && user.password === req.body.password);
    if (!user) {
        return res.status(401).send({ error: 'Unauthorized: username or password is incorrect' })
    }
    //generate 32 character random string
    const sessionToken = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);


    let newSession = {
        sessionToken: sessionToken,
        userId: user.id
    }
    sessions.push(newSession)
    res.status(201).send(
        { sessionToken: sessionToken }
    )
})

// Endpoint for getting all tasks
app.get('/tasks', requireAuth, (req, res) => {
    res.send(tasks.filter((task) => task.userId === req.user.id))
})

app.delete('/sessions', requireAuth, (req, res) => {
    sessions = sessions.filter((session) => session.sessionToken === req.sessionToken);
    res.status(204).end()
})

app.listen(process.env.PORT, () => {
    console.log(`App running at http://localhost:${process.env.PORT}. Documentation at http://localhost:${process.env.PORT}/docs`)
})
app.use(function (err, req, res, next) {
    console.error(err.stack);
    const status = err.status || 500;
    res.status(status).send({ error: err.message });
});

function requireAuth(req, res, next) {

    if (!req.headers.authorization) {
        return res.status(401).send({ error: 'Missing authorization header' })
    }

    if (!req.headers.authorization.startsWith('Bearer ')) {
        return res.status(401).send({ error: 'Authorization header must start with Bearer followed by a space and the session sessionToken' })
    }

    const sessionToken = req.headers.authorization.split(' ')[1];
    const session = sessions.find((session) => session.sessionToken === sessionToken);

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