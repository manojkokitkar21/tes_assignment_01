const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();


app.use(express.json());


const users = [];


const JWT_SECRET = 'secretkey';
const JWT_EXPIRATION_TIME = '30m'; 
const REFRESH_TOKEN_EXPIRATION_TIME = '7d'; 


app.post('/auth/signup', async (req, res) => {
 
  const { login, password } = req.body;
  if (!login || !password || typeof login !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ message: 'Invalid login or password' });
  }

  
  if (users.find((user) => user.login === login)) {
    return res.status(400).json({ message: 'User already exists' });
  }

  
  const hashedPassword = await bcrypt.hash(password, 10);

  
  const newUser = { id: users.length + 1, login, password: hashedPassword };
  users.push(newUser);

  return res.status(201).json({ message: 'User created' });
});


app.post('/auth/login', async (req, res) => {
  
  const { login, password } = req.body;
  if (!login || !password || typeof login !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ message: 'Invalid login or password' });
  }

  
  const user = users.find((user) => user.login === login);
  if (!user) {
    return res.status(403).json({ message: 'Authentication failed' });
  }

  
  if (!await bcrypt.compare(password, user.password)) {
    return res.status(403).json({ message: 'Authentication failed' });
  }

  
  const accessToken = jwt.sign({ userId: user.id, login: user.login }, JWT_SECRET, { expiresIn: JWT_EXPIRATION_TIME });

  
  const refreshToken = jwt.sign({ userId: user.id, login: user.login }, JWT_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRATION_TIME });

  return res.status(200).json({ accessToken, refreshToken });
});


app.listen(3000, () => {
  console.log('Server started on port 3000');
});














