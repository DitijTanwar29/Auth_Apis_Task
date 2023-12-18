const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;
const SECRET_KEY = "ABCDE";

// Connect to MongoDB (replace 'your_mongodb_uri' with your actual MongoDB URI)
mongoose.connect('mongodb://localhost:27017', { useNewUrlParser: true, useUnifiedTopology: true });

app.use(bodyParser.json());

// Define a MongoDB schema for users
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
});

const User = mongoose.model('User', userSchema);

// SignUp API
app.post('/signup', async (req, res) => {
  
  try{

    const { username, password, confirmPassword } = req.body;

    //validate data
    if(!username || !password || !confirmPassword ) {
      return res.status(403).json({
          success:false,
          message: "All fields are required",
      })
   }
  
    //match 2 passwords
    if(password !== confirmPassword){
      return res.status(400).json({
          success:false,
          message:"Password and ConfirmPassword value does not match, please try again",
      })
    }
  
    // Check if the username is already taken
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }
  
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);
  
    // Create a new user
    const newUser = new User({
      username,
      password: hashedPassword,
    });
  
    // Save the user to the database
    await newUser.save();
  
    res.status(200).json({ 
      success: true,
      message: 'User registered successfully' });

      
  }
  catch(error) {
      console.log(error);
      return res.status(500).json({
          ststus:false,
          message:"User cannot be registered. Please try again",
      });
  }

});

// Sign In API
app.post('/signin', async (req, res) => {
  const { username, password, confirmPassword} = req.body;

  //validations
  if(!username || !password || !confirmPassword){
    return res.status(403).json({
      success:false,
      message:"All fields are required"
    })
  }

  if(password !== confirmPassword){
    return res.status(403).json({
      success:false,
      message:"Passwords are not matching"
    })
  }



  // Find the user by username
  const user = await User.findOne({ username });

  // If the user doesn't exist or the password is incorrect, return an error
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  // Create a JWT token
  const token = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: '1h' });

  return res.status(200).json({
    data:token,
    message:"User Logged In Successfully" });
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
 