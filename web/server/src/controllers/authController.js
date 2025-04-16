import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import { PrismaClient } from '@prisma/client'
import { validateEmail, validatePassword } from '../utils/validation.js'

const prisma = new PrismaClient()
const JWT_SECRET = process.env.JWT_SECRET

// register a new user
export const register = async (req, res) => {
  try {
    const { username, email, password } = req.body

    // validate inputs
    if (!username || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' })
    }

    // validate email format
    if (!validateEmail(email)) {
      return res.status(400).json({ message: 'Invalid email format' })
    }

    // validate password strength
    if (!validatePassword(password)) {
      return res.status(400).json({ 
        message: 'Password must be at least 8 characters and include a number, lowercase and uppercase letter'
      })
    }

    // check if user already exists
    const existingUser = await prisma.user.findFirst({
      where: {
        OR: [
          { email },
          { username }
        ]
      }
    })

    if (existingUser) {
      return res.status(409).json({ message: 'User with this email or username already exists' })
    }

    // hash password
    const saltRounds = 10
    const hashedPassword = await bcrypt.hash(password, saltRounds)

    // create user
    const newUser = await prisma.user.create({
      data: {
        username,
        email,
        password: hashedPassword
      }
    })

    // create token
    const token = jwt.sign(
      { userId: newUser.id, email: newUser.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    )

    // return user data (excluding password)
    const { password: _, ...userWithoutPassword } = newUser
    
    res.status(201).json({ 
      message: 'User registered successfully',
      token,
      user: userWithoutPassword
    })
  } catch (error) {
    console.error('Registration error:', error)
    res.status(500).json({ message: 'Server error during registration' })
  }
}

// login user
export const login = async (req, res) => {
  try {
    const { email, password } = req.body

    // validate inputs
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' })
    }

    // find user by email
    const user = await prisma.user.findUnique({
      where: { email }
    })

    // check if user exists
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' })
    }

    // validate password
    const passwordMatch = await bcrypt.compare(password, user.password)
    if (!passwordMatch) {
      return res.status(401).json({ message: 'Invalid credentials' })
    }

    // create token
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    )

    // return user data (excluding password)
    const { password: _, ...userWithoutPassword } = user
    
    res.status(200).json({ 
      message: 'Login successful',
      token,
      user: userWithoutPassword
    })
  } catch (error) {
    console.error('Login error:', error)
    res.status(500).json({ message: 'Server error during login' })
  }
}

// validate token
export const validateToken = async (req, res) => {
  try {
    // user data comes from auth middleware
    const user = await prisma.user.findUnique({
      where: { id: req.user.userId },
      select: { 
        id: true, 
        username: true, 
        email: true, 
        createdAt: true,
        updatedAt: true
      }
    })

    if (!user) {
      return res.status(404).json({ message: 'User not found' })
    }

    res.status(200).json({ 
      message: 'Token is valid',
      user
    })
  } catch (error) {
    console.error('Token validation error:', error)
    res.status(500).json({ message: 'Server error during token validation' })
  }
}