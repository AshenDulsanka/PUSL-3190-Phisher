import jwt from 'jsonwebtoken'

const JWT_SECRET = process.env.JWT_SECRET

export const authMiddleware = (req, res, next) => {
  // get token from header
  const authHeader = req.headers.authorization
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'No token provided, authorization denied' })
  }

  // extract token
  const token = authHeader.split(' ')[1]

  try {
    // verify token
    const decoded = jwt.verify(token, JWT_SECRET)
    
    // add user data to request
    req.user = decoded
    
    next()
  } catch (err) {
    res.status(401).json({ message: 'Token is invalid or expired' })
  }
}