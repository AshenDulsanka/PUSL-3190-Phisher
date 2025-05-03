import jwt from 'jsonwebtoken'

export const requireAdmin = async (req, res, next) => {
  try {
    // get token from header
    const authHeader = req.headers.authorization
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Authentication required' })
    }
    
    const token = authHeader.split(' ')[1]
    
    // verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    
    // check if user is admin
    if (!decoded.isAdmin) {
      return res.status(403).json({ message: 'Admin access required' })
    }
    
    // attach user info to request
    req.user = decoded
    
    next()
  } catch (error) {
    console.error('Auth middleware error:', error)
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ message: 'Invalid token' })
    }
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token expired' })
    }
    
    res.status(500).json({ message: 'Server error' })
  }
}