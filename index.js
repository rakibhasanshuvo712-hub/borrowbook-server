import express from 'express'
import 'dotenv/config'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import jwt from 'jsonwebtoken'
import { MongoClient, ObjectId } from 'mongodb'
import { betterAuth } from 'better-auth'
import { mongodbAdapter } from 'better-auth/adapters/mongodb'
import { toNodeHandler } from 'better-auth/node'

const PORT = process.env.PORT || 5000
const CLIENT_URL = process.env.CLIENT_URL || 'http://localhost:3000'


const JWT_SECRET = process.env.JWT_SECRET || (process.env.VERCEL
  ? undefined
  : 'dev-jwt-secret-change-me-in-production')
if (!JWT_SECRET) {
  throw new Error('JWT_SECRET is required in production. Add it in the Vercel dashboard.')
}
if (!process.env.JWT_SECRET && !process.env.VERCEL) {
  console.warn('[warn] Using fallback JWT_SECRET for local development. Set JWT_SECRET in .env for realistic testing.')
}


const BETTER_AUTH_URL = process.env.VERCEL_URL
  ? `https://${process.env.VERCEL_URL}`
  : (process.env.BETTER_AUTH_URL || `http://localhost:${PORT}`)


const uri = process.env.MONGO_URI || process.env.MONGODB_URI
if (!uri) {
  throw new Error('MONGO_URI is not set')
}

const globalForMongo = globalThis
const cachedClient = globalForMongo.__mongoClient

const client = cachedClient?.client ?? new MongoClient(uri)
if (!cachedClient) {
  globalForMongo.__mongoClient = { client }
}


let dbPromise
function getDb() {
  if (!dbPromise) {
    dbPromise = client.connect().then(() => {
      console.log('You successfully connected to MongoDB!')
      return client.db('borrowbook')
    })
  }
  return dbPromise
}


const app = express()

const dbForAuth = await getDb()
const auth = betterAuth({
  secret: process.env.BETTER_AUTH_SECRET || JWT_SECRET,
  baseURL: BETTER_AUTH_URL,
  trustedOrigins: [CLIENT_URL],
  emailAndPassword: {
    enabled: true,
    minPasswordLength: 6,
    maxPasswordLength: 128,
  },
  database: mongodbAdapter(dbForAuth, { client }),
})


app.use(cors({
  origin: [CLIENT_URL, 'http://localhost:3000'],
  credentials: true,
}))


app.use('/api/auth', toNodeHandler(auth))

app.use(express.json())
app.use(cookieParser())


async function booksCollection() {
  const db = await getDb()
  return db.collection('books')
}
async function borrowsCollection() {
  const db = await getDb()
  return db.collection('borrows')
}


function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization
  if (!authHeader) return res.status(401).send({ message: 'forbidden access - no token provided' })

  const token = authHeader.split(' ')[1]
  if (!token) return res.status(401).send({ message: 'forbidden access - invalid token' })

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).send({ message: 'forbidden access - invalid token' })
    req.decodedEmail = decoded.email
    next()
  })
}

async function verifyTokenAndEmail(req, res, next) {
  if (req.query.email !== req.decodedEmail) {
    return res.status(403).send({ message: 'forbidden access' })
  }
  next()
}

function isValidId(id) {
  return ObjectId.isValid(id)
}


app.post('/jwt', async (req, res) => {
  try {
    const session = await auth.api.getSession({ headers: req.headers })
    if (!session) {
      return res.status(401).send({ message: 'forbidden access - sign in first' })
    }

    const token = jwt.sign({ email: session.user.email }, JWT_SECRET, { expiresIn: '7d' })
    res.send({ token })
  } catch (err) {
    res.status(500).send({ message: err.message })
  }
})

app.get('/books', async (req, res) => {
  try {
    const books = await booksCollection()
    const result = await books.find().toArray()
    res.send(result)
  } catch (err) {
    res.status(500).send({ message: err.message })
  }
})

app.get('/books/:id', async (req, res) => {
  try {
    const { id } = req.params
    if (!isValidId(id)) return res.status(404).send({ message: 'book not found' })

    const books = await booksCollection()
    const book = await books.findOne({ _id: new ObjectId(id) })
    if (!book) return res.status(404).send({ message: 'book not found' })

    res.send(book)
  } catch (err) {
    res.status(500).send({ message: err.message })
  }
})

app.post('/books', verifyToken, async (req, res) => {
  try {
    const bookData = req.body

    const book = {
      title: bookData.title,
      author: bookData.author,
      category: bookData.category,
      image: bookData.image,
      description: bookData.description,
      userName: bookData.userName,
      userEmail: bookData.userEmail,
      addedAt: bookData.addedAt || new Date().toISOString(),
    }

    if (!book.title || !book.author || !book.category || !book.image || !book.description) {
      return res.status(400).send({ message: 'missing required book fields' })
    }

  
    if (book.userEmail && book.userEmail !== req.decodedEmail) {
      return res.status(403).send({ message: 'forbidden access' })
    }
    book.userEmail = req.decodedEmail

    const books = await booksCollection()
    const result = await books.insertOne(book)
    res.status(201).send(result)
  } catch (err) {
    res.status(500).send({ message: err.message })
  }
})

app.patch('/books/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params
    if (!isValidId(id)) return res.status(404).send({ message: 'book not found' })

    const books = await booksCollection()
    const existing = await books.findOne({ _id: new ObjectId(id) })
    if (!existing) return res.status(404).send({ message: 'book not found' })
    if (existing.userEmail !== req.decodedEmail) {
      return res.status(403).send({ message: 'forbidden access' })
    }

    const updatedData = { ...req.body }
    delete updatedData._id
    delete updatedData.userEmail

    const result = await books.updateOne(
      { _id: new ObjectId(id) },
      { $set: updatedData }
    )

    res.send(result)
  } catch (err) {
    res.status(500).send({ message: err.message })
  }
})

app.delete('/books/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params
    if (!isValidId(id)) return res.status(404).send({ message: 'book not found' })

    const books = await booksCollection()
    const existing = await books.findOne({ _id: new ObjectId(id) })
    if (existing && existing.userEmail !== req.decodedEmail) {
      return res.status(403).send({ message: 'forbidden access' })
    }

    const result = await books.deleteOne({ _id: new ObjectId(id) })

    if (result.deletedCount === 0) {
      return res.status(404).send({ message: 'book not found' })
    }
    res.send(result)
  } catch (err) {
    res.status(500).send({ message: err.message })
  }
})

app.post('/borrows', verifyToken, async (req, res) => {
  try {
    const borrowData = req.body

    const borrow = {
      bookId: borrowData.bookId,
      bookTitle: borrowData.bookTitle,
      bookImage: borrowData.bookImage,
      userName: borrowData.userName,
      userEmail: borrowData.userEmail,
      borrowDate: borrowData.borrowDate,
      returnDate: borrowData.returnDate,
    }

    if (!borrow.bookId || !borrow.bookTitle || !borrow.userEmail || !borrow.borrowDate) {
      return res.status(400).send({ message: 'missing required borrow fields' })
    }

    if (borrow.userEmail !== req.decodedEmail) {
      return res.status(403).send({ message: 'forbidden access' })
    }

    const borrows = await borrowsCollection()
    const result = await borrows.insertOne(borrow)
    res.status(201).send(result)
  } catch (err) {
    res.status(500).send({ message: err.message })
  }
})

app.get('/borrows', verifyToken, verifyTokenAndEmail, async (req, res) => {
  try {
    const { email } = req.query
    const borrows = await borrowsCollection()
    const result = await borrows
      .find({ userEmail: email })
      .sort({ borrowDate: -1 })
      .toArray()
    res.send(result)
  } catch (err) {
    res.status(500).send({ message: err.message })
  }
})

app.delete('/borrows/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params
    if (!isValidId(id)) return res.status(404).send({ message: 'borrow not found' })

    const borrows = await borrowsCollection()
    const borrow = await borrows.findOne({ _id: new ObjectId(id) })
    if (!borrow) return res.status(404).send({ message: 'borrow not found' })

    if (borrow.userEmail !== req.decodedEmail) {
      return res.status(403).send({ message: 'forbidden access' })
    }

    const result = await borrows.deleteOne({ _id: new ObjectId(id) })
    res.send(result)
  } catch (err) {
    res.status(500).send({ message: err.message })
  }
})

app.get('/', (req, res) => {
  res.send('BookNook server is running!')
})

app.use((err, req, res, next) => {
  res.status(500).send({ message: err.message })
})


if (process.env.VERCEL) {
 
} else {
  app.listen(PORT, () => {
    console.log(`server is running at ${PORT}`)
  })
}

export default app
