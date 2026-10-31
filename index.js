import express from 'express'
import 'dotenv/config'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import jwt from 'jsonwebtoken'
import { MongoClient, ObjectId } from 'mongodb'

const PORT = process.env.PORT || 5000
const app = express()

// ---------- middleware ----------
app.use(cors({
  origin: [process.env.CLIENT_URL || 'http://localhost:5173', 'http://localhost:5173'],
  credentials: true,
}))
app.use(express.json())
app.use(cookieParser())

// ---------- database ----------
const client = new MongoClient(process.env.MONGO_URI)

async function connectToMongoDB() {
  try {
    await client.connect()
    console.log('You successfully connected to MongoDB!')
    return client
  } catch (err) {
    console.dir(err)
    process.exit(1)
  }
}

const connectClient = await connectToMongoDB()
const db = connectClient.db('borrowbook')
const booksCollection = db.collection('books')
const borrowsCollection = db.collection('borrows')

// ---------- token check helpers ----------
// Verifies the JWT sent as: Authorization: Bearer <token>
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization
  if (!authHeader) return res.status(401).send({ message: 'forbidden access - no token provided' })

  const token = authHeader.split(' ')[1]
  if (!token) return res.status(401).send({ message: 'forbidden access - invalid token' })

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).send({ message: 'forbidden access - invalid token' })
    req.decodedEmail = decoded.email
    next()
  })
}

// Ensures the requested email matches the token's email (for query-based routes)
async function verifyTokenAndEmail(req, res, next) {
  if (req.query.email !== req.decodedEmail) {
    return res.status(403).send({ message: 'forbidden access' })
  }
  next()
}

// Checks that a string is a valid MongoDB ObjectId
function isValidId(id) {
  return ObjectId.isValid(id)
}

// ---------- API routes ----------

// Issue a token for a logged-in user (used by the frontend after login)
app.post('/jwt', (req, res) => {
  const { email } = req.body
  if (!email) return res.status(400).send({ message: 'email is required' })

  const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '7d' })
  res.send({ token })
})

// GET /books — get all books (public)
app.get('/books', async (req, res) => {
  try {
    const result = await booksCollection.find().toArray()
    res.send(result)
  } catch (err) {
    res.status(500).send({ message: err.message })
  }
})

// GET /books/:id — get one book (public)
app.get('/books/:id', async (req, res) => {
  try {
    const { id } = req.params
    if (!isValidId(id)) return res.status(404).send({ message: 'book not found' })

    const book = await booksCollection.findOne({ _id: new ObjectId(id) })
    if (!book) return res.status(404).send({ message: 'book not found' })

    res.send(book)
  } catch (err) {
    res.status(500).send({ message: err.message })
  }
})

// POST /books — add a book (private)
app.post('/books', verifyToken, async (req, res) => {
  try {
    const bookData = req.body

    // only allow known fields
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

    const result = await booksCollection.insertOne(book)
    res.status(201).send(result)
  } catch (err) {
    res.status(500).send({ message: err.message })
  }
})

// PATCH /books/:id — update a book (private)
app.patch('/books/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params
    if (!isValidId(id)) return res.status(404).send({ message: 'book not found' })

    const updatedData = { ...req.body }
    delete updatedData._id

    const result = await booksCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updatedData }
    )

    if (result.matchedCount === 0) {
      return res.status(404).send({ message: 'book not found' })
    }
    res.send(result)
  } catch (err) {
    res.status(500).send({ message: err.message })
  }
})

// DELETE /books/:id — delete a book (private)
app.delete('/books/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params
    if (!isValidId(id)) return res.status(404).send({ message: 'book not found' })

    const result = await booksCollection.deleteOne({ _id: new ObjectId(id) })

    if (result.deletedCount === 0) {
      return res.status(404).send({ message: 'book not found' })
    }
    res.send(result)
  } catch (err) {
    res.status(500).send({ message: err.message })
  }
})

// POST /borrows — borrow a book (private)
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

    const result = await borrowsCollection.insertOne(borrow)
    res.status(201).send(result)
  } catch (err) {
    res.status(500).send({ message: err.message })
  }
})

// GET /borrows?email=user@email.com — get borrows of the logged in user (private)
app.get('/borrows', verifyToken, verifyTokenAndEmail, async (req, res) => {
  try {
    const { email } = req.query
    const result = await borrowsCollection
      .find({ userEmail: email })
      .sort({ borrowDate: -1 })
      .toArray()
    res.send(result)
  } catch (err) {
    res.status(500).send({ message: err.message })
  }
})

// DELETE /borrows/:id — return a book (private)
app.delete('/borrows/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params
    if (!isValidId(id)) return res.status(404).send({ message: 'borrow not found' })

    const borrow = await borrowsCollection.findOne({ _id: new ObjectId(id) })
    if (!borrow) return res.status(404).send({ message: 'borrow not found' })

    // only the borrower can return their own book
    if (borrow.userEmail !== req.decodedEmail) {
      return res.status(403).send({ message: 'forbidden access' })
    }

    const result = await borrowsCollection.deleteOne({ _id: new ObjectId(id) })
    res.send(result)
  } catch (err) {
    res.status(500).send({ message: err.message })
  }
})

// root
app.get('/', (req, res) => {
  res.send('BookNook server is running!')
})

// global error handler
app.use((err, req, res, next) => {
  res.status(500).send({ message: err.message })
})

app.listen(PORT, () => {
  console.log(`server is running at ${PORT}`)
})
