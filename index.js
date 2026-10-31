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

// ---------- secrets / origins ----------
// Locally we only require MONGODB_URI and CLIENT_URL in .env.
// JWT_SECRET is required on Vercel production so tokens aren't signed with
// a predictable fallback. Better Auth reuses the same secret.
const JWT_SECRET = process.env.JWT_SECRET || (process.env.VERCEL
  ? undefined
  : 'dev-jwt-secret-change-me-in-production')
if (!JWT_SECRET) {
  throw new Error('JWT_SECRET is required in production. Add it in the Vercel dashboard.')
}
if (!process.env.JWT_SECRET && !process.env.VERCEL) {
  console.warn('[warn] Using fallback JWT_SECRET for local development. Set JWT_SECRET in .env for realistic testing.')
}

// Better Auth's own public URL. On Vercel this is auto-derived from the
// VERCEL_URL env var, so BETTER_AUTH_URL no longer needs to be set manually.
const BETTER_AUTH_URL = process.env.VERCEL_URL
  ? `https://${process.env.VERCEL_URL}`
  : (process.env.BETTER_AUTH_URL || `http://localhost:${PORT}`)

// ---------- database ----------
// Vercel runs each request in a serverless function instance that may be
// reused across invocations. Cache the MongoClient globally so a warm
// instance reuses the existing connection instead of reconnecting on every
// request. We never call .connect() at module top-level (that would block
// cold starts and can race with the function lifecycle).
const uri = process.env.MONGO_URI
if (!uri) {
  throw new Error('MONGO_URI is not set')
}

const globalForMongo = globalThis
const cachedClient = globalForMongo.__mongoClient

const client = cachedClient?.client ?? new MongoClient(uri)
if (!cachedClient) {
  globalForMongo.__mongoClient = { client }
}

// Lazily connect on first request. Returns the ``borrowbook`` db handle.
// The same promise is reused across concurrent cold-start requests.
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

// ---------- app ----------
const app = express()

// ---------- authentication (Better Auth) ----------
// Sign-up / sign-in / sign-out / session are handled by Better Auth, which
// stores users, sessions, and (scrypt-hashed) passwords in this MongoDB.
// The handler is mounted at /api/auth/*; the Next.js client reaches it
// through the same-origin /api/server proxy in next.config.ts, so the
// session cookie it sets is first-party for the browser.
//
// mongodbAdapter takes a live `Db` instance, so we must resolve the
// connection before constructing Better Auth. This awaits the (cached)
// connect promise once per cold start; warm invocations reuse it.
const dbForAuth = await getDb()
const auth = betterAuth({
  secret: process.env.BETTER_AUTH_SECRET || JWT_SECRET,
  baseURL: BETTER_AUTH_URL,
  trustedOrigins: [CLIENT_URL],
  emailAndPassword: {
    enabled: true,
    // Matches the register form's live checklist (6+ chars).
    // NOTE: minPasswordLength/maxPasswordLength sit directly on
    // emailAndPassword, not nested under a `password` key — Better Auth
    // reads `emailAndPassword.minPasswordLength` (defaults to 8 otherwise).
    minPasswordLength: 6,
    maxPasswordLength: 128,
  },
  database: mongodbAdapter(dbForAuth, { client }),
})

// ---------- middleware ----------
// CORS only matters when the browser bypasses the Next.js proxy and hits
// this server directly; through the proxy all requests are same-origin.
app.use(cors({
  origin: [CLIENT_URL, 'http://localhost:3000'],
  credentials: true,
}))

// Better Auth must be mounted BEFORE express.json(): its handler reads the
// raw request body itself, which express.json() would consume first.
app.use('/api/auth', toNodeHandler(auth))

app.use(express.json())
app.use(cookieParser())

// Resolve the collections lazily so route handlers always run after the
// connection is established.
async function booksCollection() {
  const db = await getDb()
  return db.collection('books')
}
async function borrowsCollection() {
  const db = await getDb()
  return db.collection('borrows')
}

// ---------- token check helpers ----------
// Verifies the JWT sent as: Authorization: Bearer <token>
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

// Issue a JWT for a *logged-in* user. The client calls this after Better Auth
// sign-in/sign-up; the Better Auth session cookie that arrives with the
// request is what authenticates it — the email is never trusted from the body.
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

// GET /books — get all books (public)
app.get('/books', async (req, res) => {
  try {
    const books = await booksCollection()
    const result = await books.find().toArray()
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

    const books = await booksCollection()
    const book = await books.findOne({ _id: new ObjectId(id) })
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

    // The token identifies the user — never trust the body's email instead.
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

// PATCH /books/:id — update a book (private)
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

// DELETE /books/:id — delete a book (private)
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

// GET /borrows?email=user@email.com — get borrows of the logged in user (private)
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

// DELETE /borrows/:id — return a book (private)
app.delete('/borrows/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params
    if (!isValidId(id)) return res.status(404).send({ message: 'borrow not found' })

    const borrows = await borrowsCollection()
    const borrow = await borrows.findOne({ _id: new ObjectId(id) })
    if (!borrow) return res.status(404).send({ message: 'borrow not found' })

    // only the borrower can return their own book
    if (borrow.userEmail !== req.decodedEmail) {
      return res.status(403).send({ message: 'forbidden access' })
    }

    const result = await borrows.deleteOne({ _id: new ObjectId(id) })
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

// ---------- serverless export ----------
// On Vercel, the function runtime imports this module and calls the default
// export for every request. Locally (`npm run dev`), we start a normal
// long-lived server instead.
if (process.env.VERCEL) {
  // Vercel sets VERCEL=1; export the Express app as the handler.
  // Better Auth's adapter already awaited the db connection above, so by
  // the time a request arrives the connection is warm (or warming via the
  // shared promise).
} else {
  app.listen(PORT, () => {
    console.log(`server is running at ${PORT}`)
  })
}

export default app
