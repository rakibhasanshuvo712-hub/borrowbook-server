import express from 'express'
import 'dotenv/config'
import { MongoClient } from 'mongodb';
import cors from 'cors'
const PORT= 5000;
const app=express()
app.use(express.json());



const client = new MongoClient(process.env.MONGO_URI);

export async function connectToMongoDB() {
  try {
    await client.connect();
    console.log("You successfully connected to MongoDB!");
    return client;
  } catch (err) {
    console.dir(err);
  }
}
const connectClient=await connectToMongoDB();
const db=connectClient.db("borrowbook")
const facilitiesCollection=db.collection("books")

app.get('/books', async(req,res) => {
    const result=await facilitiesCollection.find().toArray()
    res.json(result)

})

app.post('/books', async(req,res) => {
   const facilityData=req.body
   const result=await facilitiesCollection.insertOne(facilityData)
   res.send(result)
})


app.get('/', (req,res) => {
    res.send("hello world!")

})


app.listen(PORT,()=>{
    console.log(`server is runnig at ${PORT}`);
})