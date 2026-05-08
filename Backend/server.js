import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const app = express();
app.use(cors());
app.use(express.json());

const User = mongoose.model("User", {
  email: String,
  password: String
});

const Data = mongoose.model("Data", {
  userId: String,
  data: Object
});

app.post("/auth/register", async (req,res)=>{
  const hash = await bcrypt.hash(req.body.password,10);
  await User.create({email:req.body.email,password:hash});
  res.json({msg:"ok"});
});

app.post("/auth/login", async (req,res)=>{
  const user = await User.findOne({email:req.body.email});
  if(!user) return res.sendStatus(400);

  const ok = await bcrypt.compare(req.body.password,user.password);
  if(!ok) return res.sendStatus(400);

  const token = jwt.sign({id:user._id},"segredo");
  res.json({token});
});

function auth(req,res,next){
  try{
    const token = req.headers.authorization;
    const decoded = jwt.verify(token,"segredo");
    req.userId = decoded.id;
    next();
  }catch{
    res.sendStatus(401);
  }
}

app.post("/data", auth, async (req,res)=>{
  await Data.findOneAndUpdate(
    {userId:req.userId},
    {data:req.body},
    {upsert:true}
  );
  res.json({msg:"salvo"});
});

app.get("/data", auth, async (req,res)=>{
  const d = await Data.findOne({userId:req.userId});
  res.json(d || {});
});

mongoose.connect(process.env.MONGO_URI)
.then(()=>console.log("db ok"));

app.listen(process.env.PORT || 3000);
