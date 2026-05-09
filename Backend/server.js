import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const app = express();
app.use(cors());
app.use(express.json());

// --- CONEXÃO COM O BANCO DE DADOS ---
// O link será pego das configurações do seu Render (MONGO_URI)
const MONGO_URI = process.env.MONGO_URI; 

mongoose.connect(MONGO_URI)
  .then(() => console.log("✅ Banco de dados conectado!"))
  .catch((err) => console.error("❌ Erro ao conectar ao banco:", err));

// --- MODELOS ---
const User = mongoose.model("User", {
  email: { type: String, required: true },
  password: { type: String, required: true }
});

const Data = mongoose.model("Data", {
  userId: String,
  data: Object
});

// --- ROTAS ---

// 1. REGISTRO (Com verificação se já existe)
app.post("/auth/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    // VERIFICAÇÃO: Verifica se o usuário já existe no banco
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ msg: "Este e-mail já está cadastrado!" });
    }

    const hash = await bcrypt.hash(password, 10);
    await User.create({ email, password: hash });
    
    res.json({ msg: "Usuário criado com sucesso!" });
  } catch (err) {
    res.status(500).json({ msg: "Erro no servidor ao registrar." });
  }
});

// 2. LOGIN
app.post("/auth/login", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user) return res.status(400).json({ msg: "Usuário não encontrado." });

    const ok = await bcrypt.compare(req.body.password, user.password);
    if (!ok) return res.status(400).json({ msg: "Senha incorreta." });

    const token = jwt.sign({ id: user._id }, "segredo");
    res.json({ token });
  } catch (err) {
    res.status(500).json({ msg: "Erro no servidor ao logar." });
  }
});

// Middlewares e outras rotas permanecem iguais...
function auth(req, res, next) {
  try {
    const token = req.headers.authorization;
    const decoded = jwt.verify(token, "segredo");
    req.userId = decoded.id;
    next();
  } catch {
    res.sendStatus(401);
  }
}

app.post("/data", auth, async (req, res) => {
  await Data.findOneAndUpdate(
    { userId: req.userId },
    { data: req.body },
    { upsert: true }
  );
  res.json({ msg: "ok" });
});

app.get("/data", auth, async (req, res) => {
  const item = await Data.findOne({ userId: req.userId });
  res.json(item ? item.data : {});
});

// --- INICIALIZAÇÃO ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor rodando na porta ${PORT}`);
});
