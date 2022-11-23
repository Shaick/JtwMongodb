require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')


const app = express()

// Config JSON response
app.use(express.json())

//Models
const User  = require('./models/User')

// Open Route - Public Route
app.get('/', (req, res) => {
    res.status(200).json({ msg: 'Bem vindo a nossa api!'})
})

//Private Route
app.get("/user/:id", checkToken, async(req, res) => {

    const id = req.params.id

    // check if user exist
    const user = await User.findById(id, '-password')

    if(!user) {
        return res.status(404).json({ 
            msg: 'Usuário não encontrado!'
        })
    } 

    res.status(200).json({ user })

})

function checkToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if(!token) {
        return res.status(401).json({ msg: 'Acesso negado!'})
    }

    try {
        const secret = process.env.SECRET

        jwt.verify(token, secret)
        next()

    } catch(erro) {
        res.status(400).json('Token Inválido!')
    }

}

// Register User
app.post('/auth/register', async (req, res) => {
    const { name, email, password, confirmpassword } = req.body

    // Validations
    if(!name) {
        return res.status(422).json({ msg: 'O Nome é obrigatório!'})
    }

    if(!email) {
        return res.status(422).json({ msg: 'O E-mail é obrigatório!'})
    }

    if(!password) {
        return res.status(422).json({ msg: 'A Senha é obrigatória!'})
    }

    if(password !== confirmpassword) {
        return res.status(422).json({ msg: 'Senhas não conferem!'})
    }

    // check if user exist
    const userExist = await User.findOne({ email: email })

    if(userExist) {
        return res.status(422).json({ msg: 'Email já cadastrado!'})
    } 
    
    //create password
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    // create user
    const user = new User({
        name,
        email,
        password: passwordHash
    })

    try {
        await user.save()

        res.status(201).json({msg: 'Usuário criado com sucesso'})
    } catch(error) {
        res.status(500).json({msg: error+"\n Erro no Servidor, tente novamente"})
    }   
})

//Login User
app.post("/auth/login", async (req,res) => {
    const { email, password } = req.body

    //validações
    if(!email) {
        return res.status(422).json({ msg: 'O E-mail é obrigatório!'})
    }

    if(!password) {
        return res.status(422).json({ msg: 'A Senha é obrigatória!'})
    }

    // check if user exist
    const user = await User.findOne({ email: email })

    if(!user) {
        return res.status(404).json({ msg: 'Usuário não encontrado!'})
    } 

    // check if password match
    const checkPassword = await bcrypt.compare(password, user.password)

    if(!checkPassword) {
        return res.status(422).json({ msg: 'Senha Inválida!'})
    }

    try {
        const secret = process.env.SECRET

        const token = jwt.sign(
            {
                id: user._id,
            },
            secret,
        )

        res.status(200).json({ msg: 'Autenticação realizada com sucesso!', token})
    } catch(err) {
        console.log(err)

        res.status(500).json({msg: err+"\n Erro no Servidor, tente novamente"})
    }
})

//Credentials
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS
const cluster = process.env.CLUSTER
const strConect = `mongodb+srv://${dbUser}:${dbPassword}@${cluster}.mongodb.net/?retryWrites=true&w=majority`

mongoose.connect(strConect).then(() => {
    app.listen(3000)
    console.log('Conectou se ao banco!')
}).catch((err) => console.log(''))

