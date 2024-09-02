const express = require("express")
require('dotenv').config()
const cors = require('cors')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()
// config json
app.use(express.json())
app.use(cors())

//Models
const User = require('./models/User')
//Open Route
app.get('/', (req, res) =>{
    res.status(200).json({msg: 'Bem vindo a nossa Api!'})
})
//Private route
app.get('/user/:id',checkToken, async(req, res)=>{
    const id = req.params.id
    //check if user exists
    const user = await User.findById(id, '-password')
    if(!user){
        return res.status(404).json({msg: 'usuario não encontrado'})
    }
    res.status(200).json({user})
})

function checkToken(req, res, next){
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if(!token){
        return res.status(401).json({msg: 'Acesso negado'})
    }

    try{
        const secret = process.env.SECRET

        jwt.verify(token, secret)

        next()
    } catch(error){
        res.status(400).json({msg: 'token invalido'})
    }
}
//Register User
app.post('/auth/register', async(req, res) =>{
    const {name, email, password, confirmpassword} = req.body
    //validations
    if(!name){
        return res.status(422).json({msg: 'nome obrigatório!'})
    }
    if(!email){
        return res.status(422).json({msg: 'email obrigatório!'})
    }
    if(!password){
        return res.status(422).json({msg: 'senha obrigatório!'})
    }
    if(password != confirmpassword){
        return res.status(422).json({msg: 'As senhas não conferem'})
    }

    //check if user exists
    const userExists = await User.findOne({email: email})

    if(userExists){
        return res.status(422).json({msg: 'Utilize outro email'})
    }

    // create password
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    //create user
    const user = new User({
        name,
        email,
        password: passwordHash,
    })
    try{

        await user.save()
        res.status(201).json({msg: 'user criado com sucesso!'})

    } catch(error){
        console.log(error);
        
        res.status(500).json({msg: error})
    }
})


//login user
app.post('/auth/login', async(req, res) =>{

    const {email, password} = req.body

    //validations
    if(!email){
        return res.status(422).json({msg: 'email obrigatório!'})
    }
    if(!password){
        return res.status(422).json({msg: 'senha obrigatório!'})
    }
    // check if user exists
    const user = await User.findOne({email: email})

    if(!user){
        return res.status(404).json({msg: 'usuário não existe'})
    }

    //check if password match
    const checkPassword = await bcrypt.compare(password, user.password)

    if(!checkPassword){
        return res.status(404).json({msg: 'senha inválida'})
    }

    try{
        const secret = process.env.SECRET
        const token = jwt.sign({
            id: user._id,
        },
    secret, 
    )

    res.status(200).json({msg: 'autenticação realizada com sucesso', token, id: user._id})
    } catch(error){
        console.log(error);
        
        res.status(500).json({msg: error})
    }
})
//Credenciais
const dbUser = process.env.DB_USER
const dbPass = process.env.DB_PASS

mongoose.connect(`mongodb+srv://${dbUser}:${dbPass}@loginusers.uw70m.mongodb.net/?retryWrites=true&w=majority&appName=loginusers`).then(()=>{
        app.listen(3000)
        console.log('Conectou ao banco!');
        
    }).catch((err) => console.log(err));
