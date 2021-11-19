import jwt from 'jsonwebtoken'
import bcrypt from 'bcrypt'
import fs from 'fs'

var users = {}; // Mocked database

async function getUsers() {
    return users;
}

async function createUser(user) {

    const encryptedPwd = await bcrypt.hash(user.password, 1);

    users[user.username] = {
        password: encryptedPwd,
        role: user.role
    }

    return user;
}

async function login(user) {
    const databaseUser = users[user.username];

    if (databaseUser) {
        const pwdMatches = bcrypt.compareSync(user.password, databaseUser.password);

        const privateKey = fs.readFileSync('./security/private.key', 'utf-8');

        if (pwdMatches) {
            const jwtToken = jwt.sign(
                { role: databaseUser.role, key: 'value' },
                privateKey,
                { expiresIn: 300, algorithm: 'RS256' }
            );
            return jwtToken
        } else {
            throw new Error('Senha incorreta');
        }
    } else {
        throw new Error('Usuário não encontrado');
    }
}

export default {
    getUsers,
    createUser,
    login
}