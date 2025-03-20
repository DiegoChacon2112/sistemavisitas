const sql = require('mssql');

const dbConfig = {
    user: 'Sa',
    password: 'Sp#@2502',
    server: '192.168.0.207',
    database: 'SYS_MVK',
    options: {
        encrypt: false,
        enableArithAbort: true
    }
};

async function connectToDatabase() {
    try {
        const pool = await sql.connect(dbConfig);
        console.log("Conectado ao banco de dados com sucesso!");
        return pool;
    } catch (err) {
        console.error("Erro ao conectar ao banco de dados: ", err);
        throw err;
    }
}

module.exports = {
    sql, // Exporte o objeto sql aqui
    connectToDatabase
};
