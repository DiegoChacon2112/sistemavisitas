const express = require('express');
const path = require('path');
const cors = require('cors');
const bodyParser = require('body-parser');
const session = require('express-session');
const { sql, connectToDatabase } = require('./dbConfig');
const axios = require('axios');
const app = express();
//const port = 3000;
const port = process.env.PORT;
const enviarEmail = require('./services/emailService');

// Configurar EJS como motor de template
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views')); // Certifique-se de que os arquivos EJS estão na pasta 'views'

// Configuração de middleware
app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
    secret: 'sua_chave_secreta', // Substitua por uma chave secreta única
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Se estiver usando HTTPS, altere para true
}));

// Servir arquivos estáticos na pasta 'public'
app.use(express.static(path.join(__dirname, 'public')));

// Conectar ao banco de dados ao iniciar o servidor
let pool;
async function startServer() {
    try {
        pool = await connectToDatabase();
        console.log('Conexão com o banco de dados estabelecida com sucesso!');
        app.listen(port, () => {
            console.log(`Servidor rodando em http://localhost:${port}`);
        });
    } catch (err) {
        console.error('Erro ao conectar ao banco de dados:', err);
    }
}

// Rota para servir a página home com dados de sessão
app.get('/home', (req, res) => {
    if (!req.session.userLogin || !req.session.userName) {
        return res.redirect('/'); // Redireciona para a página de login se não estiver autenticado
    }

    // Renderiza home.ejs com os dados do usuário
    res.render('home', {
        userLogin: req.session.userLogin,
        userName: req.session.userName,
        autorizaVisitas: req.session.autorizaVisitas,
        aberturasPortoes: req.session.aberturasPortoes, // Passando aberturaPortoes para a view
        acessologistica: req.session.acessologistica,
        visualizabotoes: req.session.visualizabotoes,
        useradministrador: req.session.useradministrador
    });
});

// Rota para validação do login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const result = await pool.request()
            .input('username', sql.VarChar, username)
            .input('password', sql.VarChar, password)
            .query(`
                SELECT LOGIN, USUARIO, AUTORIZA_VISITAS, ABERTURA_PORTOES, ACESSO_LOGISTICA, VISUALIZA_BOTOES, ADMINISTRADOR FROM USERS 
                WHERE LOGIN = @username 
                AND SENHA = @password
            `);

        if (result.recordset.length > 0) {
            const user = result.recordset[0];
            req.session.userLogin = user.LOGIN;
            req.session.userName = user.USUARIO;
            req.session.autorizaVisitas = user.AUTORIZA_VISITAS;
            req.session.aberturasPortoes = user.ABERTURA_PORTOES;
            req.session.acessologistica = user.ACESSO_LOGISTICA; // Adiciona a permissão de abertura de portões
            req.session.visualizabotoes = user.VISUALIZA_BOTOES; // Adiciona a permissão de abertura de portões
            req.session.useradministrador = user.ADMINISTRADOR; // Adiciona a permissão de abertura de portões

            res.send({ success: true, message: "Login bem-sucedido", redirectUrl: '/home' });
        } else {
            res.send({ success: false, message: "Usuário ou senha inválidos" });
        }
    } catch (err) {
        console.error("Erro ao consultar o banco de dados:", err);
        res.status(500).send({ success: false, message: "Erro interno no servidor" });
    }
});

// Rota para logout
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error("Erro ao encerrar a sessão:", err);
            return res.redirect('/home'); // Se houver erro, redireciona de volta ao home
        }
        res.redirect('/'); // Redireciona para a página de login após encerrar a sessão
    });
});




// Rota para servir a página home com dados de sessão
app.get('/home', (req, res) => {
    if (!req.session.userLogin || !req.session.userName) {
        return res.redirect('/'); // Redireciona para a página de login se não estiver autenticado
    }

    // Renderiza home.ejs com os dados do usuário
    res.render('home', {
        userLogin: req.session.userLogin,
        userName: req.session.userName,
        autorizaVisitas: req.session.autorizaVisitas,
        aberturasPortoes: req.session.aberturasPortoes,
        password: req.session.password
    });
});






// Rota para validação do login
app.post('/trocar-senha', async (req, res) => {
    const { email, newPassword } = req.body; // Não precisa mais da senha atual

    try {
        // Senha atual está correta, atualize a senha
        await pool.request()
            .input('email', sql.VarChar, email)
            .input('newPassword', sql.VarChar, newPassword)
            .query(`
                UPDATE USERS SET SENHA = @newPassword 
                WHERE LOGIN = @email 
            `);

        res.send({ success: true, message: "Senha atualizada com sucesso", redirectUrl: '/home' });
    } catch (err) {
        console.error("Erro ao consultar o banco de dados:", err);
        res.status(500).send({ success: false, message: "Erro interno no servidor" });
    }
});








// Rota para abertura de portões
app.post('/abrir-portao-social', async (req, res) => {
    const { gateType } = req.body; // Captura o tipo de portão enviado pelo frontend

    let gateName;

    // Define o nome do portão com base no tipo de portão
    if (gateType === 'social') {
        gateName = 'ENTRADA SOCIAL';
    } else if (gateType === 'torniquete') {
        gateName = 'ENTRADA TORNIQUETE';
    } else if (gateType === 'veiculos') {
        gateName = 'ACESSO VEICULAR - FACIAL';
    } else {
        return res.status(400).json({ success: false, message: 'Tipo de portão inválido' });
    }

    try {
        const response = await axios.post('https://192.168.1.204:8090/portaria/v1/bravas/command', {
            command: {
                type: "accessCmd",
                action: "open",
                target: {
                    name: gateName, // Usa o nome do portão definido acima
                    uuid: "ae620012-18d3-48fd-8e51-4d648376d231" // O UUID permanece o mesmo
                },
                operator: "bravas",
                enforce_rules: true,
                user: "Visitante"
            }
        }, {
            headers: {
                'Authorization': `Bearer @Mvk#2024`,
                'Content-Type': 'application/json'
            },
            httpsAgent: new require('https').Agent({ rejectUnauthorized: false })
        });

        if (response.status === 200) {
            res.json({ success: true, message: `${gateName} aberto com sucesso!` });
        } else {
            res.status(500).json({ success: false, message: 'Erro ao abrir o portão' });
        }
    } catch (error) {
        console.error('Erro ao abrir o portão:', error);
        res.status(500).json({ success: false, message: 'Erro ao abrir o portão' });
    }
});




// Rota para a página de administração
app.get('/admin', (req, res) => {
    // Verifique se o usuário está autenticado e se tem permissão de administrador
    if (!req.session.userLogin || !req.session.userName || req.session.useradministrador !== 'S') {
        return res.redirect('/home'); // Redirecione para a página inicial se não estiver autenticado ou não for administrador
    }

    // Renderize a página admin.ejs
    res.render('admin', {
        userName: req.session.userName, // Envie o nome do usuário para a página
        autorizaVisitas: req.session.autorizaVisitas, // Envie a permissão de visitas para a página
        aberturasPortoes: req.session.aberturasPortoes
    });
});



// Rota para buscar usuários
app.get('/api/usuarios', async (req, res) => {
    try {
        // Faz a consulta SQL para buscar usuários
        const result = await pool.request()
            .query(`SELECT USUARIO, LOGIN FROM USERS ORDER BY USUARIO ASC`);

        res.json({ usuarios: result.recordset }); // Retorna os usuários em JSON
    } catch (err) {
        console.error("Erro ao consultar o banco de dados:", err);
        res.status(500).send({ success: false, message: "Erro interno no servidor" });
    }
});


// Rota para excluir usuário
app.post('/api/excluir-usuario', async (req, res) => {
    const { login } = req.body;

    try {
        // Faz a exclusão do usuário no banco de dados
        const result = await pool.request()
            .input('login', sql.VarChar, login)
            .query(`DELETE FROM USERS WHERE LOGIN = @login`);

        res.json({ success: true, message: 'Usuário excluído com sucesso!' });
    } catch (err) {
        console.error("Erro ao excluir usuário:", err);
        res.status(500).send({ success: false, message: "Erro interno no servidor" });
    }
});



// Rota para adicionar um novo usuário
app.post('/api/novo-usuario', async (req, res) => {
    const { login, usuario, senha, permissoes } = req.body;

    try {
        // Valide os dados (opcional)
        // ... (verifique se o login já existe, se a senha atende aos requisitos, etc)

        // Prepare as permissões para o INSERT
        const permissaoAdmin = permissoes.admin ? 'S' : 'N';
        const permissaoAberturaPortasVisita = permissoes.aberturaPortasVisita ? 'S' : 'N';
        const permissaoClienteRetira = permissoes.clienteRetira ? 'S' : 'N';
        const permissaoAutorizaVisitas = permissoes.autorizaVisitas ? 'S' : 'N';
        const permissaoAberturaPortasTelaInicial = permissoes.aberturaPortasTelaInicial ? 'S' : 'N';

        // Insira o novo usuário no banco de dados (sem usar a variável 'result')
        await pool.request()
            .input('login', sql.VarChar, login)
            .input('usuario', sql.VarChar, usuario)
            .input('senha', sql.VarChar, senha)
            .input('permissaoAdmin', sql.VarChar, permissaoAdmin)
            .input('permissaoAberturaPortasVisita', sql.VarChar, permissaoAberturaPortasVisita)
            .input('permissaoClienteRetira', sql.VarChar, permissaoClienteRetira)
            .input('permissaoAutorizaVisitas', sql.VarChar, permissaoAutorizaVisitas)
            .input('permissaoAberturaPortasTelaInicial', sql.VarChar, permissaoAberturaPortasTelaInicial)
            .query(`
          INSERT INTO USERS (LOGIN, USUARIO, SENHA, ADMINISTRADOR, ABERTURA_PORTOES, ACESSO_LOGISTICA, AUTORIZA_VISITAS, VISUALIZA_BOTOES) 
          VALUES (@login, @usuario, @senha, @permissaoAdmin, @permissaoAberturaPortasVisita, @permissaoClienteRetira, @permissaoAutorizaVisitas, @permissaoAberturaPortasTelaInicial)
        `);

        res.send({ success: true, message: 'Novo usuário cadastrado com sucesso!' });
    } catch (err) {
        console.error("Erro ao cadastrar novo usuário:", err);
        res.status(500).send({ success: false, message: 'Erro ao cadastrar novo usuário' });
    }
});




// Rota para buscar permissões do usuário
app.get('/api/permissoes-usuario', async (req, res) => {
    const { login } = req.query; // Obtenha o login do usuário da query string
  
    try {
      const result = await pool.request()
          .input('login', sql.VarChar, login)
          .query(`
              SELECT 
                  CASE WHEN ADMINISTRADOR = 'S' THEN 1 ELSE 0 END AS PermissaoAdmin,
                  CASE WHEN ABERTURA_PORTOES = 'S' THEN 1 ELSE 0 END AS PermissaoAberturaPortasVisita,
                  CASE WHEN ACESSO_LOGISTICA = 'S' THEN 1 ELSE 0 END AS PermissaoClienteRetira,
                  CASE WHEN AUTORIZA_VISITAS = 'S' THEN 1 ELSE 0 END AS PermissaoAutorizaVisitas,
                  CASE WHEN VISUALIZA_BOTOES = 'S' THEN 1 ELSE 0 END AS PermissaoAberturaPortasTelaInicial
              FROM USERS
              WHERE LOGIN = @login
          `);
  
      // Converta os resultados para um objeto de permissões
      const permissoes = result.recordset.map(row => ({
        Permissao: 'Administrador',
        Ativo: row.PermissaoAdmin
      }, {
        Permissao: 'Abertura de Portões na Visita',
        Ativo: row.PermissaoAberturaPortasVisita
      }, {
        Permissao: 'Opção Cliente Retira',
        Ativo: row.PermissaoClienteRetira
      }, {
        Permissao: 'Autoriza Visitas',
        Ativo: row.PermissaoAutorizaVisitas
      }, {
        Permissao: 'Abertura de Portões na Tela Inicial',
        Ativo: row.PermissaoAberturaPortasTelaInicial
      }));
  
      res.json({ permissoes: permissoes }); 
    } catch (err) {
      console.error("Erro ao consultar o banco de dados:", err);
      res.status(500).send({ success: false, message: "Erro interno no servidor" });
    }
  });
  


// Rota para alterar as permissões do usuário
app.post('/api/alterar-permissoes', async (req, res) => {
    const { login, permissoes } = req.body;

    try {
        // Atualiza as permissões do usuário no banco de dados
        const result = await pool.request()
            .input('login', sql.VarChar, login)
            .input('permissaoAdmin', sql.VarChar, permissoes.admin)
            .input('permissaoAberturaPortasVisita', sql.VarChar, permissoes.aberturaPortasVisita)
            .input('permissaoClienteRetira', sql.VarChar, permissoes.clienteRetira)
            .input('permissaoAutorizaVisitas', sql.VarChar, permissoes.autorizaVisitas)
            .input('permissaoAberturaPortasTelaInicial', sql.VarChar, permissoes.aberturaPortasTelaInicial)
            .query(`
                UPDATE USERS 
                SET ADMINISTRADOR = @permissaoAdmin, 
                    ABERTURA_PORTOES = @permissaoAberturaPortasVisita, 
                    ACESSO_LOGISTICA = @permissaoClienteRetira, 
                    AUTORIZA_VISITAS = @permissaoAutorizaVisitas, 
                    VISUALIZA_BOTOES = @permissaoAberturaPortasTelaInicial
                WHERE LOGIN = @login
            `);

        res.send({ success: true, message: 'Permissões atualizadas com sucesso!' });
    } catch (err) {
        console.error("Erro ao atualizar as permissões do usuário:", err);
        res.status(500).send({ success: false, message: "Erro interno no servidor" });
    }
});




//********************************************************************/
//**************** ROTAS PARA ENVIO DE E-MAIL ***********************//
//********************************************************************/


// Exemplo de uso após agendar uma visita
app.post('/enviar-email', async (req, res) => {
    const { destinatario, data, visitTime, companyName, visitorName, responsibleMVK, otherVisitors, numPessoas, visitType, visitReason, userName } = req.body;

    // Assunto do e-mail
    const assunto = 'Agendamento de Visita - ' + companyName;
    let visitTypeText; // Declaração sem inicialização

    console.log(visitType)

    if (visitType === '1') {
        visitTypeText = 'Visita';
    } else if (visitType === '2') {
        visitTypeText = 'Manutencao';
    } else if (visitType === '3') {
        visitTypeText = 'Visita Cliente';
    } else {
        visitTypeText = 'Visita Fornecedor';
    }


    // Conteúdo HTML do e-mail
    const htmlConteudo = `
                    <!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Solicitação de Visita</title>
</head>
<body style="margin: 0; padding: 0; background-color: #f4f4f4; font-family: Arial, sans-serif;">
    <table cellpadding="0" cellspacing="0" border="0" width="100%" style="background-color: #f4f4f4; width: 100%; margin: 0 auto;">
        <tr>
            <td align="center">
                <table cellpadding="0" cellspacing="0" border="0" width="600" style="width: 100%; max-width: 600px; background-color: #ffffff; border: 1px solid #e0e0e0;">
                    <tr>
                        <td style="background-color: #4CAF50; color: white; padding: 20px; text-align: center;">
                            <h1 style="margin: 0; font-size: 24px; color: #ffffff;">Confirmação de Agendamento</h1>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 20px; color: #333; line-height: 1.6;">
                            <h2 style="font-size: 22px; color: #4CAF50; margin-bottom: 20px;">Olá, o usuário ${userName} abriu uma nova agenda de visita</h2>
                            <p>O agendamento foi realizado com os seguintes detalhes:</p>
                            <table cellpadding="0" cellspacing="0" border="0" width="100%" style="width: 100%; border-collapse: collapse;">
                                <tr>
                                    <th style="background-color: #f2f2f2; padding: 10px; border: 1px solid #dddddd; text-align: left;">Data</th>
                                    <td style="padding: 10px; border: 1px solid #dddddd;">${data}</td>
                                </tr>
                                <tr>
                                    <th style="background-color: #f2f2f2; padding: 10px; border: 1px solid #dddddd; text-align: left;">Hora</th>
                                    <td style="padding: 10px; border: 1px solid #dddddd;">${visitTime}</td>
                                </tr>
                                <tr>
                                    <th style="background-color: #f2f2f2; padding: 10px; border: 1px solid #dddddd; text-align: left;">Empresa</th>
                                    <td style="padding: 10px; border: 1px solid #dddddd;">${companyName}</td>
                                </tr>
                                <tr>
                                    <th style="background-color: #f2f2f2; padding: 10px; border: 1px solid #dddddd; text-align: left;">Visitante</th>
                                    <td style="padding: 10px; border: 1px solid #dddddd;">${visitorName}</td>
                                </tr>
                                <tr>
                                    <th style="background-color: #f2f2f2; padding: 10px; border: 1px solid #dddddd; text-align: left;">Responsável</th>
                                    <td style="padding: 10px; border: 1px solid #dddddd;">${responsibleMVK}</td>
                                </tr>
                                <tr>
                                    <th style="background-color: #f2f2f2; padding: 10px; border: 1px solid #dddddd; text-align: left;">Outros Visitantes</th>
                                    <td style="padding: 10px; border: 1px solid #dddddd;">${otherVisitors}</td>
                                </tr>
                                 <tr>
                                    <th style="background-color: #f2f2f2; padding: 10px; border: 1px solid #dddddd; text-align: left;">Quantidade de Visitantes</th>
                                    <td style="padding: 10px; border: 1px solid #dddddd;">${numPessoas}</td>
                                </tr>
                                <tr>
                                    <th style="background-color: #f2f2f2; padding: 10px; border: 1px solid #dddddd; text-align: left;">Tipo de Visita</th>
                                    <td style="padding: 10px; border: 1px solid #dddddd;">${visitTypeText}</td>
                                </tr>
                                <tr>
                                    <th style="background-color: #f2f2f2; padding: 10px; border: 1px solid #dddddd; text-align: left;">Motivo</th>
                                    <td style="padding: 10px; border: 1px solid #dddddd;">${visitReason}</td>
                                </tr>
                            </table>
                            <p style="margin-top: 20px;">Acesse o sistema de Agendamento de Visitas para realizar as ações necessárias.</p>
                        </td>
                    </tr>
                    <tr>
                        <td style="background-color: #4CAF50; color: white; padding: 20px; text-align: center; font-size: 12px;">
                            <p style="margin: 0;">Este é um e-mail automático, por favor, não responda.</p>
                            <p style="margin: 0;">© 2024 MVK - Todos os direitos reservados.</p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>


    `;


    try {
        // Envio do e-mail

        await enviarEmail(destinatario, assunto, htmlConteudo, visitTypeText);
        res.send({ success: true, message: 'Visita agendada e e-mail enviado!' });
    } catch (err) {
        res.status(500).send({ success: false, message: 'Erro ao enviar o e-mail.' });
    }
});



///////Envio de E-mail da Aprovação da Visita

app.post('/enviar-email-aprovado', async (req, res) => {
    const { codigo, visitDate, visitTime, companyName, destinatarios, brinde, coffebreak, almoco, catalogo, QtdVisita, local, brindeouro, brindeprata, brindebronze } = req.body;

    // Verifica se o destinatário foi passado corretamente
    if (!destinatarios) {
        return res.status(400).send({ success: false, message: 'E-mail do destinatário não informado.' });
    }

    let destinatario = destinatarios; // Assume que 'destinatario' já contém um endereço

    // Regras para adicionar destinatários com base nos campos
    if (almoco === 'Sim' || brinde === 'Sim' || coffebreak === 'Sim') {
        destinatario += ',giani.rodrigues@mvk.com.br';
    }

    if (catalogo === 'Sim') {
        destinatario += ',sabrina.almeida@mvk.com.br';
    }

    // Assunto do e-mail
    const assunto = 'Visita Aprovada - ' + codigo;


    // Conteúdo HTML do e-mail
    const htmlConteudo = `
<table cellpadding="0" cellspacing="0" border="0" width="100%" style="font-family: Arial, sans-serif; color: #333;">
<tr>
 <td align="center">
     <table cellpadding="0" cellspacing="0" border="0" width="600" style="border: 1px solid #e0e0e0; background-color: #ffffff;">
         <tr>
             <td style="background-color: #4CAF50; padding: 20px; text-align: center;">
                 <h2 style="color: #ffffff; font-size: 24px;">Parabéns, seu agendamento de visita foi Aprovado!</h2>
             </td>
         </tr>
         <tr>
             <td style="padding: 20px;">
                 <p>Olá,</p>
                 <p>Estamos felizes em informar que seu agendamento de visita foi aprovado. Confira os detalhes abaixo:</p>
                 
                 <table cellpadding="0" cellspacing="0" border="0" width="100%" style="margin-top: 20px; border-collapse: collapse;">
                     <tr>
                         <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2;">Código</th>
                         <td style="border: 1px solid #ddd; padding: 8px;">${codigo}</td>
                     </tr>
                     <tr>
                         <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2;">Data</th>
                         <td style="border: 1px solid #ddd; padding: 8px;">${visitDate}</td>
                     </tr>
                     <tr>
                         <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2;">Hora</th>
                         <td style="border: 1px solid #ddd; padding: 8px;">${visitTime}</td>
                     </tr>
                     <tr>
                         <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2;">Empresa</th>
                         <td style="border: 1px solid #ddd; padding: 8px;">${companyName}</td>
                     </tr>
                     <tr>
                         <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2;">Local</th>
                         <td style="border: 1px solid #ddd; padding: 8px;">${local}</td>
                     </tr>
                      <tr>
                         <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2;">Qtd Visitantes</th>
                         <td style="border: 1px solid #ddd; padding: 8px;">${QtdVisita}</td>
                     </tr>

                     ${brinde === "Sim" ? `
                     <tr>
                         <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2;">Brinde</th>
                         <td style="border: 1px solid #ddd; padding: 8px;">
                             <ul>
                                 ${brindeouro > 0 ? `<li>Brinde Ouro: ${brindeouro}</li>` : ''}
                                 ${brindeprata > 0 ? `<li>Brinde Prata: ${brindeprata}</li>` : ''}
                                 ${brindebronze > 0 ? `<li>Brinde Bronze: ${brindebronze}</li>` : ''}
                             </ul>
                         </td>
                     </tr>` : ''}
                     <tr>
                         <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2;">Coffee Break</th>
                         <td style="border: 1px solid #ddd; padding: 8px;">${coffebreak}</td>
                     </tr>
                     <tr>
                         <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2;">Almoço</th>
                         <td style="border: 1px solid #ddd; padding: 8px;">${almoco}</td>
                     </tr>
                     <tr>
                         <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2;">Catálogo</th>
                         <td style="border: 1px solid #ddd; padding: 8px;">${catalogo}</td>
                     </tr>
                 </table>

                 <p style="color: #999; font-size: 12px; text-align: center;">Este é um e-mail automático, por favor, não responda.</p>
             </td>
         </tr>
     </table>
 </td>
</tr>
</table>
`;


    try {
        // Envio do e-mail
        await enviarEmail(destinatario, assunto, htmlConteudo);
        res.send({ success: true, message: 'E-mail de aprovação enviado com sucesso!' });
    } catch (err) {
        console.error('Erro ao enviar o e-mail:', err);
        res.status(500).send({ success: false, message: 'Erro ao enviar o e-mail.' });
    }
});
/////Fim do e-mail de Aprovação da Visita




///////Envio de E-mail da Rejeição da Visita

app.post('/enviar-email-rejeicao', async (req, res) => {
    const { codigo, visitDate, visitTime, companyName, motivoRejeicao, destinatario } = req.body;

    // Verifica se o destinatário foi passado corretamente
    if (!destinatario) {
        return res.status(400).send({ success: false, message: 'E-mail do destinatário não informado.' });
    }

    // Assunto do e-mail
    const assunto = 'Rejeição da Visita - ' + codigo;


    // Conteúdo HTML do e-mail
    const htmlConteudo = `
        <table cellpadding="0" cellspacing="0" border="0" width="100%" style="font-family: Arial, sans-serif; color: #333;">
            <tr>
                <td align="center">
                    <table cellpadding="0" cellspacing="0" border="0" width="600" style="border: 1px solid #e0e0e0; background-color: #ffffff;">
                        <tr>
                            <td style="background-color: #f44336; padding: 20px; text-align: center;">
                                <h2 style="color: #ffffff; font-size: 24px;">Que pena, seu agendamento de visita não foi aprovado</h2>
                            </td>
                        </tr>
                        <tr>
                            <td style="padding: 20px;">
                                <p>Olá,</p>
                                <p>Lamentamos informar que seu agendamento visita não foi aprovada. Confira os detalhes abaixo:</p>
                                
                                <table cellpadding="0" cellspacing="0" border="0" width="100%" style="margin-top: 20px; border-collapse: collapse;">
                                    <tr>
                                        <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2;">Código</th>
                                        <td style="border: 1px solid #ddd; padding: 8px;">${codigo}</td>
                                    </tr>
                                    <tr>
                                        <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2;">Data</th>
                                        <td style="border: 1px solid #ddd; padding: 8px;">${visitDate}</td>
                                    </tr>
                                    <tr>
                                        <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2;">Hora</th>
                                        <td style="border: 1px solid #ddd; padding: 8px;">${visitTime}</td>
                                    </tr>
                                    <tr>
                                        <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2;">Empresa</th>
                                        <td style="border: 1px solid #ddd; padding: 8px;">${companyName}</td>
                                    </tr>
                                    <tr>
                                        <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2;">Motivo da Rejeição</th>
                                        <td style="border: 1px solid #ddd; padding: 8px; color: #d32f2f;">${motivoRejeicao}</td>
                                    </tr>
                                </table>

                                <p style="color: #999; font-size: 12px; text-align: center;">Este é um e-mail automático, por favor, não responda.</p>
                            </td>
                        </tr>
                    </table>
                </td>
            </tr>
        </table>
    `;

    try {
        // Envio do e-mail
        await enviarEmail(destinatario, assunto, htmlConteudo);
        res.send({ success: true, message: 'E-mail de rejeição enviado com sucesso!' });
    } catch (err) {
        console.error('Erro ao enviar o e-mail:', err);
        res.status(500).send({ success: false, message: 'Erro ao enviar o e-mail.' });
    }
});
/////Fim do e-mail de Rejeição da Visita




///////Envio de E-mail da Exclusão da Visita

app.post('/enviar-email-exclusao', async (req, res) => {
    const { codigo, visitDate, visitTime, companyName, email, brinde, coffebreak, almoco, catalogo, solicitante } = req.body;

    // Assunto do e-mail
    const assunto = `Visita Cancelada - Código ${codigo}`;


    let destinatario = email; // Assume que 'destinatario' já contém um endereço


    // Regras para adicionar destinatários com base nos campos
    if (almoco === 'Sim' || brinde === 'Sim' || coffebreak === 'Sim') {
        destinatario += ',giani.rodrigues@mvk.com.br';
    }

    if (catalogo === 'Sim') {
        destinatario += ',sabrina.almeida@mvk.com.br';
    }



    // Conteúdo HTML do e-mail
    const htmlConteudo = `
        <table cellpadding="0" cellspacing="0" border="0" width="100%" style="font-family: Arial, sans-serif; color: #333;">
            <tr>
                <td align="center">
                    <table cellpadding="0" cellspacing="0" border="0" width="600" style="border: 1px solid #e0e0e0; background-color: #f2f2f2;">
                        <tr>
                            <td style="background-color: #777; padding: 20px; text-align: center;">
                                <h2 style="color: #ffffff; font-size: 24px;">Visita Cancelada</h2>
                            </td>
                        </tr>
                        <tr>
                            <td style="padding: 20px;">
                                <p>Olá,</p>
                                <p>Informamos que uma visita foi cancelada. Confira os detalhes abaixo:</p>
                                
                                <table cellpadding="0" cellspacing="0" border="0" width="100%" style="margin-top: 20px; border-collapse: collapse;">
                                    <tr>                                        <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2;">Código</th>
                                        <td style="border: 1px solid #ddd; padding: 8px;">${codigo}</td>
                                    </tr>
                                    <tr>
                                        <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2;">Data</th>
                                        <td style="border: 1px solid #ddd; padding: 8px;">${visitDate}</td>
                                    </tr>
                                    <tr>
                                        <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2;">Hora</th>
                                        <td style="border: 1px solid #ddd; padding: 8px;">${visitTime}</td>
                                    </tr>
                                    <tr>
                                        <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2;">Empresa</th>
                                        <td style="border: 1px solid #ddd; padding: 8px;">${companyName}</td>
                                    </tr>
                                    <tr>
                                        <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2;">Brinde</th>
                                        <td style="border: 1px solid #ddd; padding: 8px;">${brinde}</td>
                                    </tr>
                                    <tr>
                                        <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2;">Coffee Break</th>
                                        <td style="border: 1px solid #ddd; padding: 8px;">${coffebreak}</td>
                                    </tr>
                                    <tr>
                                        <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2;">Almoço</th>
                                        <td style="border: 1px solid #ddd; padding: 8px;">${almoco}</td>
                                    </tr>
                                    <tr>
                                        <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2;">Catálogo</th>
                                        <td style="border: 1px solid #ddd; padding: 8px;">${catalogo}</td>
                                    </tr>
                                    <tr>
                                        <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2;">Solicitante</th>
                                        <td style="border: 1px solid #ddd; padding: 8px;">${solicitante}</td>
                                    </tr>
                                </table>

                                <p style="color: #999; font-size: 12px; text-align: center;">Este é um e-mail automático, por favor, não responda.</p>
                            </td>
                        </tr>
                    </table>
                </td>
            </tr>
        </table>
    `;

    try {
        // Envio do e-mail
        await enviarEmail(destinatario, assunto, htmlConteudo);
        res.send({ success: true, message: 'E-mail de exclusão enviado com sucesso!' });
    } catch (err) {
        console.error('Erro ao enviar o e-mail:', err);
        res.status(500).send({ success: false, message: 'Erro ao enviar o e-mail.' });
    }
});
/////Fim do e-mail de Exclusão da Visita



/// Envio de e-mail de Reagendamento
app.post('/enviar-email-reagendamento', async (req, res) => {
    const { codigo, novaData, novaHora, empresa, brinde, coffeebreak, almoco, catalogo, solicitante, motivo, email, tipoVisita } = req.body;

    // Verifica se os dados foram recebidos corretamente
    if (!codigo || !novaData || !novaHora || !email) {
        return res.status(400).send({ success: false, message: 'Dados incompletos para envio do e-mail.' });
    }

    let destinatario = email; // Assume que 'destinatario' já contém um endereço

    if (tipoVisita === 'Visita') {
        destinatario += ',daniela.cippola@mvk.com.br,francisco.vendramini@mvk.com.br'; // Junta os e-mails de visita
    } else if (tipoVisita === 'Manutenção') {
        destinatario += ',sabrina.almeida@mvk.com.br,francisco.vendramini@mvk.com.br,andre.jesus@mvk.com.br,diego.chacon@mvk.com.br';
    } else if (tipoVisita === 'CRetira') {
        destinatario += ',sabrina.almeida@mvk.com.br,gabriel.alves@mvk.com.br,marcelo.casarin@mvk.com.br';
    }

    // Assunto do e-mail
    const assunto = 'Reagendamento de Visita - ' + codigo;

    // Conteúdo HTML do e-mail
    const htmlConteudo = `
        <table cellpadding="0" cellspacing="0" border="0" width="100%" style="font-family: Arial, sans-serif; color: #333;">
            <tr>
                <td align="center">
                    <table cellpadding="0" cellspacing="0" border="0" width="600" style="border: 1px solid #e0e0e0; background-color: #ffffff;">
                        <tr>
                            <td style="background-color: #FFA500; padding: 20px; text-align: center;">
                                <h2 style="color: #ffffff; font-size: 24px;">Visita Reagendada!</h2>
                            </td>
                        </tr>
                        <tr>
                            <td style="padding: 20px;">
                                <p>Olá,</p>

                                ${tipoVisita === "Visita" ? `<p>Informamos que a seguinte visita foi reagendada e esta aguardando nova aprovação. Confira os novos detalhes abaixo:</p>` 
                                : `<p>Informamos que a seguinte visita foi reagendada. Confira os novos detalhes abaixo:</p>`
                                }


                                
                                <table cellpadding="0" cellspacing="0" border="0" width="100%" style="margin-top: 20px; border-collapse: collapse;">
                                    <tr>
                                        <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2;">Código</th>
                                        <td style="border: 1px solid #ddd; padding: 8px;">${codigo}</td>
                                    </tr>
                                    <tr>
                                        <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2;">Código</th>
                                        <td style="border: 1px solid #ddd; padding: 8px;">${tipoVisita}</td>
                                    </tr>
                                    <tr>
                                        <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2;">Nova Data</th>
                                        <td style="border: 1px solid #ddd; padding: 8px;">${novaData}</td>
                                    </tr>
                                    <tr>
                                        <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2;">Nova Hora</th>
                                        <td style="border: 1px solid #ddd; padding: 8px;">${novaHora}</td>
                                    </tr>
                                    <tr>
                                        <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2;">Empresa</th>
                                        <td style="border: 1px solid #ddd; padding: 8px;">${empresa}</td>
                                    </tr>
                                    <tr>
                                        <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2;">Brinde</th>
                                        <td style="border: 1px solid #ddd; padding: 8px;">${brinde}</td>
                                    </tr>
                                    <tr>
                                        <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2;">Coffee Break</th>
                                        <td style="border: 1px solid #ddd; padding: 8px;">${coffeebreak}</td>
                                    </tr>
                                    <tr>
                                        <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2;">Almoço</th>
                                        <td style="border: 1px solid #ddd; padding: 8px;">${almoco}</td>
                                    </tr>
                                    <tr>
                                        <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2;">Catálogo</th>
                                        <td style="border: 1px solid #ddd; padding: 8px;">${catalogo}</td>
                                    </tr>
                                    <tr>
                                        <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2;">Solicitante</th>
                                        <td style="border: 1px solid #ddd; padding: 8px;">${solicitante}</td>
                                    </tr>
                                    <tr>
                                        <th style="border: 1px solid #ddd; padding: 8px; background-color: #f2f2f2;">Motivo do Reagendamento</th>
                                        <td style="border: 1px solid #ddd; padding: 8px; color: #d32f2f;">${motivo}</td>
                                    </tr>
                                </table>


                                <p style="margin-top: 20px;">Acesse o sistema de agendamentos MVK e realize as açôes necessárias.</p>


                                <p style="color: #999; font-size: 12px; text-align: center;">Este é um e-mail automático, por favor, não responda.</p>
                            </td>
                        </tr>
                    </table>
                </td>
            </tr>
        </table>
    `;

    console.log(htmlConteudo)

    try {
        await enviarEmail(destinatario, assunto, htmlConteudo);
        res.send({ success: true, message: 'E-mail de reagendamento enviado com sucesso!' });
    } catch (err) {
        console.error('Erro ao enviar o e-mail:', err);
        res.status(500).send({ success: false, message: 'Erro ao enviar o e-mail.' });
    }
});
/// Fim do envio de e-mail de reagendamento





// Exemplo de uso após agendar uma visita
app.post('/email-cliente-retira', async (req, res) => {
    const { destinatario, data, visitTime, companyName, visitorName, responsibleMVK, otherVisitors, visitType, visitReason, userName } = req.body;


    // Assunto do e-mail
    const assunto = 'Agendamento de Coleta de Pedido - ' + companyName;
    let visitTypeText; // Declaração sem inicialização

    console.log(visitType)


    visitTypeText = 'Cliente Retira';

    console.log(visitTypeText)


    // Conteúdo HTML do e-mail
    const htmlConteudo = `
                    <!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Solicitação de Visita</title>
</head>
<body style="margin: 0; padding: 0; background-color: #f4f4f4; font-family: Arial, sans-serif;">
    <table cellpadding="0" cellspacing="0" border="0" width="100%" style="background-color: #f4f4f4; width: 100%; margin: 0 auto;">
        <tr>
            <td align="center">
                <table cellpadding="0" cellspacing="0" border="0" width="600" style="width: 100%; max-width: 600px; background-color: #ffffff; border: 1px solid #e0e0e0;">
                    <tr>
                        <td style="background-color: #d6cb22; color: white; padding: 20px; text-align: center;">
                            <h1 style="margin: 0; font-size: 24px; color: #ffffff;">Confirmação de Agendamento</h1>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 20px; color: #333; line-height: 1.6;">
                            <h2 style="font-size: 22px; color: #d6cb22; margin-bottom: 20px;">Olá, o usuário ${userName} abriu uma nova agenda para coleta de pedido de venda</h2>
                            <p>O agendamento foi realizado com os seguintes detalhes:</p>
                            <table cellpadding="0" cellspacing="0" border="0" width="100%" style="width: 100%; border-collapse: collapse;">
                                <tr>
                                    <th style="background-color: #f2f2f2; padding: 10px; border: 1px solid #dddddd; text-align: left;">Data</th>
                                    <td style="padding: 10px; border: 1px solid #dddddd;">${data}</td>
                                </tr>
                                <tr>
                                    <th style="background-color: #f2f2f2; padding: 10px; border: 1px solid #dddddd; text-align: left;">Hora</th>
                                    <td style="padding: 10px; border: 1px solid #dddddd;">${visitTime}</td>
                                </tr>
                                <tr>
                                    <th style="background-color: #f2f2f2; padding: 10px; border: 1px solid #dddddd; text-align: left;">Empresa</th>
                                    <td style="padding: 10px; border: 1px solid #dddddd;">${companyName}</td>
                                </tr>
                                <tr>
                                    <th style="background-color: #f2f2f2; padding: 10px; border: 1px solid #dddddd; text-align: left;">Visitante</th>
                                    <td style="padding: 10px; border: 1px solid #dddddd;">${visitorName}</td>
                                </tr>
                                <tr>
                                    <th style="background-color: #f2f2f2; padding: 10px; border: 1px solid #dddddd; text-align: left;">Responsável</th>
                                    <td style="padding: 10px; border: 1px solid #dddddd;">${responsibleMVK}</td>
                                </tr>
                                <tr>
                                    <th style="background-color: #f2f2f2; padding: 10px; border: 1px solid #dddddd; text-align: left;">Outros Visitantes</th>
                                    <td style="padding: 10px; border: 1px solid #dddddd;">${otherVisitors}</td>
                                </tr>
                                <tr>
                                    <th style="background-color: #f2f2f2; padding: 10px; border: 1px solid #dddddd; text-align: left;">Tipo de Visita</th>
                                    <td style="padding: 10px; border: 1px solid #dddddd;">${visitTypeText}</td>
                                </tr>
                                <tr>
                                    <th style="background-color: #f2f2f2; padding: 10px; border: 1px solid #dddddd; text-align: left;">Motivo</th>
                                    <td style="padding: 10px; border: 1px solid #dddddd;">${visitReason}</td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    <tr>
                        <td style="background-color: #d6cb22; color: white; padding: 20px; text-align: center; font-size: 12px;">
                            <p style="margin: 0;">Este é um e-mail automático, por favor, não responda.</p>
                            <p style="margin: 0;">© 2024 MVK - Todos os direitos reservados.</p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>


    `;


    try {
        // Envio do e-mail

        await enviarEmail(destinatario, assunto, htmlConteudo, visitTypeText);
        res.send({ success: true, message: 'Visita agendada e e-mail enviado!' });
    } catch (err) {
        res.status(500).send({ success: false, message: 'Erro ao enviar o e-mail.' });
    }
});




startServer();
