require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const passport = require('passport');
const SamlStrategy = require('passport-saml').Strategy;
const { Issuer, Strategy, generators } = require('openid-client');
const fs = require('fs');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;
const certPath = path.join(__dirname, 'lab.crt');
const samlCert = fs.readFileSync(certPath, 'utf-8');

let oidcClient;

// Passport session setup
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// Configuração do EJS e middlewares
app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());

// Estratégia SAML
passport.use(new SamlStrategy({
  path: '/saml/consume',
  entryPoint: process.env.SAML_ENTRY_POINT,
  issuer: 'http://localhost:3000',
  callbackUrl: 'http://localhost:3000/saml/consume',
  logoutUrl: 'http://localhost:3000/logout',
  cert: samlCert
}, (profile, done) => done(null, profile)));

// Endpoint para iniciar o login SAML
app.get('/login-saml', passport.authenticate('saml', {
  successRedirect: '/success',
  failureRedirect: '/login',
  failureFlash: true
}));

app.post('/saml/consume', passport.authenticate('saml', {
  failureRedirect: '/login',
  failureFlash: true
}), function (req, res) {
  req.session.authMethod = 'SAML';
  res.redirect('/success');
});

// Rotas
app.get('/', (req, res) => res.redirect('/login'));
app.get('/login', (req, res) => res.render('login'));
app.post('/login-oidc', (req, res) => { /* ... */ });

// Descoberta do Issuer OIDC e inicialização do cliente
Issuer.discover(process.env.OIDC_DISCOVERY_URL)
  .then(issuer => {
    oidcClient = new issuer.Client({
      client_id: process.env.OIDC_CLIENT_ID,
      client_secret: process.env.OIDC_CLIENT_SECRET,
      redirect_uris: [process.env.OIDC_REDIRECT_URI],
      response_types: ['code'],
      // Adicione mais configurações conforme necessário
    });

    // Configurar a estratégia OIDC depois de definir o cliente OIDC
    passport.use('oidc', new Strategy({
      client: oidcClient,
      params: { scope: 'openid email profile' }
    }, (tokenset, userinfo, done) => {
      // Aqui você processa o tokenset e userinfo
      done(null, userinfo);
    }));

    // Agora que a estratégia está configurada, definir as rotas que usam a estratégia
    // Rota para iniciar a autenticação OIDC
    app.get('/auth/oidc', (req, res) => {
      const code_verifier = generators.codeVerifier();
      req.session.code_verifier = code_verifier;
      const code_challenge = generators.codeChallenge(code_verifier);

      const authorizationUrl = oidcClient.authorizationUrl({
        scope: 'openid email profile',
        code_challenge,
        code_challenge_method: 'S256'
      });

      res.redirect(authorizationUrl);
    });

    // Rota para lidar com o callback do OIDC
    app.get('/oidc/callback', passport.authenticate('oidc', {
      successRedirect: '/success',
      failureRedirect: '/login'
    }));

    // Rota para iniciar a autenticação OIDC com GET
    app.get('/login-oidc', (req, res) => {
      const code_verifier = generators.codeVerifier();
      req.session.code_verifier = code_verifier;
      const code_challenge = generators.codeChallenge(code_verifier);

      const authorizationUrl = oidcClient.authorizationUrl({
        scope: 'openid email profile',
        code_challenge,
        code_challenge_method: 'S256'
      });

      res.redirect(authorizationUrl);
    });


    // Inicialização do servidor deve estar aqui também
    app.listen(port, () => {
      console.log(`Aplicação ouvindo em http://localhost:${port}`);
    });

  })
  .catch(err => {
    console.error('Erro ao descobrir o OIDC Issuer:', err);
  });

app.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/');
});

app.get('/success', (req, res) => {
  if (req.isAuthenticated()) {
    const authMethod = req.session.authMethod || 'desconhecido';
    res.render('success', { authMethod: authMethod });
  } else {
    res.redirect('/login');
  }
});


