const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const passport = require('passport');
const SamlStrategy = require('passport-saml').Strategy;
const fs = require('fs');
const path = require('path');
const { Issuer, generators } = require('openid-client');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000; 
const certPath = path.join(__dirname, 'lab.crt');
const samlCert = fs.readFileSync(certPath, 'utf-8');

// Passport session setup.
passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((obj, done) => {
  done(null, obj);
});

// Configuração do EJS
app.set('view engine', 'ejs');

// Serve arquivos estáticos da pasta 'public'
app.use(express.static('public'));

// Configuração do body-parser
app.use(bodyParser.urlencoded({ extended: true }));

// Configuração de sessão
app.use(session({
  secret: 'N3oS3nh@2024', 
  resave: false,
  saveUninitialized: true
}));

// Inicialização do Passport
app.use(passport.initialize());
app.use(passport.session());

// Estratégia SAML
passport.use(new SamlStrategy({
  path: '/saml/consume',
  entryPoint: 'https://idp.eu.safenetid.com/auth/realms/WAPKCZAVLU-STA/protocol/saml',
  issuer: 'http://localhost:3000',
  callbackUrl: 'http://localhost:3000/saml/consume',
  logoutUrl: 'http://localhost:3000/logout',
  cert: samlCert
  // Outras configurações conforme necessário
}, (profile, done) => {
  // Aqui você processaria o perfil do usuário e chamaria done com os dados do usuário
  // Exemplo:
  // User.findOrCreate({ samlId: profile.nameID }, function (err, user) {
  //   return done(err, user);
  // });
  return done(null, profile);
}));

// Rotas
app.get('/', (req, res) => res.redirect('/login'));
app.get('/login', (req, res) => res.render('login'));
app.post('/login-oidc', (req, res) => { /* ... */ });

// Endpoint para iniciar o login SAML
app.get('/login-saml', passport.authenticate('saml', {
  successRedirect: '/success',
  failureRedirect: '/login',
  failureFlash: true
}));

// Endpoint para processar a resposta SAML
app.post('/saml/consume', passport.authenticate('saml', {
  failureRedirect: '/login',
  failureFlash: true
}), function(req, res) {
  req.session.authMethod = 'SAML';
  res.redirect('/success');
});

// Supondo que você tenha um callback para OIDC assim
app.post('/auth/oidc/callback', passport.authenticate('oidc', {
  failureRedirect: '/login',
  failureFlash: true
}), function(req, res) {
  req.session.authMethod = 'OIDC';
  res.redirect('/success');
});

app.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/');
});

// Rota para a página de login bem-sucedido
app.get('/success', (req, res) => {
  if (req.isAuthenticated()) {
    const authMethod = req.session.authMethod || 'desconhecido';
    res.render('success', { authMethod: authMethod });
  } else {
    res.redirect('/login');
  }
});

// Ouvir na porta configurada
app.listen(port, () => {
  console.log(`Aplicação ouvindo em http://localhost:${port}`);
});
