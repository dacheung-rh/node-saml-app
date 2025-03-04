var https = require('https');
var express = require('express');
var session = require('express-session');
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var passport = require('passport');
var saml = require('@node-saml/passport-saml');
var fs = require('fs');
const config = require('config');

//declare constantss
const PORT = config.get('app.port') || 3000;

/** SAML Configurations attributes
 * callbackurl : apps url for IDP to response post authetication
 * signout: apps url for IDP to notify app post signout
 * entrypoint: IDP url to redirect for authentication
 * entityId : Apps Id
 */
const samlConfig = {
    issuer: config.get('saml.issuer'),
    entityId: config.get('saml.entityId'),
    callbackUrl: config.get('saml.callbackUrl'),
    logoutCallbackUrl: config.get('saml.logoutCallbackUrl'),
    entryPoint: config.get('saml.entryPoint')
};

// For running apps on https mode
// load the public certificate
const sp_pub_cert = fs.readFileSync('sp-pub-cert.pem', 'utf8');

//load the private key
const sp_pvk_key = fs.readFileSync('sp-pvt-key.pem', 'utf8');

//Idp's certificate from metadata
const idp_cert = fs.readFileSync('idp-pub-key.pem', 'utf8');

passport.serializeUser(function (user, done) {
    //Serialize user, console.log if needed
    done(null, user);
});

passport.deserializeUser(function (user, done) {
    //Deserialize user, console.log if needed
    done(null, user);
});

// configure SAML strategy for SSO
const samlStrategy = new saml.Strategy({
    callbackUrl: samlConfig.callbackUrl,
    entryPoint: samlConfig.entryPoint,
    logoutCallbackUrl: samlConfig.logoutCallbackUrl,
    issuer: samlConfig.issuer,
    identifierFormat: null,
    decryptionPvk: sp_pvk_key,
    idpCert: idp_cert,
    // idpCert: [idp_cert1,idp_cert2],
    privateKey: fs.readFileSync('sp-pvt-key.pem', 'utf8'),
    publicCert: sp_pub_cert,
    signatureAlgorithm: 'sha256',
    validateInResponseTo: 'ifPresent',
    disableRequestedAuthnContext: true,
    WantAssertionsSigned: true,
    wantAuthnResponseSigned: true,
}, function (profile, done) {
    console.log('passport.use() profile: %s \n', JSON.stringify(profile));
    return done(null, profile);
});

//initialize the express middleware
const app = express();
app.use(cookieParser());

app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())

//configure session management
// Note: Always configure session before passport initialization & passport session, else error will be encounter
app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: true,
}));

passport.use('samlStrategy', samlStrategy);
app.use(passport.initialize({}));
app.use(passport.session({}));

/** Configure routes **/
// default route
app.get('/',
    function (req, res) {
        res.send('Weclome to Single Sign-On Application');
    }
);

//login route
app.get('/login',
    passport.authenticate("samlStrategy", { failureRedirect: "/", failureFlash: true }),
    function (req, res) {
      res.redirect("/");
    },    
);

//post login callback route
app.post('/login/callback',
    bodyParser.urlencoded({ extended: false }),
    passport.authenticate("samlStrategy", {
      failureRedirect: "/",
      failureFlash: true,
    }),
    function (req, res) {
    //   res.redirect("/");
      res.send(req.user.attributes);
    },    
);

//Run the https server
const server = https.createServer({
    'key': sp_pvk_key,
    'cert': sp_pub_cert
}, app).listen(PORT, () => {
    console.log('Listening on port %d', server.address().port)
});


//Run the http server
// app.listen(PORT, () => {
//     console.log(`Listening on port ${PORT}.`);
// });