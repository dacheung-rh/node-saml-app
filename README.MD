# Keycloak nodejs saml client

### Part 1 - Keycloak ###
#### Generate Self-Sign SSL certificate to run keycloak container
```
openssl req -newkey rsa:2048 -nodes  -keyout idp-server.key.pem -x509 -days 3650 -out idp-server.crt.pem         
```

```
chmod 755 idp-server.key.pem
```

#### Run Keycloak in docker
```
docker run -name keycloak \
  -e KEYCLOAK_ADMIN=admin\
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  -e KC_HTTPS_CERTIFICATE_FILE=/opt/keycloak/conf/idp-server.crt.pem \
  -e KC_HTTPS_CERTIFICATE_KEY_FILE=/opt/keycloak/conf/idp-server.key.pem \
  -v $PWD/idp-server.crt.pem:/opt/keycloak/conf/idp-server.crt.pem \
  -v $PWD/idp-server.key.pem:/opt/keycloak/conf/idp-server.key.pem \
  -p 8443:8443 -d quay.io/keycloak/keycloak:26.1 start-dev
```

#### Access the Keycloak in UI
```
https://localhost:8443
```

### Part 2 - Keycloak Nodejs SAML 2.0 client ###

## Usage
Clone the source code over https
```
git clone https://github.com/dacheung-rh/node-saml-app.git
```

```
cd node-saml-app      
```

#### Generate Self-Sign SSL certificate to run the nodejs app in HTTPS mode
```
openssl req -newkey rsa:2048 -nodes  -keyout sp-pvt-key.pem -x509 -days 3650 -out sp-pub-cert.pem        
```

#### Configurations

Navigate to App.js and update the configures as per IDP provider you're using
```
/** SAML Configurations attributes 
* callbackurl : apps url for IDP to response post authentication 
* signout: apps url for IDP to notify app post sign out 
* entrypoint: IDP url to redirect for authentication 
* entityId : Apps Id 
*/ 
const samlConfig = {
  issuer: "Client-ID", 
  entityId: "realm name/entity name", 
  callbackUrl: "https://{IP-Address}:{PORT}/login/callback", 
  signOut: "https://{IP-Address}:{PORT}/signout/callback", 
  entryPoint: "{saml 2.0 login Url}",
  idpCert: 'MIICizCCAfQCCQCY8tKaMc0BMjANBgkqh ... W==', // x509 cert must be provided 
};
```

## The idpCert can object from the SAML xml descriptor
```
https://{KEYCLOAK-IP-Address}:{PORT}/realms/{IDP_REALM}/protocol/saml/descriptor
```

e.g.
```
<ds:X509Certificate>MIICqzCCAZMCBgGVT/dvizANBgkqhkiG9w0BAQsFADAZMRcwFQYDVQQDDA5 ... W==</ds:X509Certificate>
```

```
cat "MIICqzCCAZMCBgGVT/dvizANBgkqhkiG9w0BAQsFADAZMRcwFQYDVQQDDA5 ... W==" > idp-pub-key.pem
```


#### Run app in container
Build Docker Image
```
docker build -t nodesamlapp:v1.0 dir
```

Run in Container
```
docker run --name nodesamlapp -p 8080:3000 -d nodesamlapp:v1.0
```

Run locally Non-Container
```
//install dependency module
npm install 

//ensure it app root directory
node app.js
```

- Go the browser and navigate to home page : http://localhost:8080/
- Navigate to login page: http://localhost:8080/login app will redirect to IDP for login process and post login it will redirect to call back url with SAML assertion token with claims container user details
