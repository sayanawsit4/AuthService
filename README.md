# AuthService 2

This repo is an `prototype` on the implementation of Spring OAuth2 and currently dev in progress.

## Requirements

 `Java` installed,`Spring boot maven dependency` is configured.


## OAuth2 flows

**Flow of calls between gateway service and downstream service**

<img src="https://github.com/lnl/AuthService2/blob/master/doc/oauth2_microservice_flow.png" />

 **Flow of calls from external client**

<img src="https://github.com/lnl/AuthService2/blob/master/doc/external_client_flow.png" />

## Endpoints

`Gateway Service` -  8080
`Auth Service` - 7070
`Resource Server` - 9000

## Auth flows

### Authorization Code Flow

```
# get code
http://localhost:7070/authserver/oauth/authorize?response_type=code&client_id=authserver&redirect_uri=http://localhost:8080/&scope=myscope&state=Lq3pSG
# login if prompted
# exchange code with token
http://localhost:7070/authserver/oauth/token?grant_type=authorization_code&client_id=authserver&redirect_uri=http://localhost:8080/&scope=myscope&state=Lq3pSG&code=fTId6p
# call resource endpoint with token (bearer)
http://localhost:9000/user
```
### Implicit Flow (Client-Side Flow)
```
#call authorize endpoint
http://localhost:7070/authserver/oauth/authorize?response_type=token&client_id=authserver&redirect_uri=http://localhost:8080/&scope=myscope&state=Lq3pSG
# login if prompted
# get redirected back with the token
```
###  Client credentials
```
#call token endpoint directly with client id and secret
http://localhost:7070/authserver/oauth/token?grant_type=client_credentials
# token returned
```
###  Password Grant
```
#call token endpoint directly with client-id secret and username/pwd
http://localhost:7070/authserver/oauth/token?grant_type=password&username=admin&password=admin
#token returned
```

## Use cases

###  As an external client
Configure external client like below sample

```
spring.security.oauth2.client.registration.vibe.client-id=vibe
spring.security.oauth2.client.registration.vibe.client-secret=passwordforvibeserver
spring.security.oauth2.client.provider.vibe.authorizationUri=http://localhost:7070/authserver/oauth/authorize
spring.security.oauth2.client.provider.vibe.tokenUri=http://localhost:7070/authserver/oauth/token
spring.security.oauth2.client.provider.vibe.userInfoUri=http://localhost:9000/user
spring.security.oauth2.client.registration.vibe.authorizationGrantType=authorization_code
spring.security.oauth2.client.registration.vibe.authorizationGrantType.scope=myscope
spring.security.oauth2.client.registration.vibe.redirectUriTemplate=http://localhost:8081/login/oauth2/code/vibe
spring.security.oauth2.client.provider.vibe.usernameAttribute=name

```

###  As an internal client

update Gateway service and (other optional internal clients) with
```
security:
 oauth2: client: accessTokenUri: http://localhost:7070/authserver/oauth/token
      userAuthorizationUri: http://localhost:7070/authserver/oauth/authorize
      clientId: authserver
      clientSecret: passwordforauthserver
    resource:
 userInfoUri: http://localhost:9000/user
 ```

Try to access
`http://localhost:8080/personInfo` which internally calls the downstream resource server
`http://localhost:9000/person`
it will prompt for user authentication at `http://localhost:7070/authserver/login`
login with credentials defaults are admin:admin and user:user
should display resource information which is protected under `http://localhost:9000/person`

### Features

#### Feature covered
````
1.Implement Spring OAuth2 as is.
2.Implement extended features
3.Implemented User management.
4.Client management UI.
5.Backward compatibility in terms of payload,signature and token type.
(this one is important and guarantees the client adoption seamlessly)
Note: the backward compatibility is developed as "feature" which can be turned on-off from configs.
this includes 
      - Payload format. (verbose(Recommended) to Lean(As is in Auth1))
      - token format ( Jwt (Recommended) to Standard(As is in Auth1))
6.Process Audit
7.Access Audit
8.Captcha
9.Dictonary attack prevention
10.Scheduled spring batch for token cleanup
11.Log appender to AWS cloudwatach
12.Though Phase 1 deployment of AuthService is a standalone version.It has been tested to work as microservice with following functionality
      - with a Gateway Service (Reactive) (Potentially replaces lnlApp)
      - intercommunication between these services using Kuberentes fqdn namespace
      - token relay
      - microservices acting as resource server and as client to access its neighbor resources servers.
      - statefull and elastic
````
#### Feature yet to be covered

````
1.Dry run integration with lnlApp
2.MFA(google authenticator)
4.Junit test cases.
5.logout flow
6.Deployment Script
7.Code cleanup and optimization
8. Technical documentation
````
