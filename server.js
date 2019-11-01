require('dotenv').config();
var express = require('express');
var request = require('request');
var validation = require('./ActionableMessageTokenValidator');

var jwtIdentityAccessTokenMap = {};

var app = express();

app.get('/auth/redirect', (req, res) => {
    const formData = {
        code: req.query.code,
        client_id: process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET,
        redirect_uri: process.env.REDIRECT_URI,
        grant_type: 'authorization_code'
    };
    request.post({url: 'https://login.microsoftonline.com/common/oauth2/token', formData: formData}, (error, response, body) => {
        var JSONresponse = JSON.parse(body);
        var identity = req.query.state;
        jwtIdentityAccessTokenMap[identity] = JSONresponse.access_token;
        res.redirect(`https://outlook.office.com/connectors/${identity}/b88751bf-6433-4c73-ae58-f9c4a0c6cd25/postAuthenticate`);
    });
});

app.post('/action', (req, res) => {
    var token;
    
    if (req.headers && req.headers.hasOwnProperty('authorization')) {
        var auth = req.headers['authorization'].trim().split(' ');
        if (auth.length == 2 && auth[0].toLowerCase() == 'bearer') {
            token = auth[1];
        }
    }
    
    if (token) {
        var validator = new validation.ActionableMessageTokenValidator();
        
        // validateToken will verify the following
        // 1. The token is issued by Microsoft and its digital signature is valid.
        // 2. The token has not expired.
        // 3. The audience claim matches the service domain URL.
        //
        // Replace https://api.contoso.com with your service domain URL.
        // For example, if the service URL is https://api.xyz.com/finance/expense?id=1234,
        // then replace https://api.contoso.com with https://api.xyz.com
        validator.validateToken(
            token, 
            process.env.APP_DOMAIN,
            function (err, result) {
                if (err) {
                    console.error('error: ' + err.message);
                    res.status(401);
                    res.end();
                } else {
                    // We have a valid token. We will verify the sender and the action performer. 
                    // You should replace the code below with your own validation logic.
                    // In this example, we verify that the email is sent by expense@contoso.com
                    // and the action performer is someone with a @contoso.com email address.
                    //
                    // You should also return the CARD-ACTION-STATUS header in the response.
                    // The value of the header will be displayed to the user.
                    
                    var accessToken = jwtIdentityAccessTokenMap[result.action_performer];
                    
                    if (!accessToken || accessToken === "") {
                        res.status(401).set("ACTION-AUTHENTICATE", "https://login.microsoftonline.com/common/oauth2/authorize?"+
                                "client_id="+process.env.CLIENT_ID+
                                "&response_type=code"+
                                "&redirect_uri="+encodeURI(process.env.REDIRECT_URI)+
                                "&response_mode=query"+
                                "&resource=https%3A%2F%2Fgraph.microsoft.com%2F"+
                                "&state="+result.action_performer).end();
                
                        return;
                    }
                
                    request.get('https://graph.microsoft.com/beta/me', {
                            'auth': {
                                'bearer': accessToken
                            }
                        },
                        (error, response, body) => {
                            if (error) {
                                res.status(200).header("CARD-ACTION-STATUS", "Please try again").end();
                                return;
                            }
                            JSONresponse = JSON.parse(body);
                            res.status(200).header("CARD-UPDATE-IN-BODY", true).send(JSON.stringify(
                                {
                                    "type": "AdaptiveCard",
                                    "hideOriginalBody": true,
                                    "version": "1.0",
                                    "body": [
                                        {
                                            "type": "FactSet",
                                            "facts": [
                                                {
                                                    "title": "Name",
                                                    "value": JSONresponse.displayName
                                                },
                                                {
                                                    "title": "Company",
                                                    "value": JSONresponse.companyName
                                                }
                                            ]
                                        }
                                    ]
                                }
                            )).end()
                        }
                    );
                
                    // Delete the access token to demo the flow again.
                    jwtIdentityAccessTokenMap[result.action_performer] = null;
                }
            });
    } else {
        res.status(401);
        res.end();
    }
});

var port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Identity Linking app listening on port ${port}!`))