import express from 'express';
import crypto from 'crypto';
import dotenv from 'dotenv';
import bodyParser from 'body-parser';
import zipcode from 'zipcode';
import request from "request";
import Twitter from 'twitter';
import qs from 'querystring';

dotenv.config();

// Watson Work Services URL
const watsonWork = "https://api.watsonwork.ibm.com";

// Application Id, obtained from registering the application at https://developer.watsonwork.ibm.com
const appId = process.env.TWITTER_CLIENT_ID;
// Application secret. Obtained from registration of application.
const appSecret = process.env.TWITTER_CLIENT_SECRET;
// Webhook secret. Obtained from registration of a webhook.
const webhookSecret = process.env.TWITTER_WEBHOOK_SECRET;
// Twitter App information
const consumerKey = process.env.TWITTER_CONSUMER_KEY;
const consumerSecret = process.env.TWITTER_CONSUMER_SECRET;
// Uri of the server
const ngrokUri = 'http://localhost:3000';//'https://92cefb03.ngrok.io'

const request_token_url = 'https://api.twitter.com/oauth/request_token';



// credentials for the user
let credentials = {};

// WWS User who is in making current request
// TODO this does not work in parallel
let wws_user;

// keyword to tweet
const webhookKeyword = "@tweet";

const failMessage =
`Hey, maybe it's me... maybe it's Twitter, but I sense the fail whale should be here... Try again later`;

const successMessage = (tweet) => (
  `Sucessfully tweeted: ${tweet}`
);

const app = express();

// Send 200 and empty body for requests that won't be processed.
const ignoreMessage = (res) => {
  res.status(200).end();
}

/** BEGIN WWS **/
// Process webhook verification requests
const verifyCallback = (req, res) => {
  console.log("Verifying challenge");

  const bodyToSend = {
    response: req.body.challenge
  };

  // Create a HMAC-SHA256 hash of the recieved body, using the webhook secret
  // as the key, to confirm webhook endpoint.
  const hashToSend =
    crypto.createHmac('sha256', webhookSecret)
    .update(JSON.stringify(bodyToSend))
    .digest('hex');

  res.set('X-OUTBOUND-TOKEN', hashToSend);
  res.send(bodyToSend).end();
};

// Validate events coming through and process only message-created or verification events.
const validateEvent = (req, res, next) => {

  // Event to Event Handler mapping
  const processEvent = {
    'verification': verifyCallback,
    'message-created': () => next()
  };

  // If event exists in processEvent, execute handler. If not, ignore message.

  return (processEvent[req.body.type]) ?
    processEvent[req.body.type](req, res) : ignoreMessage(res);
};

// Authenticate Application
const authenticateApp = (callback) => {

  // Authentication API
  const authenticationAPI = 'oauth/token';

  const authenticationOptions = {
    "method": "POST",
    "url": `${watsonWork}/${authenticationAPI}`,
    "auth": {
      "user": appId,
      "pass": appSecret
    },
    "form": {
      "grant_type": "client_credentials"
    }
  };

  request(authenticationOptions, (err, response, body) => {
    // If can't authenticate just return
    if (response.statusCode != 200) {
      console.log("Error authentication application. Exiting.");
      process.exit(1);
    }
    callback(JSON.parse(body).access_token);
  });
};

// Send message to Watson Workspace
const sendMessage = (spaceId, message) => {

  // Spaces API
  const spacesAPI = `v1/spaces/${spaceId}/messages`;

  // Photos API
  const photosAPI = `photos`;

  // Format for sending messages to Workspace
  const messageData = {
    type: "appMessage",
    version: 1.0,
    annotations: [
      {
        type: "generic",
        version: 1.0,
        color: "#1DA1F2",
        title: "Results from Twitter",
        text: message
      }
    ]
  };

  // Authenticate application and send message.
  authenticateApp( (jwt) => {

    const sendMessageOptions = {
      "method": "POST",
      "url": `${watsonWork}/${spacesAPI}`,
      "headers": {
        "Authorization": `Bearer ${jwt}`
      },
      "json": messageData
    };

    request(sendMessageOptions, (err, response, body) => {
      if(response.statusCode != 201) {
        console.log("Error posting twitter information.");
        console.log(response.statusCode);
        console.log(err);
      }
    });
  });
};

/** END WWS CODE **/

/** BEGIN TWITTER CODE **/

// Ensure we can parse JSON when listening to requests
app.use(bodyParser.json());

app.get('/', (req, res) => {
  res.send('IBM Watson Workspace app for Twitter is alive and happy!');
});

// auth endpoint
app.get('/auth/callback', (req, res) => {
  const auth_data = req.query;
  const user = auth_data.user;
  console.log(`callback auth data: ${JSON.stringify(auth_data,null,4)}`);
  const oauth = {
    consumer_key: consumerKey,
    consumer_secret: consumerSecret,
    token: auth_data.oauth_token,
    token_secret: credentials[user].req_token_secret,
    verifier: auth_data.oauth_verifier
  };
  const url = 'https://api.twitter.com/oauth/access_token';
  request.post({url:url, oauth:oauth}, (e, r, body) => {
    // ready to make signed requests on behalf of the user
    const perm_data = qs.parse(body);
    const oauth = {
      consumer_key: consumerKey,
      consumer_secret: consumerSecret,
      token: perm_data.oauth_token,
      token_secret: perm_data.oauth_token_secret
    };
    credentials[user] = oauth;
    // Verify that their information is accessible
    const url = 'https://api.twitter.com/1.1/users/show.json';
    const query = {
      screen_name: perm_data.screen_name,
      user_id: perm_data.user_id
    };
    console.log(perm_data);
    request.get({url:url, oauth:oauth, qs:query, json:true}, (e, r, user) => {
      console.log(user)
    })
  })
  res.end('You have successfully logged in. Please return to your app');
})

// This is callback URI that Watson Workspace will call when there's a new message created
app.post('/webhook', validateEvent, (req, res) => {

  wws_user = req.body.userId;
  console.log(`wws user: ${wws_user}`);

  if(req.type === 'message-annotation-added') {
    console.log('gotcha');
    return;
  }

  // Check if the first part of the message is '@twitter'.
  // This lets us "listen" for the '@twitter' keyword.
  if (!req.body.content || req.body.content.indexOf(webhookKeyword) != 0) {
    ignoreMessage(res);
    return;
  }

  // maybe listen for an action

  // Send status back to Watson Work to confirm receipt of message
  res.status(200).end();

  // Id of space where outbound event originated from.
  const spaceId = req.body.spaceId;

  // Parse twitter query from message body.
  // Expected format: <keyword> <twitter query>
  const twitterQuery = req.body.content.split(' ').slice(1).join(' ');
  console.log('Posting to Twitter \'' + twitterQuery + '\'');

  // if the user has not authed, do so
  if (!credentials[wws_user] || !credentials[wws_user].token) {
    credentials[wws_user] = {};
    const oauth = {
      consumer_key: consumerKey,
      consumer_secret: consumerSecret,
      callback: `${ngrokUri}/auth/callback?user=${wws_user}`
    };

    request.post({url:request_token_url, oauth:oauth}, (e, r, body) => {
      var req_data = qs.parse(body);
      var uri = 'https://api.twitter.com/oauth/authenticate' + '?' + qs.stringify({oauth_token: req_data.oauth_token});
      credentials[wws_user].req_token_secret = req_data.oauth_token_secret;
      sendMessage(spaceId, uri);
    });
  } else {
    // attempt to post the tweet
    const query = { status: twitterQuery};
    request.post({url: 'https://api.twitter.com/1.1/statuses/update.json', oauth: credentials[wws_user], qs: query }, (e,r,body) => {
      if (e) {
        console.log(e);
        return;
      }
      console.log(`posted? ${body}`);
      sendMessage(spaceId, successMessage(twitterQuery));
    });
    }
});

/** END TWITTER CODE **/

// Kickoff the main process to listen to incoming requests
app.listen(process.env.PORT || 3000, () => {
  console.log('Twitter app is listening on the port');
});
