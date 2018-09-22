// =======================
// get the packages we need ============
// =======================
var express     = require('express');
var bodyParser  = require('body-parser');
var morgan      = require('morgan');
var jwt         = require('jsonwebtoken'); // used to create, sign, and verify tokens
var loki        = require('lokijs');
var axios        = require('axios');

var config      = require('./config'); // get our config file
var app         = express();


// =======================
// in-memory db =========
// =======================
var db = new loki('db.json');
var userRecords = [
    { name: 'Thor', password: 'password', admin: 'true'}, 
    { name: 'Loki', password: 'password', admin: 'false'}
];
var users = db.addCollection('users');
var results = users.insert(userRecords);


// =======================
// configuration =========
// =======================
var port = process.env.PORT || 3000; // used to create, sign, and verify tokens
var path = __dirname + '/views/';
app.use(express.static('assets'));
app.set('superSecret', config.secret); // secret variable

// use body parser so we can get info from POST and/or URL parameters
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// use morgan to log requests to the console
app.use(morgan('dev'));

// =======================
// routes ================
// =======================
// basic route
app.get('/', function(req, res) {
    // res.send(`Hello! The API is at http://localhost:${port}/api`);
    res.sendFile(path + "index.html");
});

app.get('/sign-in', function(req, res) {
    res.sendFile(path + "sign-in.html");
});

app.post('/sign-in', function(req, res) {
    let baseURL = 'http://localhost:' + port;
    axios.post(baseURL + '/api/authenticate', req.body)
        .then(function (response) {
            console.log(response.data);
            jwt.verify(response.data.token, app.get('superSecret'), function(err, decoded) {      
                if (err) {
                  return res.json({ success: false, message: 'Failed to authenticate token.' });    
                } else {
                  // if everything is good, save to request for use in other routes
                  req.decoded = decoded;
                  res.redirect('/api/admin-dashboard?token='+response.data.token);
                }
            });
        })
        .catch(function (error) {
            console.log(`ERROR occured during sign-in >>>`);
            console.log(error);
            res.json(error);
        });  
});

app.get('/setup', function(req, res) {
    // create sample users
    var results = users.insert(userRecords);
    if (results) {
      console.log('User saved successfully ' + results);
      res.json({ success: true });
    } else {
        throw new Error("cannot insert into db");
    }
});

app.get('/setup/users', function(req, res) {
    var results = users.find({});
    res.json(results);
});

// API ROUTES -------------------
// we'll get to these in a second
// get an instance of the router for api routes
var apiRoutes = express.Router(); 

// route to authenticate a user (POST http://localhost:3000/api/authenticate)
apiRoutes.post('/authenticate', function(req, res) {
    let user = users.findOne({ name: req.body.name });
    if (!user) {
        res.json({ success: false, message: 'Authentication failed. User not found.'});
    } else if (user) {
        if (user.password != req.body.password) {
            res.json({success: false, message: 'Authentication failed. Wrong password.'});
        } else {
            const payload = {
                admin: user.admin
            };
            var token = jwt.sign(payload, app.get('superSecret'), {
                expiresIn: "2h" // 24 hours
            });
            res.json({
                success: true,
                message: 'Enjoy your token!',
                token: token
            });
        }
    }
});

// route middleware to verify a token
apiRoutes.use(function(req, res, next) {

    // check header or url parameters or post parameters for token
    var token = req.body.token || req.query.token || req.headers['x-access-token'];
  
    // decode token
    if (token) {
  
      // verifies secret and checks exp
      jwt.verify(token, app.get('superSecret'), function(err, decoded) {      
        if (err) {
          return res.json({ success: false, message: 'Failed to authenticate token.' });    
        } else {
          // if everything is good, save to request for use in other routes
          console.log(decoded);
          req.decoded = decoded;    
          next();
        }
      });
  
    } else {
  
      // if there is no token
      // return an error
      return res.status(403).send({ 
          success: false, 
          message: 'No token provided.' 
      });
  
    }
  });

apiRoutes.get('/admin-dashboard', function(req, res) {
    res.sendFile(path + "dashboard.html");
});

apiRoutes.get('/orders', function(req, res) {
    res.sendFile(path + "orders.html");

});

// route to show a random message (GET http://localhost:3000/api/)
apiRoutes.get('/', function(req, res) {
  res.json({ message: 'Welcome to NDI Workshop!' });
});

// route to return all users (GET http://localhost:3000/api/users)
apiRoutes.get('/users', function(req, res) {
    res.json(users.find({}));
});   

// apply the routes to our application with the prefix /api
app.use('/api', apiRoutes);

app.use("*",function(req,res){
    res.sendFile(path + "404.html");
});

// =======================
// start the server ======
// =======================
app.listen(port);
console.log(`service running at http://localhost:${port}`);
