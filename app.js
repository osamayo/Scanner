var createError = require('http-errors');
var express = require('express');
var http = require('http');
var url = require('url');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var session = require('express-session');

require('dotenv').config()

var indexRouter = require('./routes/index');
var scannerRouter = require('./routes/scanner');
var docRouter = require('./routes/doc');
var projectsRouter = require('./routes/projects');
var wsRouter = require('./routes/websocket');

var app = express();


// session config
const sessionCookieLifeTime =  1 * 60 * 60 * 1000; // 1 hour
var cookieOptions = {
  path: '/',
  httpOnly: true,
  secure: false,
  maxAge: sessionCookieLifeTime
};

var sessionParser = session({
  key: 'sid',
  secret: process.env.SecretSessionKey,
  resave: true,
  saveUninitialized: true,
  cookie: cookieOptions
});
app.use(sessionParser);

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/css', express.static(path.join(__dirname, 'node_modules/bootstrap/dist/css')))
app.use('/js', express.static(path.join(__dirname, 'node_modules/bootstrap/dist/js')))
app.use('/js', express.static(path.join(__dirname, 'node_modules/jquery/dist')))


app.use('/', indexRouter);
app.use('/scanner', scannerRouter);
app.use('/doc', docRouter);
app.use('/projects', projectsRouter);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

var server = http.createServer(app);
// websocket upgrade request
server.on('upgrade', function(request, socket, head)
{
  console.log('Parsing session from request...');
  sessionParser(request, {}, () => {
    if (!request.session)
    {
      console.log("not valid session");
      console.log(request.session);
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }
    console.log('Session is parsed!');
    if (url.parse(request.url).pathname !== "/ws")
    {
      console.log('Invalid URI: ' + request.url);
      socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
      socket.destroy();
      return;
    }

    wsRouter.handleUpgrade(request, socket, head, function(ws) 
    {
      wsRouter.emit('connection', ws, request);
    });
  });  
});

console.log("listening on localhost:3000");

server.listen(3000);

module.exports = server;
