const express  = require("express");
const bodyParser = require("body-parser");
require('./database/mongoose');


const app = express();

app.use(bodyParser.json());

app.use(bodyParser.urlencoded({ 
    extended: false
  }));


  
app.use('/api', require('./routes/api'));
app.use("/public", express.static(__dirname + '/public'));
app.use('/api/auth', require('./routes/auth'));


app.use(function(err, req, res, next){
res.status(422).send({error: err.message});
});


app.listen(3000);
