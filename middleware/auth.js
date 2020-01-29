const jwt = require("jsonwebtoken");
const config = require("config");

module.exports = function(req, res, next){
    //get the token from header
    const token = req.header("x-auth-token");
    // check if not token
    if(!token){
        return res.status(401).json({msg: "No token, authorization denied"});
    }

    //verify token
    try{
        const decoded = jwt.verify(token, config.get("jwtSecret"));
        //we attached user to the payload so we can set it to req after its decoded
        req.user = decoded.user;
        next();
    } catch(err){
        res.status(401).json({msg: "token is invalid"});
    }
}