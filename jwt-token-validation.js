const jwt =require("jsonwebtoken");

async function validateToken(req, res, next) {
  const auhorizationHeader = req.headers.authorization;
  let result;

  if (!auhorizationHeader) {
    return res.status(401).json({
      error: true,
      message: "Access token is missing",
    });
  }

  const token = req.headers.authorization.split(" ")[1];

  const options = {
    expiresIn: "24h",
  };

  try {

    result = jwt.verify(token, process.env.JWT_SECRET, options);

    if (!result) {
      result = {
        error: true,
        message: "Invalid token",
      };

      return res.status(401).json(result);
    }

    req.decoded = result;
    console.log('decoded', result);

    next();
  } catch (error) {
    console.error(error);

    if (error.name === "TokenExpiredError") {
      return res.status(403).json({
        error: true,
        message: "Token expired",
      });
    }

    return res.status(403).json({
      error: true,
      message: "Authentication error",
    });
  }
}

module.exports = validateToken;
