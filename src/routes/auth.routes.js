const router = require("express").Router();
const rateLimit = require("../middleware/rateLimit.middleware");
const authController = require("../controllers/auth.controller");

router.post("/register", rateLimit, authController.register);
router.post("/login", rateLimit, authController.login);

module.exports = router;
