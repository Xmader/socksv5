
module.exports = {
    ...require("./lib/server"),
    ...require("./lib/client"),
    ...require("./lib/Agents"),
    auth: {
        None: require("./lib/auth/None"),
        UserPassword: require("./lib/auth/UserPassword"),
    }
}
