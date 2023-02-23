
function DB()
{
    this.vulns = {};
    this.projects = {};
    this.UsersMap = new Map();

}

var database = new DB();

module.exports = database;
