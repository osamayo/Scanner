var express = require('express');
var router = express.Router();
var DB = require('../classes/database');

router.get("/all", function(req, res, next) {
    if (req.session.projects && req.session.projects.length !==0 )
    {
        res.render('projects_list', { title: process.env.SiteName, message: "All available projects", projects: req.session.projects})
    } else 
    {
        res.render('projects_list', { title: process.env.SiteName, message: "There is no available projects right now!", projects: []})
    }
});

router.get('/:projectID/info', function(req, res, next) {
    if (req.params.projectID && req.session.projects.includes(req.params.projectID) && req.params.projectID in DB.projects)
    { 
        res.send(DB.projects[req.params.projectID]);
    } else{
        res.send('401');
    }
});

router.get('/:projectID', function(req, res, next) {
    console.log(req.session.projects);
    if (req.params.projectID && req.session.projects && req.session.projects.includes(req.params.projectID) && req.params.projectID in DB.projects)
    {
        var id = req.params.projectID;
        res.render('projects', { title: process.env.SiteName, id: id, method: DB.projects[id].method, uri: DB.projects[id].URI, postData: DB.projects[id].postData, headers: DB.projects[id].headers, cookies: DB.projects[id].cookies, notes: DB.projects[id].notes });
    } else 
    {
        res.redirect("/")
        // res.render('projects', { title: process.env.SiteName, id: "dsjfskldfj", method: "GET", uri: "http://example.com", notes: "project notes", headers: [{"name": "header-x", "value": "value-x"}, {"name": "useragent", "value": "custom"}], cookies: "session=ajkdjfklsdjfasddfjsdklfj;", postData: null }, );
    }

});

module.exports = router;
