var express = require('express');
var router = express.Router();
var Scanner = require('../classes/Scanner');

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('scanner', { title: process.env.SiteName });
});

router.post('/', function(req, res, next)
{
  let data = req.body;
  try 
  {

    let target = data.target;
    let options = data.options;
    let report = data.report;

    let scanner = new Scanner(target.URI, target.method, target["post-data"], target.headers, target.cookies, target.notes);
    scanner.setScanOptions(options.canary, options['follow-redirect'], options['terminate-msg'], options['terminate-status-code'], options['terminate-redirect'], options.timeout, options.ratelimit, options.proxy);
    scanner.setReportingOptions(report['report-first-requests'], report.reporting, report['report-forms']);

    scanner.startScan();
    let result = {};
    result.id = scanner.getProjectID();
    // save project id in session
    if (!req.session.projects)
    {
      req.session.projects = [];
    }
    req.session.projects.push(result.id);
    res.send(result);

  } catch (e) {
    console.log(e);
    res.send('false');
  }
});

module.exports = router;
