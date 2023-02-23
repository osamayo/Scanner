const { group } = require('console');
var https = require('https');
var axios = require('axios').default;
var HTMLParser = require('node-html-parser');
const { report } = require('process');
var DB = require('./database');

class Scanner {
	DEBUG = false
	CANARY_LEN = 6
	FIND_CANARIES_IN_SCRIPT_TAG = `(?:<script\\b[^>]*>)([\\s\\S]*?)(canary)([\\s\\S]*?)(?:<\\/script>)`
	FIND_CANARIES_IN_ATTRIBUTES = `(?:<\\w+\\s+[^>]*?)(canary)`
	FIND_CANARIES_IN_HTML_BODY = `(?:>\\s*?)([^<]*?canary)`
	FIND_CANARIES_IN_HYPER_LINKS = `(?:<\\w+\\s+[^>]*?)(?:href|src)\\s*=(\\s*[^ ]*?canary)`
	FIND_CANARIES_IN_EVENT_HANDLERS = `(?:<\\w+\\s+[^>]*?)(?:on\\w*?)\\s*=(\\s*[^ ]*?canary)`

	MATCH_CRITICAL_CANARIES_IN_URI = `^\\w*(?::\\/\\/|\\/|\\/\\/){0,1}[a-zA-Z0-9-\\.]*(canary)`

	// MATCH_CANARIES_IN_DOUBLEQUOTE_ATTRIBUTE = `(?:<\\w+\\s+(?:(?:\\s*\\w*\\s*=*?)|(?:\\w*\\s*=\\s*"[^"]*?")|(?:\\w*\\s*=\\s*'[^']*?'))*?\\s*(\\w*\\s*=\\s*"[^"]*?canary))`

	MATCH_CANARIES_IN_DOUBLEQUOTE_ATTRIBUTE = `(?:<\\w+\\s+(?:(?:(?:\\s|\\w|-|:)*=*?)|(?:"[^"]*")|(?:'[^']*')|(?:(?:\\s|\\w|-|:)*=\\s*"[^"]*?")|(?:(?:\\s|\\w|-|:)*=\\s*'[^']*?'))*?\\s*((?:\\s|\\w|-|:)*=\\s*"[^"]*?canary))`
	MATCH_CANARIES_IN_SINGLEQUOTE_ATTRIBUTE = `(?:<\\w+\\s+(?:(?:(?:\\s|\\w|-|:)*=*?)|(?:"[^"]*")|(?:'[^']*')|(?:(?:\\s|\\w|-|:)*=\\s*"[^"]*?")|(?:(?:\\s|\\w|-|:)*=\\s*'[^']*?'))*?\\s*((?:\\s|\\w|-|:)*=\\s*'[^']*?canary))`
	MATCH_CANARIES_WITHOUT_QUOTES_ATTRIBUTE = `(?:<\\w+\\s+(?:(?:(?:\\s|\\w|-|:)*=*?)|(?:"[^"]*")|(?:'[^']*')|(?:(?:\\s|\\w|-|:)*=\\s*"[^"]*?")|(?:(?:\\s|\\w|-|:)*=\\s*'[^']*?'))*?\\s*((?:\\s|\\w|-|:)*=\\s*[^(?:'|"|\\s|=)][^=]*canary))`
	MATCH_KEY_ATTRIBUTE_CANARIES = `(?:<\\w+\\s+(?:(?:(?:\\s|\\w|-|:)*=*?)|(?:"[^"]*")|(?:'[^']*')|(?:(?:\\s|\\w|-|:)*=\\s*"[^"]*?")|(?:(?:\\s|\\w|-|:)*=\\s*'[^']*?'))*?\\s*((\\w|\\s|:|-)*canary))`

	resultIDS = {
		CANARY_REFLECTED_IN_SCRIPT: 0,
		OPEN_CANARY_TAG: 1,
		CANARY_AS_ATTRIBUTE_KEY: 2,
		CANARY_IN_ATTRIBUTE_VALUE_WITHOUT_QUOTES: 3,
		SPECIAL_CHAR_ALLOWED_IN_ATTRIBUTE: 4,
		CANARY_IN_EVENT_HANDLER: 5,
		CANARY_IN_URI: 6,
		CANARY_IN_URI_PATH: 7,
		INFO_CHECK_CANARY_REFLECTED_IN_URI: 8,
		INFO_CANARY_IN_SINGLE_QUOTE_ATTRIBUTE: 9,
		INFO_CANARY_IN_DOUBLE_QUOTE_ATTRIBUTE: 10,
	}
	constructor(uri, method, postData, headers, cookies, notes)
	{

		this.uri = uri;
		if (method)
			this.method = method;
		else
			this.method = "GET";
		this.postData = postData;
		this.headers = headers;
		this.cookies= cookies;
		this.notes = notes;
		

		// results data structure
		this.scanResult = {} 
		/*
			{
				"param": [{"value": value, "request": request, "response": response, "result": resultID, "allowedChars": chars, "attributeQuoteType": quote_type  .....}]
			}

		*/
		this.projectId = this.getCanary(10);
		var project = {};
		project.URI = this.uri;
		project.method = this.method;
		project['post-data'] = this.postData;
		project.headers = this.headers;
		project.cookies = this.cookies;
		project.notes = this.notes;
		DB.projects[this.projectId] = project;

	}
	getProjectID()
	{
		return this.projectId;
	}
	setScanOptions (canary, followRedirect, terminateMsg, terminateStatus, terminateRedirect, timeout, ratelimit, proxy)
	{
		this.canary = canary;
		this.followRedirect = followRedirect;
		this.terminateMsg = terminateMsg;
		this.terminateStatus = terminateStatus;
		this.terminateRedirect = terminateRedirect;
		this.timeout = timeout;
		this.ratelimit= ratelimit;
		this.proxy = proxy;

		

		// init axios instance
		var instanceConfig = {"headers": {}}
		if (this.headers)
		{
			for (let i=0; i<this.headers.length; i++)
			{
				if (this.headers[i].name === "Content-Length")
					continue
				instanceConfig.headers[this.headers[i].name] = this.headers[i].value;
			}
		}
		
		if (this.cookies)
		{
			instanceConfig.headers['Cookie'] = this.cookies;
		}

		if (this.proxy && this.proxy.trim() !== "")
		{
			var url = new URL(this.proxy);
			var host = url.hostname;
			var port = url.port;
			if (port === "")
				port = 80;	

			instanceConfig.proxy = {host: host, port: port};
			
		}
		const httpsAgent = new https.Agent({
			rejectUnauthorized: false,
		})
		instanceConfig.httpsAgent = httpsAgent
		this.axiosInstance = axios.create(instanceConfig);

	}

	setReportingOptions (reportFirstN, reporting, reportForms)
	{
		this.reportFirstN = reportFirstN;
		this.reporting = reporting;
		this.reportForms = reportForms;
	}

	storeResults(param, value, canary, request, response, result, allowedChars, attributeQuoteType)
	{
		if (!(param in this.scanResult))
		{
			this.scanResult[param] = [];
		} 
		var res = {};
		res.value = value;
		res.canary = canary;
		res.request = request;
		res.response = response;
		res.result = result;
		if (allowedChars)
			res.allowedChars = allowedChars; 
		if (attributeQuoteType)
			res.attributeQuoteType = attributeQuoteType;
		this.scanResult[param].push(res);

		// send results ** Live Reporting **
		if (DB.UsersMap.has(this.projectId))
		{
			var dataToSend = {"status": "running", "vulns": this.scanResult};
			DB.UsersMap.get(this.projectId).send(JSON.stringify(dataToSend));
		}
		// this.printLog("*************************");
		// this.printLog(this.scanResult);
		// this.printLog("*************************");

	}
	

	async startScan()
	{
		// iterate for parameters
		var params;
		if (this.method && this.method.toUpperCase() === "POST")
		{
			params = this.parseParams(this.postData);
		} else {
			var queryIndex = this.uri.indexOf("?");
			if (queryIndex != -1)
			{
				let paramData = this.uri.substring(queryIndex);
				this.uri = this.uri.substring(0, queryIndex);
				if (paramData !== "?")
				{
					paramData = paramData.substring(1);
					params = this.parseParams(paramData);
				}
			}
		}
		
		// for every paramter check the destination of the canary
		// for every destination check the bad characters
		// # it could be param=value or param
		this.printLog(params);
		var canary = this.getCanary(this.CANARY_LEN);
		if (this.canary && this.canary.trim() !== "")
		{
			canary = this.canary;
		}
		for (let i=0; i<params.length; i++) {
			var p = params[i];
			var param, value;
			if (p.indexOf("=") != -1 && (p.substring(p.indexOf("=")) != "=" || p.substring(p.indexOf("=")) != "=="))
			{
				// param=value
			 	param = p.substring(0, p.indexOf("="));
				value = p.substring(p.indexOf("=") + 1);
				param = decodeURIComponent(param);
				value = decodeURIComponent(value);
			} else 
			{
				// param
				param = decodeURIComponent(p);
				value = ""; // scan the value also if not specified
			}

			await this.scanSpecificPoint(params, i, canary, false, param, value);
			await this.scanSpecificPoint(params, i, canary, true, param, value);

		}
		DB.vulns[this.projectId] = this.scanResult;
		// report results
		var dataToSend = {"status": "finished", "vulns": this.scanResult};
		if (DB.UsersMap.get(this.projectId))
			DB.UsersMap.get(this.projectId).send(JSON.stringify(dataToSend));
		
	}

	printLog(msg)
	{
		if (this.DEBUG)
		{
			console.log(msg)
		}	
	}

	async scanSpecificPoint(params, index, canary, scanValue, param, value) 
	{
		// check where the input is reflected in the response
		/*
			- inside <script> "to report"
			- inside html body "check if possible to insert <>"
			- inside normal attribute "check if possible to escape"
			- inside href|src|eventhandler "to report" 
		*/
		var paramsData;
		if (scanValue)
			paramsData = this.reconstructParams(params, index, param, value+canary);
		else
			paramsData = this.reconstructParams(params, index, param+canary);

		var mainParamsData = paramsData;
		var response;
		var res;
		try {
			if (this.method.toUpperCase() === "POST")
			{
				response = await this.axiosInstance.post(this.uri, paramsData);
			} else {
				response = await this.axiosInstance.get(this.uri + "?" + paramsData);
			}
			res = response.data;

		} catch(e)
		{
			res = ""
		}
		
		var mainResponse = res;
		var regex = new RegExp(canary, 'igm');

		var Canaryfound  = res.match(regex);
		
		if (!Canaryfound)
		{
			// Canary not found
			return;
		}
		// - inside <script> "to report"
		this.printLog("[-] inside <script> to report")
		var foundCanaryInScript = this.matchCanaryInScript(mainResponse, canary);
		if (foundCanaryInScript)
		{
			this.printLog(res);
			this.printLog(`[+] ${this.method} ${this.uri} ${paramsData} | canary is reflected in <script>`);
			this.printLog("________________________________________________________________");
			// check allowed characters inside script tag
			var chars = ["\"", "'", ";"];
			let allowedChars = [];
			for (let c of chars) {
				let {allowed, paramsInj, output} = await this.scanAllowedCharsInScriptTag(c, params, index, canary, scanValue, param, value);
				if (allowed)
				{
					allowedChars.push(c);
					this.printLog(output);
					this.printLog(`[+] ${this.method} ${this.uri} ${paramsInj} | canary with \`${c}\` is reflected in <script>`);
					this.printLog("________________________________________________________________");
				}
			}
			this.storeResults(param, value, canary, paramsData, res, this.resultIDS.CANARY_REFLECTED_IN_SCRIPT, allowedChars);
		}



		// - inside html body "check if possible to insert <>"
		this.printLog("[-] inside html body, check if possible to insert <>");

		if (scanValue)
			paramsData = this.reconstructParams(params, index, param, value+canary+"<");
		else
			paramsData = this.reconstructParams(params, index, param+canary+"<");

		var response;
		var res;
		try {
			if (this.method.toUpperCase() === "POST")
			{
				response = await this.axiosInstance.post(this.uri, paramsData);
			} else {
				response = await this.axiosInstance.get(this.uri + "?" + paramsData);
			}
			res = response.data;
	
		} catch (e)
		{
			res = ""
		}
		regex = new RegExp(this.FIND_CANARIES_IN_HTML_BODY.replace("canary", canary + "<"), "igm");
		var charAllowed = res.match(regex);

		if (charAllowed)
		{
			this.printLog(res);
			this.printLog(`[+] ${this.method} ${this.uri} ${paramsData} | character "<" is allowed`);
			let testTag = canary;
			let {allowed, paramsInj, output} = await this.scanAllowedHTMLTags(testTag, params, index, canary, scanValue, param, value);
			if (allowed)
			{
				this.printLog(output);
				this.printLog(`[+] ${this.method} ${this.uri} ${paramsInj} | character "<${testTag}" is allowed`);
				this.printLog("________________________________________________________________");
				this.storeResults(param, value, canary, paramsData, output, this.resultIDS.OPEN_CANARY_TAG, ["<"+testTag]);
			} else
			{
				this.storeResults(param, value, canary, paramsData, output, this.resultIDS.OPEN_CANARY_TAG);
			}
		}

		// - inside normal attribute "check if possible to escape"
		this.printLog("[-] inside normal attribute && check if possible to escape");
		var doubleQuoteAttr = false;
		var singleQuoteAttr = false;

		regex = new RegExp(this.FIND_CANARIES_IN_ATTRIBUTES.replace("canary", canary), "igm");
		var fullStringMatch = true;
		var m;
		while ((m = regex.exec(mainResponse)) !== null) {
			if (m.index === regex.lastIndex) {
				regex.lastIndex++;
			}
			m.forEach((match, groupIndex) => {
				if (fullStringMatch)
				{
					this.printLog(mainResponse);
					// this.printLog(`Found match, group ${groupIndex}: ${match}`);
	
					// check if there are canaries as key attributes
					var regex2 = new RegExp(this.MATCH_KEY_ATTRIBUTE_CANARIES.replace("canary", canary), "igm");
					if (match.match(regex2))
					{
						this.printLog(`[+] ${this.method} ${this.uri} ${mainParamsData} | Found canary as attribute key`);
						this.printLog("________________________________________________________________");
						this.storeResults(param, value, canary, mainParamsData, mainResponse, this.resultIDS.CANARY_AS_ATTRIBUTE_KEY);
					}

					regex2 = new RegExp(this.MATCH_CANARIES_WITHOUT_QUOTES_ATTRIBUTE.replace("canary", canary), "igm");
					if (match.match(regex2))
					{
						this.printLog(`[+] ${this.method} ${this.uri} ${mainParamsData} | Found canary in attribute value without quotes!`);
						this.printLog("________________________________________________________________");
						this.storeResults(param, value, canary, mainParamsData, mainResponse, this.resultIDS.CANARY_IN_ATTRIBUTE_VALUE_WITHOUT_QUOTES);
					}

					regex2 = new RegExp(this.MATCH_CANARIES_IN_SINGLEQUOTE_ATTRIBUTE.replace("canary", canary), "igm");
					if (match.match(regex2))
					{
						this.printLog(`[*] ${this.method} ${this.uri} ${mainParamsData} | Found canary in single quote attribute!`);
						this.printLog("________________________________________________________________");
						singleQuoteAttr = true;
						this.storeResults(param, value, canary, mainParamsData, mainResponse, this.resultIDS.INFO_CANARY_IN_SINGLE_QUOTE_ATTRIBUTE);
					}
					regex2 = new RegExp(this.MATCH_CANARIES_IN_DOUBLEQUOTE_ATTRIBUTE.replace("canary", canary), "igm");
					if (match.match(regex2))
					{
						this.printLog(`[*] ${this.method} ${this.uri} ${mainParamsData} | Found canary in double quote attribute!`);
						this.printLog("________________________________________________________________");
						doubleQuoteAttr = true;
						this.storeResults(param, value, canary, mainParamsData, mainResponse, this.resultIDS.INFO_CANARY_IN_DOUBLE_QUOTE_ATTRIBUTE);

					}

					fullStringMatch = false;
				} else
					fullStringMatch = true;
			});
		}
		// scan for allowed characters in the attribute
		var scanChars = ["\"", "'"];
		let allowedChars = [];
		for (let c of scanChars)
		{
			let {allowed, paramsInj, output} = await this.scanAllowedCharsInAttributes(c, params, index, canary, scanValue, param, value);
			if (allowed)
			{
				this.printLog(output);
				this.printLog(`[+] ${this.method} ${this.uri} ${paramsInj} | character \`${c}\` is allowed`);
				this.printLog("________________________________________________________________");
				this.storeResults(param, value, canary, paramsInj, output, this.resultIDS.SPECIAL_CHAR_ALLOWED_IN_ATTRIBUTE, [c], (singleQuoteAttr)? "SINGLE": "DOUBLE");	
			}
		}
		// - inside href|src|eventhandler "to report" 
		this.printLog("[-] inside href|src|eventhandler to report");
		regex = new RegExp(this.FIND_CANARIES_IN_EVENT_HANDLERS.replace("canary", canary), "igm");
		if (mainResponse.match(regex))
		{
			this.printLog(mainResponse);
			this.printLog(`[+] ${this.method} ${this.uri} ${mainParamsData} | canary is reflected in event handler`);
			this.printLog("________________________________________________________________");
			this.storeResults(param, value, canary, mainParamsData, mainResponse, this.resultIDS.CANARY_IN_EVENT_HANDLER);
		}
		regex = new RegExp(this.FIND_CANARIES_IN_HYPER_LINKS.replace("canary", canary), "igm");

		m=null;
		let capturingGroup = false;

		while ((m = regex.exec(mainResponse)) !== null) {
			if (m.index === regex.lastIndex) {
				regex.lastIndex++;
			}
			
			m.forEach((match, groupIndex) => {
				if (!capturingGroup)
					capturingGroup = true;
				else {
					// this.printLog(`Found match, group ${groupIndex}: ${match}`);
					this.printLog(mainResponse);

					let link = match.replace(/^('|")/, '');
					if (mainResponse.match(new RegExp(this.MATCH_CRITICAL_CANARIES_IN_URI.replace("canary", canary), "igm")))
					{
						this.printLog(`[+] ${this.method} ${this.uri} ${mainParamsData} | canary is reflected in URI`);
						this.printLog("________________________________________________________________");
						this.storeResults(param, value, canary, mainParamsData, mainResponse, this.resultIDS.CANARY_IN_URI);
					} else {
						let url = new URL(link);
						if (url.pathname.includes(canary))
						{
							this.printLog(`[+] ${this.method} ${this.uri} ${mainParamsData} | canary is reflected in URI path`);
							this.printLog("________________________________________________________________");	
							this.storeResults(param, value, canary, mainParamsData, mainResponse, this.resultIDS.CANARY_IN_URI_PATH);

						} else {
							this.printLog(`[*] ${this.method} ${this.uri} ${mainParamsData} | check if the canary reflected in URI is exploitable! `);
							this.printLog("________________________________________________________________");	
							this.storeResults(param, value, canary, mainParamsData, mainResponse, this.resultIDS.INFO_CHECK_CANARY_REFLECTED_IN_URI);
						}
					} 
					
				}
			});
		}
	}

	async scanAllowedCharsInScriptTag(character, params, index, canary, scanValue, param, value)
	{
		var paramsInj;
		if (scanValue)
			paramsInj = this.reconstructParams(params, index, param, value+canary+character+canary);
		else
			paramsInj = this.reconstructParams(params, index, param+canary+character+canary);

		var response;
		var output;
		try
		{
			if (this.method.toUpperCase() === "POST")
			{
				response = await this.axiosInstance.post(this.uri, paramsInj);
			} else {
				response = await this.axiosInstance.get(this.uri + "?" + paramsInj);
			}
			output = response.data;
	
		} catch (e)
		{
			output = "";
		}
		var regex = new RegExp(this.FIND_CANARIES_IN_SCRIPT_TAG.replace("canary", canary + character+canary), "igm");
		var m = null;
		var allowed = false;
		while ((m = regex.exec(output)) !== null) {
			if (m.index === regex.lastIndex) {
				regex.lastIndex++;
			}
			m.forEach((match, groupIndex) => {
				allowed= true;				
			});
		}
		return {allowed, paramsInj, output}

	}

	async scanAllowedCharsInAttributes(char, params, index, canary, scanValue, param, value)
	{
		var paramsInj, output, regex;
		if (scanValue)
			paramsInj = this.reconstructParams(params, index, param, value+canary+char+canary);
		else
			paramsInj = this.reconstructParams(params, index, param+canary+char+canary);
		var response;
		var output;
		try
		{
			if (this.method.toUpperCase() === "POST")
			{
				response = await this.axiosInstance.post(this.uri, paramsInj);
			} else {
				response = await this.axiosInstance.get(this.uri + "?" + paramsInj);
			}
			output = response.data;
	
		} catch(e)
		{
			output = "";
		}
		regex = new RegExp(this.FIND_CANARIES_IN_ATTRIBUTES.replace("canary", canary+char+canary), "igm");
		var m;
		var allowed = false;
		while ((m = regex.exec(output)) !== null) {
			if (m.index === regex.lastIndex) {
				regex.lastIndex++;
			}
			m.forEach((match, groupIndex) => {
				allowed= true;	
			});
		}

		

		return {allowed, paramsInj, output}



	}

	async scanAllowedHTMLTags(tag, params, index, canary, scanValue, param, value)
	{
		var paramsInj;
		if (scanValue)
			paramsInj = this.reconstructParams(params, index, param, value+canary+"<" + tag);
		else
			paramsInj = this.reconstructParams(params, index, param+canary+"<" + tag);

		var response;
		var output;
		try
		{
			if (this.method.toUpperCase() === "POST")
			{
				response = await this.axiosInstance.post(this.uri, paramsInj);
			} else {
				response = await this.axiosInstance.get(this.uri + "?" + paramsInj);
			}
			output = response.data;
	
		} catch (e)
		{
			output = "";
		}
		var regex = new RegExp(this.FIND_CANARIES_IN_HTML_BODY.replace("canary", canary + "<"+ tag), "igm");
		var m = null;
		var allowed = false;
		while ((m = regex.exec(output)) !== null) {
			if (m.index === regex.lastIndex) {
				regex.lastIndex++;
			}
			m.forEach((match, groupIndex) => {
				allowed= true;				
			});
		}
		return {allowed, paramsInj, output}
	}

	matchCanaryInScript(htmlcode, canary)
	{
		var root = HTMLParser.parse(htmlcode);
		var found = false;
		root.querySelectorAll('script').forEach((script) => {
			if (script.innerText.includes(canary)) 
				found = true;
		});
		return found;
	}

	matchRegex(text, regexStr, canary)
	{
		var regex = new RegExp(regexStr.replace("canary", canary), "igm");
		let m;
		// this.printLog(text);
		// this.printLog(regex);
		var result = false;
		while ((m = regex.exec(text)) !== null) {
			// This is necessary to avoid infinite loops with zero-width matches
			if (m.index === regex.lastIndex) {
				regex.lastIndex++;
			}
			
			// The result can be accessed through the `m`-variable.
			m.forEach((match, groupIndex) => {
				this.printLog(`Found match, group ${groupIndex}: ${match}`);
				result = true;
			});
			return result;
		}
	}
	sendErrorMessage(response, msg)
	{
		let out = {"status": false, "msg": msg};
		response.send(out);
	}
	parseParams(paramsData)
	{
		let params = []
		paramsData = paramsData.replace(/\+/g, "%20");
		params = paramsData.split("&")
		return params;
	}

	reconstructParams(params, index, param, value)
	{
		let paramsData = "";
		for (let i=0; i<params.length; i++)
		{
			if (i == index) {
				paramsData += encodeURIComponent(param);
				if (value)
					paramsData += "=" + encodeURIComponent(value);
			} else {
				paramsData += params[i];
			}
			if (i+1 != params.length)
				paramsData+="&"

		}
		this.printLog("reconstruct params: " + paramsData);
		return paramsData;
	}

	getCanary(length) {
		var result           = '';
		var characters       = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
		var charactersLength = characters.length;
		for ( var i = 0; i < length; i++ ) {
			result += characters.charAt(Math.floor(Math.random() * charactersLength));
		}
		return result;
	}

}

module.exports = Scanner;