"use strict";

const headersContainer = document.getElementById('headers-container');
var HeadersObject = function () {
	this.objects = {};
	this.add = function(key) 
	{
		this.objects[key] = "1";
	}
	this.remove = function(key)
	{
		delete this.objects[key];
	}
	this.getNextAvailable = function ()
	{
		let i=1;
		for (; i<=Object.keys(this.objects).length; i++)
		{
			if (!this.objects[`${i}`])
			{
				break;
			}
		}
		return `${i}`;
	}
}

// keep tracking of empty cells
var headers = new HeadersObject();
headers.add("1");
headers.add("2");

document.getElementById('remove-header-1').addEventListener('click', (e)=> {
	document.getElementById('header-1').value = "";
	document.getElementById('header-value-1').value = "";
});

document.getElementById('add-header-1').addEventListener('click', addNewHeader);
document.getElementById('add-header-2').addEventListener('click', addNewHeader);


document.getElementById('remove-header-2').addEventListener('click', removeHeader);

function removeHeader(e) {
	let headerNum = e.target.id.split('-')[2];
	let child = document.getElementById(`header-container-${headerNum}`);
	headersContainer.removeChild(child);
	headers.remove(headerNum);
}

function addNewHeader(e) {
	let headerNum = headers.getNextAvailable();
	// header containser
	let child = document.createElement('div');
	child.id = `header-container-${headerNum}`;
	child.classList.value = 'input-group mb-3';
	// span header
	let span = document.createElement('span');
	span.classList.add('input-group-text');
	span.innerText = 'Header';
	child.appendChild(span);
	// header input
	let headerinput = document.createElement('input');
	headerinput.id = `header-${headerNum}`;
	headerinput.type = "text";
	headerinput.classList.add('form-control');
	headerinput.placeholder = "<Content-Type>";
	child.appendChild(headerinput);
	// span value
	let spanvalue = document.createElement('span');
	spanvalue.classList.add('input-group-text');
	spanvalue.innerText = 'Value';
	child.appendChild(spanvalue);
	// value input
	let valueinput = document.createElement('input');
	valueinput.id= `header-value-${headerNum}`;
	valueinput.type = "text";
	valueinput.classList.add('form-control');
	valueinput.placeholder = "<application/x-www-form-urlencoded>";
	child.appendChild(valueinput);
	// remove button
	let removebtn = document.createElement('button');
	removebtn.id = `remove-header-${headerNum}`;
	removebtn.type = "button";
	removebtn.classList.value = 'btn btn-outline-danger';
	removebtn.innerHTML='<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-node-minus-fill" viewBox="0 0 16 16">\n    <path fill-rule="evenodd" d="M16 8a5 5 0 0 1-9.975.5H4A1.5 1.5 0 0 1 2.5 10h-1A1.5 1.5 0 0 1 0 8.5v-1A1.5 1.5 0 0 1 1.5 6h1A1.5 1.5 0 0 1 4 7.5h2.025A5 5 0 0 1 16 8zm-2 0a.5.5 0 0 0-.5-.5h-5a.5.5 0 0 0 0 1h5A.5.5 0 0 0 14 8z"/>\n  </svg>\n    Remove';
	child.appendChild(removebtn);
	// add button
	let addbtn = document.createElement('button');
	addbtn.id = `add-header-${headerNum}`;
	addbtn.type = "button";
	addbtn.classList.value = 'btn btn-outline-primary';
	addbtn.innerHTML= '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-node-plus-fill" viewBox="0 0 16 16">\n      <path d="M11 13a5 5 0 1 0-4.975-5.5H4A1.5 1.5 0 0 0 2.5 6h-1A1.5 1.5 0 0 0 0 7.5v1A1.5 1.5 0 0 0 1.5 10h1A1.5 1.5 0 0 0 4 8.5h2.025A5 5 0 0 0 11 13zm.5-7.5v2h2a.5.5 0 0 1 0 1h-2v2a.5.5 0 0 1-1 0v-2h-2a.5.5 0 0 1 0-1h2v-2a.5.5 0 0 1 1 0z"></path>\n    </svg>\n    Add';
	child.appendChild(addbtn);
	// button listeners
	addbtn.addEventListener('click', addNewHeader);
	removebtn.addEventListener('click', removeHeader);

	headersContainer.appendChild(child);
	headers.add(headerNum);
}



// Scanning info
var Target = function()
{
	this.target = {"URI": null, "method": "GET", "post-data": null, "headers": null, "cookies": null, "notes": null};
	this.options = {"canary": null, "follow-redirect": false, "terminate-msg": null, "terminate-status-code": null, "terminate-redirect": null, "timeout": 10, "ratelimit": 10, "proxy": null};
	this.report = {"report-first-requests": 2, "reporting": "live", "report-forms": false};


	this.submit = function (callback)
	{
		var xhttp = new XMLHttpRequest();
		xhttp.onload = function()
		{
			let status = xhttp.status;
			let response = xhttp.responseText

			if (status === 200)
			{
				let res = JSON.parse(response);
				window.open(`/projects/${res.id}`, '');
			} else {
				console.log(response);
			}
		}

		xhttp.open("POST", "/scanner", true);
		xhttp.setRequestHeader("Content-Type", "application/json");
		let data = this.constructData();
		callback(data);
		xhttp.send(data);

	}

	this.constructData = function()
	{
		let data = {"target": this.target, "options": this.options, "report": this.report};
		return JSON.stringify(data);
	}


}



// set scanning input
document.getElementById('start-attack').addEventListener('click', (e) =>
{
	// get headers
	var headersList = document.getElementById('headers-container').getElementsByTagName('div');

	var headerObjectsList = [];
	for (let i=0; i<headersList.length; i++)
	{
		let inputs = headersList[i].getElementsByTagName('input');
		let header = {};
		let headerName = inputs[0].value;
		let headerValue = inputs[1].value;
		if (headerName.trim() === "" || headerValue.trim() === "")
		{
			continue;
		}
		header.name = headerName;
		header.value = headerValue;
		headerObjectsList.push(header);
	}
	var info = new Target();
	info.target.URI = document.getElementById('target-url').value;
	info.target.method = document.getElementById('target-method').selectedOptions[0].value;
	let postData = document.getElementById('target-post-data').value.trim()
	info.target['post-data'] = (postData === "") ? null : postData;
	info.target.headers = (headerObjectsList.length === 0)? null : headerObjectsList;
	let cookies = document.getElementById('target-cookies').value.trim();
	info.target.cookies = cookies === "" ? null : cookies;
	let notes = document.getElementById('target-notes').value.trim();
	info.target.notes = notes === "" ? null : notes;

	// target options
	let canary = document.getElementById('canary').value.trim();
	info.options.canary = canary === "" ? null : canary;
	let followRedirect = document.getElementById('follow-redirect').selectedOptions[0].value;
	info.options["follow-redirect"] = followRedirect === "true" ? true : false;
	let terminateMsg = document.getElementById('terminate-msg').value.trim();
	info.options['terminate-msg'] = terminateMsg === "" ? null : terminateMsg;
	let terminateStatus = document.getElementById('terminate-status-code').value.trim();
	info.options['terminate-status-code'] = terminateStatus === "" ? null : terminateStatus;
	let terminateRedirect = document.getElementById('terminate-redirect').value.trim();
	info.options['terminate-redirect'] = terminateRedirect === "" ? null : terminateRedirect;

	let timeout = document.getElementById('timeout').value.trim();
	info.options.timeout = timeout === "" ? 10 : parseInt(timeout);

	let ratelimit = document.getElementById('ratelimit').value.trim();
	info.options.ratelimit = ratelimit === "" ? 10 : parseInt(ratelimit);

	let proxy = document.getElementById('proxy').value.trim();
	info.options.proxy = proxy === "" ? null : proxy;

	// reporting options
	let reportFirstN = document.getElementById('report-first-n').value.trim();
	info.report['report-first-requests'] = reportFirstN == "" ? 2 : parseInt(reportFirstN);
	let reporting = document.getElementById('reporting').selectedOptions[0].value;
	info.report['reporting'] = reporting;
	let reportForms = document.getElementById('report-forms').selectedOptions[0].value;
	info.report['report-forms'] = reportForms === "true" ? true : false;


	info.submit((d)=>{
		console.log(d);
	});
});
