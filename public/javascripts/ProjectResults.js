"use strict";

const sock = new WebSocket('ws://localhost:3000/ws');

const statusMsgContainer = document.getElementById('status-message');
const vulnContainer = document.getElementById('accordionVulns');


var sockConnectionOpened = false;
var projectInfoRetrieved = false;

var vulnCount = 0;

var project = {};
var projectid = window.location.pathname.replace('/projects/', '');
var vulns = {};

var severity = {
    HIGH: "#b82525",
    MEDIUM: "#e0824f",
    INFO: "#366fc4"
}

var resultIDS = {
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

var resultsMsg = [
    "Canary is relfected in <mark>script</mark> tag",
    "Canary is relfected in new HTML Tag",
    "Canary is attribute key",
    "Canary is inside attribute value without quotes",
    "Special character allowed in attribute value",
    "Canary is inside event handler",
    "Canary is reflected in URI",
    "Canary is reflected in URI path",
    "Canary is relfected in URI parameter",
    "Canary is inside single quote attribute",
    "Canary is inside double quote attribute"
]

window.addEventListener('load', getProjectInfo);

function sendGetResultCommand()
{
    if (sockConnectionOpened && projectInfoRetrieved)
    {
        var command = {"cmd": "getResult", "id": projectid}
        sock.send(JSON.stringify(command));
        alert("Scanning the target", "info");
    }
}
sock.addEventListener('open', function(event)
{
	console.log("connection is opened");
    sockConnectionOpened = true;
    sendGetResultCommand();
});

function displayVuln(param, vuln)
{   
    // vuln.allowedChars
    console.log(vuln);
    appendVulnerability(vuln.result, param, vuln.value, vuln.canary, vuln.request, vuln.response, vuln.allowedChars, vuln.attributeQuoteType);
}

sock.addEventListener('message', function(event)
{
	console.log('server has sent: ' + event.data);

	var data = JSON.parse(event.data);
    if (data.status === "finished")
        alert("Scanning the target is completed successfully!", "success");

    if ("vulns" in data)
    {
        for (let param in data.vulns)
        {
            if (param in vulns)
            {
                if (data.vulns[param].length !== vulns[param].length)
                {
                    // vulnerabilities found have been updated
                    for (let i=vulns[param].length; i<data.vulns[param].length; i++)
                    {
                        vulns[param].push(data.vulns[param][i]);
                        displayVuln(param, vulns[param][i]);
                    }                    
                } 
            } else 
            {   
                
                vulns[param] = data.vulns[param];
                for (let i=0; i<vulns[param].length; i++)
                {
                    displayVuln(param, vulns[param][i]);
                }
            }
        }
    }
    
});

sock.addEventListener('close', function(event)
{
	console.log('connection is closed');
});

sock.addEventListener('error', function(event)
{
	console.log('socket error: ' + event);
});

function getProjectInfo() {
    var xhttp = new XMLHttpRequest();
    xhttp.onload = function()
    {
        let status = xhttp.status;
        let response = xhttp.responseText

        if (status === 200 && response !== "401")
        {
            projectInfoRetrieved = true;
            let res = JSON.parse(response);
            project = res;
            var queryIndex = project.URI.indexOf("?");
			if (queryIndex != -1)
				project.URI = project.URI.substring(0, queryIndex);
            sendGetResultCommand();
        } else {
            console.log(response);
            alert("Error while getting project information", "danger");
        }
    }
    xhttp.open("GET", `/projects/${projectid}/info`, true);
    xhttp.send();
}

function alert (message, type) {
    const wrapper = document.createElement('div')
    wrapper.innerHTML = [
      `<div class="alert alert-${type} alert-dismissible" role="alert">`,
      `   <div>${message}</div>`,
      '   <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>',
      '</div>'
    ].join('')
  
    statusMsgContainer.append(wrapper)
}


function appendVulnerability(id, param, value, canary, paramsData, response, allowedChars, attributeQuoteType)
{
    vulnCount +=1;
    if (attributeQuoteType)
        attributeQuoteType = (attributeQuoteType === "DOUBLE") ? "\"": "'";
    var msg = resultsMsg[id];
    // #TODO:
    // high severity by default
    var vulnSeverity = severity.HIGH;
    if (id === resultIDS.CANARY_IN_URI_PATH || (id === resultIDS.SPECIAL_CHAR_ALLOWED_IN_ATTRIBUTE && !allowedChars.includes(attributeQuoteType)))
    {
        // medium severity
        vulnSeverity = severity.MEDIUM;
    } else if (id === resultIDS.INFO_CANARY_IN_DOUBLE_QUOTE_ATTRIBUTE || id=== resultIDS.INFO_CANARY_IN_SINGLE_QUOTE_ATTRIBUTE || id === resultIDS.INFO_CHECK_CANARY_REFLECTED_IN_URI)
    {
        // informational
        vulnSeverity = severity.INFO;
    }

    var accordionItem = document.createElement('div');
    accordionItem.className = "accordion-item";
    var itemcode = ""
    itemcode += `<h2 class="accordion-header" id="flush-heading${vulnCount}">`;
    itemcode += `<button class="accordion-button collapsed" style="color: white; background-color: ${vulnSeverity}" type="button" data-bs-toggle="collapse" data-bs-target="#flush-collapse${vulnCount}" aria-expanded="false" aria-controls="flush-collapse${vulnCount}">
                                    ${project.method}&nbsp;${project.URI}&nbsp;<code>${param}</code>&nbsp;#${vulnCount}
                                </button>`;
    itemcode += "</h2>";
    itemcode += `<div id="flush-collapse${vulnCount}" class="accordion-collapse collapse" aria-labelledby="flush-heading${vulnCount}" data-bs-parent="#accordionVulns">
                                    <div class="accordion-body">
                                        <h6>${msg}</h6>`;
    if (id === resultIDS.CANARY_REFLECTED_IN_SCRIPT && allowedChars && allowedChars.length !==0)
    {  
        itemcode += `                   <h6>Allowed Characters: ${allowedChars.join(' ')}</h6>`
    }
    itemcode+= `                        <h6>Canary: <mark>${canary}</mark></h7><br>
                                        <code>`;

    if (project.method === "GET")
    {
        itemcode += `${project.method} ${project.URI}?${paramsData} HTTP/1.1<br>`;
    } else 
    {
        itemcode += `${project.method} ${project.URI} HTTP/1.1<br>`;
    }

    for (let i=0; i<project.headers.length; i++)
    {
        itemcode += `            ${project.headers[i].name}: ${project.headers[i].value}<br>`;
    }
    if (project.headers.cookies && project.headers.cookies != "")
    {
        itemcode += `            Cookies: ${project.cookies}<br>`;
    }
    if (project.method !== "GET")
    {
        itemcode += `            <br>${paramsData}`;
    }
    var responseHTMLCode = document.createElement('code');
    responseHTMLCode.innerText = response;
    // highlight canaries
    var htmlcode = responseHTMLCode.innerHTML;
    htmlcode = htmlcode.replaceAll(canary, `<mark>${canary}</mark>`);
    itemcode += `        </code><br>
                                        <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#response${vulnCount}">
                                            Show Response
                                        </button>
                                        <div class="modal fade" id="response${vulnCount}" tabindex="-1" aria-labelledby="BackdropLabel" aria-hidden="true">
                                            <div class="modal-dialog modal-dialog-centered modal-dialog-scrollable">
                                                <div class="modal-content">
                                                <div class="modal-header">
                                                    <h1 class="modal-title fs-5" id="staticBackdropLabel">${param}=${value}</h1>
                                                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                                                </div>
                                                <div class="modal-body">
                                                    <code>
                                                        ${htmlcode}
                                                    </code>
                                                </div>
                                                <div class="modal-footer">
                                                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                                                </div>
                                                </div>
                                            </div>
                                        </div>
                                            
                                    </div>
                                    </div>`;
    accordionItem.innerHTML = itemcode;
    vulnContainer.appendChild(accordionItem);

}
