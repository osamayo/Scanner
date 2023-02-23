from burp import IBurpExtender
from burp import IContextMenuFactory

from burp.api.montoya.utilities import ByteUtils

from javax.swing import JMenuItem
from java.util import List, ArrayList
from java.net import URL

import json
import urllib2


class BurpExtender(IBurpExtender, IContextMenuFactory):
    
    scannerURI = "http://localhost:3000"    

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.context = None

        callbacks.setExtensionName("XSS Scanner")
        callbacks.registerContextMenuFactory(self)

        self.target = {}
        self.options = {}
        self.report = {}

        # get a session cookie from the server
        req = urllib2.Request(self.scannerURI + "/scanner")
        response = urllib2.urlopen(req)
        self.cookie = response.headers.get('Set-Cookie').split(';')[0]
        print("[+] Session Cookie " + self.cookie.split("=")[0] + ": " + self.cookie.split("=")[1])
        print("[+] Projects URI: " + self.scannerURI + "/projects/all")

        return
    def createMenuItems(self, context_menu):
        self.context = context_menu
        menu_list = ArrayList()
        menu_list.add(JMenuItem("Send to Scanner", actionPerformed=self.scan))
        return menu_list

    def scan(self, event):
        http_reqs = self.context.getSelectedMessages()
        for http in http_reqs:
            req = http.getHttpService()
            print("host: " + req.getHost())

            self.parseHTTPRequest(req, http.getRequest())

            requestBody = {"target": self.target, "options": self.options, "report": self.report}
            body = json.dumps(requestBody)
            req = urllib2.Request(self.scannerURI + "/scanner", data=body)
            req.add_header('Cookie', self.cookie)
            req.add_header('Content-Type', "application/json")
            response = urllib2.urlopen(req)
            try:
                id = json.loads(response.read())["id"]
                print("[+] Project created: " + self.scannerURI + "/projects/" + id)
            except:
                print("Error Recieved!")
                print(response.text())

        return



    def parseHTTPRequest(self, httpService, bytesArrayReq):
        requestInfo = self._helpers.analyzeRequest(httpService, bytesArrayReq)

        self.notes = requestInfo.getUrl().getHost()
        self.target["URI"] = requestInfo.getUrl().toString()
        self.target["method"] = requestInfo.getMethod()
        if requestInfo.getMethod() != "GET":
            postData = ""
            parameters = requestInfo.getParameters()
            getParams = requestInfo.getUrl().toString().split('?', 1)
            countOfGETParams = 0

            if len(getParams) > 1:
                getParams = getParams[1].split("&")
                countOfGETParams = len(getParams)


            for i in range (countOfGETParams, len(parameters), 1):
                # get only post parameters
                parameter = parameters[i]
                postData += parameter.getName() +"="+parameter.getValue() 
                if i != len(parameters) - 1:
                    postData += "&"
            
            self.target["post-data"] = postData

        self.target["headers"] = []
        headers = requestInfo.getHeaders()
        for i in range(1, len(headers), 1):
            header = headers[i]
            h = header.split(":", 1)

            if h[0] == "Cookie":
                self.target["cookies"] = h[1]
                continue
            hObj = {"name": h[0], "value": h[1]}
            self.target["headers"].append(hObj)
        
        self.options = {"canary":None,"follow-redirect":False,"terminate-msg":None,"terminate-status-code":None,"terminate-redirect":None,"timeout":10,"ratelimit":10,"proxy":"http://127.0.0.1:8080/"}
        self.report = {"report-first-requests":2,"reporting":"live","report-forms":False}



        return
            
        