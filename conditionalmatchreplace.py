from burp import IBurpExtender, IProxyListener, IHttpListener, IHttpService
from java.io import PrintWriter

class BurpExtender(IBurpExtender, IProxyListener, IHttpListener, IHttpService):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("Conditional Match&Replace")

        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        callbacks.registerProxyListener(self)

        return
        
    def processProxyMessage(self, messageIsRequest, message):
        
        if not messageIsRequest:
            httpRequestResponse = message.getMessageInfo()

            # get the request and check first header
            req = httpRequestResponse.getRequest()
            reqInfo = self._helpers.analyzeRequest(req)
            reqHeaders = reqInfo.getHeaders()

            respB = httpRequestResponse.getResponse()
            respS = self._helpers.bytesToString(respB)

            if 'GET /xsrf' in reqHeaders[0]:
                replS = respS.replace('HTTP/1.1 402 Payment Required', 'HTTP/1.1 204 No Content')
                newB = self._helpers.stringToBytes(replS)
                httpRequestResponse.setResponse(newB)

            elif 'POST /tokens.json' in reqHeaders[0]:
                replS = respS.replace('HTTP/1.1 402 Payment Required', 'HTTP/1.1 200 OK')
                newB = self._helpers.stringToBytes(replS)
                httpRequestResponse.setResponse(newB)

        return
