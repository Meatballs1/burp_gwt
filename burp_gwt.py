##
# js-beautifier BurpSuite Extension
# Ben Campbell <eat_meatballs[at]hotmail.co.uk>
# http://rewtdance.blogspot.co.uk
# http://github.com/Meatballs1/burp_jsbeautifier
#
# Place the jsbeautifier python folder in the burpsuite/lib/ folder.
# Load extension in the Extender tab.
#
# Tested in Burpsuite Pro v1.5.11 with js-beautify v1.3.2
# http://jsbeautifier.org/
##

from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IParameter
from burp import IBurpExtenderCallbacks
from javax import swing
from gwtparse import GWTParser

def getHeadersContaining(findValue, headers):
    if (findValue != None and headers != None and len(headers)>0):
        return [s for s in headers if findValue in s]
    return None

def parserRequestContent(helper, content):
    parser = None

    if content == None:
        return parser
    
    info = helper.analyzeRequest(content)

    gwt = helper.bytesToString(content[info.getBodyOffset():])
    
    if (gwt != None and len(gwt) > 0):
        parser = GWTParser.GWTParser()
        parser.burp = True
        try:
            parser.deserialize(gwt)
        except Exception as e:
            print "Parser failed! %s" % str(e)

    return parser

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    
    #
    # implement IBurpExtender
    #
    def	registerExtenderCallbacks(self, callbacks):
        print "GWT BurpSuite Extension"
        print "Ben Campbell <eat_meatballs[at]hotmail.co.uk>"
        print "http://rewtdance.blogspot.co.uk"
        print "http://github.com/Meatballs1/burp_jsbeautifier"
        
    
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("GWT")

        # register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(self)
        return
        
    # 
    # implement IMessageEditorTabFactory
    #
    def createNewInstance(self, controller, editable):
        # create a new instance of our custom editor tab
        return GWTTab(self, controller, editable)

    #
    # implement ITab
    #
    def getTabCaption(self):
        return "GWT"

        
# 
# class implementing IMessageEditorTab
#
class GWTTab(IMessageEditorTab):

    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._editable = editable
        self._parser = None
        
        # create an instance of Burp's text editor, to display the javascript
        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(editable)

        # Store httpHeaders incase request is modified
        self._httpHeaders = None
        return

    #
    # implement IMessageEditorTab
    #
    def getTabCaption(self):
        return "GWT"
        
    def getUiComponent(self):
        return self._txtInput.getComponent()
                
    def isEnabled(self, content, isRequest):
        # enable this tab only for responses containing gwt Content-Types
	if isRequest:
            request_info = self._extender._helpers.analyzeRequest(content)
            
            if request_info != None:
                headers = request_info.getHeaders()
                # Store HTTP Headers incase we edit the response.
                self._httpHeaders = headers
                if (headers != None and len(headers) > 0):
                    content_type_headers = getHeadersContaining('Content-Type', headers)
                    if (content_type_headers != None):
                        for content_type_header in content_type_headers:
                            if ('gwt' in content_type_header):
                                return True
        else:
            response_info = self._extender._helpers.analyzeResponse(content)
            
            if response_info != None:
                headers = response_info.getHeaders()
                # Store HTTP Headers incase we edit the response.
                self._httpHeaders = headers
                if (headers != None and len(headers) > 0):
                    content_type_headers = getHeadersContaining('Content-Type', headers)
                    if (content_type_headers != None):
                        for content_type_header in content_type_headers:
                            if ('json' in content_type_header):
                                return False # Handle JSON embedded gwt
							
        return False
    

        
    def setMessage(self, content, isRequest):
        if (content is None):
            # clear our display
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)
        
        else:
            gwt = parserRequestContent(self._extender._helpers, content)
            self._parser = gwt
            text = self._parser.display() + "\n\nFuzz String:\n" + self._parser.get_fuzzstr()
            self._txtInput.setText(text)
            self._txtInput.setEditable(self._editable)

        # remember the displayed content
        self._currentMessage = content
        return
    
    def getMessage(self):
        if (self._txtInput.isTextModified()):
            # reserialize the data
            text = self._txtInput.getText()
            
            # update the request with the new edited gwt
            return self._extender._helpers.buildHttpMessage(self._httpHeaders,text)
        else:
            return self._currentMessage
    
    def isModified(self):
        return self._txtInput.isTextModified()
    
    def getSelectedData(self):
        return self._txtInput.getSelectedText()
            
