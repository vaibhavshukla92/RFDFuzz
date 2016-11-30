from IronWASP import *
import re


#Extend the ActivePlugin base class
class RFDPlugin(ActivePlugin):


  #Implement the GetInstance method of ActivePlugin class. This method is used to create new instances of this plugin.
  def GetInstance(self):
    p = RFDPlugin()
    p.Name = 'RFDPlugin'
    p.Description = 'scans for RFD vulnerabilities'
    p.Version = '0.1'
    p.payloads = []
    #Update this instance with the payloads read from the payloads file
    p.payloads.extend(self.payloads)
    return p


  #Implement the Check method of ActivePlugin class. This is the method called by the Scanner and the entry point in to the plugin.
  def Check(self, scnr):
    self.scnr = scnr # 'scnr' is the Scanner object calling this plugin
    #Print out a message to the Scan trace indicating the start of the check. Check the comments at the bottom to know more about the Trace feature and the formattng inside Scan trace messages.
    self.scnr.Trace("<i<br>><i<h>>Checking for RFDPlugin:<i</h>><i<br>><i<br>>")
    #Request trace adds information about the request to the Trace. The log id of the Request is automatically added.
    self.scnr.RequestTrace("Sending request without payloads to get normal response - ")
    #This methods sends the original request without any payloads. If any Session Plugin is selected with this scan job then that Session Plugin is used to update the original request before sending.
    res = self.scnr.Inject()
    #Response trace adds information about the response to the Trace in the same line as the previous RequestTrace message. This and RequestTrace must be called together.
    self.scnr.ResponseTrace(" ==> Normal Code - " + str(res.Code) + " | Normal Length - " + str(res.BodyLength))
    self.scnr.Trace("<i<br>><i<b>>Starting injection of payloads<i</b>><i<br>>")
    for payload in self.payloads:
      #Since the payloads are stored in url encoded form they are decoded before being used.
      payload = Tools.UrlDecode(payload)
      #The original value of the currently tested parameter is added before the payload. self.scnr.PreInjectionParameterValue gives this value.
      payload = self.scnr.PreInjectionParameterValue + payload
      #Tools.EncodeForTrace converts the input in to a form that is friendly towards being added to the Scan Trace
      self.scnr.RequestTrace("Injected - " + Tools.EncodeForTrace(payload))
      #The payload is injected in the parameter currently being tested and the response is returned. If a Session Plugin was used along with this Scan Job it would have been called now internally.
      res = self.scnr.Inject(payload)
      if res.Code == 500:
        self.scnr.ResponseTrace(" ==> <i<cr>> Got 500 response code. Indicates error on the server.<i</cr>>")
        #If the response code is 500 then we report a vulnerability
        self.report_vuln(Tools.EncodeForTrace(payload))
      else:
        self.scnr.ResponseTrace(" ==> Code - " + str(res.Code) + " | Length - " + str(res.BodyLength))


  #This method implements the vulnerability reporting function
  def report_vuln(self, payload):
    #Create a new instance of the Finding class, it takes the BaseUrl property of the Request object as constructor argument. The self.scnr.BaseRequest property returns the original request that is being scanned.
    f = Finding(self.scnr.BaseRequest.BaseUrl)
    #The type of the finding is set as vulnerability. Other possible values are FindingType.Information and FindingType.TestLead
    f.Type = FindingType.Vulnerability
    #The confidence of the finding is set as Medium. This property only applies to vulnerabilities. TestLeads and Information don't need to set this. Other possible values are FindingConfidence.High and FindingConfidence.Low
    f.Confidence = FindingConfidence.Medium
    #The severity of the finding is set as High. This property only applies to vulnerabilities. TestLeads and Information don't need to set this. Other possible values are FindingSeverity.Medium and FindingSeverity.Low
    f.Severity = FindingSeverity.High
    #This vulnerability is given a title
    f.Title = 'RFDPlugin vulnerability found'
    #This vulnerability summary and trace are added. self.scnr.InjectedParameter gives the name of the parameter that was tested. self.scnr.InjectedSection gives the section where the parameter is located in the request. self.scnr.GetTrace() returns the scan trace messages collected up to this ponit as a string.
    f.Summary = "RFDPlugin vulnerability has been detected in the '" + self.scnr.InjectedParameter + "' parameter of the " + self.scnr.InjectedSection + " section of the request. <i<br>><i<br>><i<hh>>Test Trace:<i</hh>> " + self.scnr.GetTrace()
    #Triggers are a collection of Trigger objects. A Trigger is a set of Request object, corrresponding Response object and some keywords that were found in the Request and Response that triggered the detection of this vulnerability.
    #self.scnr.InjectedRequest property returns the request that was sent using the Inject method and self.scnr.InjectionResponse property gives the response to that request. In this case the request trigger is added as the injected payload and the response trigger is the status code 500
    f.Triggers.Add(payload, self.scnr.InjectedRequest, '500', self.scnr.InjectionResponse)
    #After defining the vulnerability it is added to the scanner objects list of findings
    self.scnr.AddFinding(f)
    #self.scnr.SetTraceTitle sets a title to this scan trace message. A title makes it easy to identify that this particular scan had some interesting finding.
    #The second argument to this function is the title importantance value. The SetTraceTitle method can be called multiple times in this plugin. But only the title that was given the highest importance value will be displayed in the scan trace. If there are more than one title with the highest priority value then their all these high importance titles will be shown.
    self.scnr.SetTraceTitle("RFDPlugin Found",100)


  #This method reads the payloads from the payloads files and stores it in a variable
  def load_payloads_from_file(self):
    #Config.Path gives the full path directory containing IronWASP.exe
    p_file = open(Config.Path + "\\plugins\\active\\RFDPlugin_payloads.txt")
    self.payloads = []
    payloads_with_newline = p_file.readlines()
    p_file.close()
    for pwnl in payloads_with_newline:
      self.payloads.append(pwnl.rstrip())



#This code is executed only once when this new plugin is loaded in to the memory.
#Create an instance of the this plugin
p = RFDPlugin()
#load payloads from the file
p.load_payloads_from_file()
#Call the GetInstance method on this instance which will return a new instance with all the approriate values filled in. Add this new instance to the list of ActivePlugins
ActivePlugin.Add(p.GetInstance())



#Information about Trace and Trace message formatting
#IronWASP has a special Scan Trace feature using which the plugin can tell the user exactly what it tried to do during the scan.
#The scan messages are available in the Automated Scanning -> Scan Trace section.
#The messasge formation system used is similar to HTML. There are special tags that you can use to format the message in differnet forms.
#The same system can be used to format your Finding summary as well.
#<i<br>>introduces a line break
#<i<b>>Makes the enclosed text bold<i</b>>
#<i<h>>Makes the enclosed text prominent like a heading<i</h>>
#<i<cr>>Makes the enclosed text appear in red<i</cr>>
#<i<cg>>Makes the enclosed text appear in green<i</cg>>
#<i<cb>>Makes the enclosed text appear in blue<i</cb>>
#<i<hlr>>Highlights the enclosed text appear in red<i</hlr>>
#<i<hlg>>Highlights the enclosed text appear in green<i</hlg>>
#<i<hlb>>Highlights the enclosed text appear in blue<i</hlb>>

