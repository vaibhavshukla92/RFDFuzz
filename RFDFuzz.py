from IronWASP import *
import re


#Extend the Module base class
class RFDFuzz(Module):


  #Implement the GetInstance method of Module class. This method is used to create new instances of this module.
  def GetInstance(self):
    m = RFDFuzz()
    m.Name = 'RFDFuzz'
    return m


  #Implement the StartModule method of Module class. This is the method called by IronWASP when user tries to launch the moduule from the UI.
  def StartModule(self):
    #IronConsole is a CLI window where output can be printed and user input accepted
    self.console = IronConsole()
    self.console.SetTitle('RFDFuzz')
    #Add an event handler to the close event of the console so that the module can be terminated when the user closes the console
    self.console.ConsoleClosing += lambda e: self.close_console(e)
    self.console.ShowConsole()
    #'PrintLine' prints text at the CLI. 'Print' prints text without adding a newline at the end.
    self.console.PrintLine('[*] RFDFuzz has started')
    self.console.Print('[*] Enter target URL: ')
    #'ReadLine' accepts a single line input from the user through the CLI. 'Read' accepts multi-line input.
    url = self.console.ReadLine()
    self.console.PrintLine(url)
    self.console.PrintLine('[*] Target scanning!')
  
  req = Request(url)
  
    
#'req' is a variable that is assumed to contain a Request object

#We display a GUI based wizard to user and get the Fuzzer setting from user.
f = Fuzzer.FromUi(req)
#Set a custom source name for the Fuzzer logs
f.SetLogSource("RFDFuzzer")

#Open the payloads file and load payload from it
p_file = open("C:\\Users\\santoshkumar_gu\\Downloads\\ironwasp\\IronWASP\\plugins\\active\\RFDPlugin_payloads.txt")
payloads = []
payloads_with_newline = p_file.readlines()
p_file.close()
for pwnl in payloads_with_newline:
  payloads.append(pwnl.rstrip())

#Resets the fuzzer so that it is ready to start.
f.Reset()

#We go through a while loop till there are Fuzz or Injection points
while f.HasMore():
#We make the fuzzer go to the next injection point. On first run this command makes it point to the first injection point.
  f.Next()
  for payload in payloads:

#Inject the payload in the Request at the current injection point, send it to the server and get the response
    res = f.Inject(payload)
    if res.Code == 500:
      #If the response code is 500 then inform the user
      print "Injecting - " + payload + " made the server return a 500 response"
    if res.BodyString.count('error') > 0:
      #If the response body contains the string 'error' then inform the user
      print "Injecting - " + payload + " made the server return an error message in the response"




  def close_console(self, e):
    #This method terminates the main thread on which the module is running
    self.StopModule()



#This code is executed only once when this new module is loaded in to the memory.
#Create an instance of the this module
m = RFDFuzz()
#Call the GetInstance method on this instance which will return a new instance with all the approriate values filled in. Add this new instance to the list of Modules
Module.Add(m.GetInstance())



