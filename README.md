# AMFDserBurp2020-12
Burp extension used to allow Burp to work with Flash applications.


Adds a tab to message viewing and editing panels to allow viewing and editing of the deserialized content.

Adds menu items to send deserialized versions of requests to either scanner or intruder so insertion points can be automatically added by Burp.

Adds a listener for outgoing requests. Requests sent by extensions, Intruder or Scanner that are in deserialized format are reserialized before being sent.


# Setup
Add the burpAMFDSerV3 jar file from the executables folder to Burp.
Point the Burp Extender Java Environment to the lib folder in Extender Options.
