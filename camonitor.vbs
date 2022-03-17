' *************************************************************************
' FILE: 
'camonitor.vbs
'
' DESCRIPTION: Monitoring script for CA Health.
'Performs the following checks
'/CAAlive - Are the CA DCOM interfaces responding?
'/CACertOK - Is the CA certificate (or the certs of parents) valid (not expired)
'/CACRLOK - Is the CRL of the CA or parents accessible and current
'/KRAOK - Are the KRA Certificates valid
'
'General parameters
'/SMTP - enable SMTP alerts
'/SMTPServer:ServerName = name of SMTP server to send alerts to
'/SMTPTo:"Maillist" = comma-separated list of recipients
'/NoEventLog - disables sending events to the event log
'
' AUTHORS:
'Andrew Hawkins, Ian Hellen (with contributions from David Hoyle)
'(C) Copyright 2004 MICROSOFT
'
' SOURCESAFE:
'$Archive: $
'$Date: $
'$Revision: $
'
' HISTORY:
'1.0 Original version adapted from script used in "Securing Wireless LANs" solution
'I added the section checking for KRAs, fixed a lot of bugs and restructured the
'the script
'1.1 Fixed a few minor bugs (SMTP addresses for email alerts not being handled properly)
'1.2 Fixed bugs in HTTP CRL checking and parsing of CA cert
'   1.3 Corrected undeclared variable errors in CheckCert, GetCRLsInChain and GetCDPs
'1.4 Corrected two more undeclared var errors in 
' *************************************************************************

Option Explicit

' Alert Levels
CONST NOSERVICE_ALERT = 5
CONST SECURITY_ALERT = 4
CONST CRITICAL_ALERT = 3
CONST ERROR_ALERT = 2
CONST WARNING_ALERT = 1
CONST NO_ALERT = 0

'String used as the Source in event log events
CONST EVENT_SOURCE= "CA Operations"
CONST CA_EVENT_SOURCE= "CA Operations"

'CA Event IDs
CONST CA_EVENT_CRL_EXPIRED=20
CONST CA_EVENT_CRL_OVERDUE=21
CONST CA_EVENT_CRL_NOT_AVAILABLE_LDAP=22
CONST CA_EVENT_CRL_NOT_AVAILABLE_HTTP=23
CONST CA_EVENT_CS_RPC_OFFLINE=1
CONST CA_EVENT_CS_RPC_ADMIN_OFFLINE=2
CONST CA_EVENT_CA_CERT_EXPIRED=10
CONST CA_EVENT_CA_CERT_NEARLY_EXPIRED=11
CONST CA_EVENT_CA_CERT_RENEWAL_DUE=12
CONST CA_EVENT_CA_CERT_REVOKED=13
CONST CA_EVENT_KRA_CERT_EXPIRED=30
CONST CA_EVENT_KRA_CERT_NEARLY_EXPIRED=31
CONST CA_EVENT_KRA_CERT_REVOKED=32
CONST CA_EVENT_KRA_CERT_UNTRUSTED=33

CONST CA_EVENT_BACKUP_LOCKED=30
CONST CA_EVENT_CA_OTHER=100

'Monitoring parameters 
CONST CRL_CHECK_TOLERANCE= 20

'percentage tolerance for CheckCRLs function
' - CheckCRLs raises an alert if more than this percentage
'of the time between the CRL Next Publish and CRL NextUpdate
'values has passed.


CONST cdoSMTPServer = "http://schemas.microsoft.com/cdo/configuration/smtpserver"
CONST cdoSMTPConnectionTimeout = "http://schemas.microsoft.com/cdo/configuration/smtpconnectiontimeout"
CONST cdoSMTPAuthenticate = "http://schemas.microsoft.com/cdo/configuration/smtpauthenticate"
CONST cdoSendUsingMethod = "http://schemas.microsoft.com/cdo/configuration/sendusing"

CONST CdoLow= 0 'Low importance  
CONST CdoNormal= 1 'Normal importance (default)  
CONST CdoHigh= 2 'High importance

CONST TristateUseDefault = -2, TristateTrue = -1, TristateFalse = 0
CONST adModeReadWrite = 3
CONST adTypeBinary = 1
CONST adTypeText = 2
CONST adSaveCreateOverwrite = 2

CONST CA_ALIVE = 1
CONST CA_CERTOK = 2
CONST CA_CRLOK = 4
CONST CA_KRAOK = 8

' Constants for CertAdmin property IDs
Const CR_PROP_CASIGCERTCOUNT    = 11  '// Long
' CR_PROP_CASIGCERTCOUNT Elements:
Const CR_PROP_CASIGCERT         = 12  ' Binary, Indexed

Const CR_PROP_KRACERTUSEDCOUNT  = 24  ' Long
Const CR_PROP_KRACERTCOUNT      = 25  ' Long
' CR_PROP_KRACERTCOUNT Elements:
Const CR_PROP_KRACERT           = 26  ' Binary, Indexed
' CR_PROP_KRACERTCOUNT Elements:
Const CR_PROP_KRACERTSTATE      = 27  ' Long, Indexed

' Constants for data types and indexed status
Const PROPTYPE_LONG  = &H1
Const PROPTYPE_DATE  = &H2
Const PROPTYPE_BINARY  = &H3
Const PROPTYPE_STRING  = &H4
Const PROPTYPE_MASK  = &HFF
Const PROPFLAGS_INDEXED = &H10000
' Constants for binary flags
Const CV_OUT_BINARY = &H2

' CertConfig.GetConfig parameter to retrieve default CA
Const CC_DEFAULTCONFIG = 0

' CertificateStatus Checkflag 
Const CAPICOM_CHECK_TRUSTED_ROOT = &H1' Checks for a trusted root of the certificate chain.
Const CAPICOM_CHECK_TIME_VALIDITY = &H2' Checks the time validity of all certificates in the chain.
Const CAPICOM_CHECK_SIGNATURE_VALIDITY = &H4'Checks signature valid
Const CAPICOM_CHECK_ONLINE_ALL = &H1EF' Checks revocation


'*********************************************************
' Global variables for alerting
Dim bAlertEvtLog, bAlertEmail
Dim strSMTPSrv, strRecipients

'*********************************************************
' Start the code here


Main


Sub Main ()
Dim iScriptOp
Dim objArgs

'Set defaults
bAlertEvtLog = True
bAlertEmail = False

' First we need to retrieve the parameters
iScriptOp = 0

Set objArgs = WScript.Arguments.Named

'If no arguments or explicit request for help display usage and exit
If objArgs.Count = 0 Or objArgs.Exists("?") Or objArgs.Exists("help") Then
Usage
Exit Sub
End If

'Extract the commands from the command line (can be multiple)
'  CAAlive - Are the CA DCOM interfaces responding?
If objArgs.Exists("CAAlive") Then iScriptOp = iScriptOp + CA_ALIVE
'  Is the CA certificate (or the certs of parents) valid (not expired)
If objArgs.Exists("CACertOK") Then iScriptOp = iScriptOp + CA_CERTOK
'  Is the CRL of the CA or parents accessible and current
If objArgs.Exists("CACRLOK") Then iScriptOp = iScriptOp + CA_CRLOK
'  Are the KRA Certificates valid
If objArgs.Exists("KRAOK") Then iScriptOp = iScriptOp + CA_KRAOK

'If no command was specified display usage
If iScriptOp = 0 Then
Usage
Exit Sub
End If

'Select alerting type (note can disable both for just screen/debug output)
'Enable email alerting
If objArgs.Exists("SMTP") Then bAlertEmail = True
'Disable event log alerting?
If objArgs.Exists("NoEventLog") Then bAlertEvtLog = False

'If email check that the server and recipients are specified
If bAlertEmail Then
If objArgs.Exists("SMTPServer") And objArgs.Item("SMTPServer") <> "" Then
strSMTPSrv = objArgs.Item("SMTPServer")
Else
debug "No SMTP Server specified"
Usage
Exit Sub
End If

If objArgs.Exists("SMTPTo") And objArgs.Item("SMTPTo") <> "" Then
strRecipients = objArgs.Item("SMTPTo")
Else
debug "No SMTP Recipients specified."
Usage
Exit Sub
End If
End If

If iScriptOp And CA_ALIVE Then IsCAAlive
If iScriptOp And CA_CERTOK Then CheckCert
If iScriptOp And CA_CRLOK Then CheckCRLsInChain
If iScriptOp And CA_KRAOK Then CheckKRAs
 

End Sub

Sub Usage
'*********************************************************
' Name:Usage
' Purpose:Pings the Certificate Services Request 
'and Admin DCOM interfaces.
' Inputs:None
' Returns:TRUE / FALSE 
'*********************************************************
WScript.Echo "CAMonitor"
WScript.Echo "Usage:"
WScript.Echo vbTab & "cscript " & WScript.ScriptName & " {/CAAlive | /CACertOK | /CACRLOK | /KRAOK}"
WScript.Echo vbTab & "[/smtp /smtpserver:MyServer.Dom /smtpto:""recip1@co.dom, recip2@co.dom]"""
WScript.Echo vbTab & "[/noeventlog]"
WScript.Echo ""
WScript.Echo vbTab & "The default is to log to the event log only."
End Sub

Sub IsCAAlive
'*********************************************************
' Name:IsCAAlive
' Purpose:Pings the Certificate Services Request 
'and Admin DCOM interfaces.
' Inputs:None
' Returns:TRUE / FALSE 
'*********************************************************

'Turn on Error Handling
On Error Resume Next
Dim strError

'Set the default return for the function
IsCAAlive = FALSE

'Dim function specific variables and constants

If Not ExecuteCommand("certutil -ping", "interface is alive") Then
strError = "CA is not responding on RPC user interface"
AlertID strError, CRITICAL_ALERT, CA_EVENT_CS_RPC_OFFLINE, CA_EVENT_SOURCE

End If 'ping
If Not ExecuteCommand("certutil -pingadmin", "interface is alive") Then
strError = "CA is not responding on RPC admin interface"
AlertID strError, CRITICAL_ALERT, CA_EVENT_CS_RPC_ADMIN_OFFLINE, CA_EVENT_SOURCE

End If 'pingadmin

End Sub 'IsCAAlive


Function CheckCert ()
'*********************************************************
' Name: CheckCert
' Purpose: Checks the CA certificate's validity and the certs
'of any parents up to the root CA.
'Issues alerts if:
'1) Warning if cert has less than 50% of validity remaining
'2) Error if  to see if is about to expire (1 month or less left)
'3) Critical error if the cert has expired
'    
' Inputs: Nothing
' Returns: True if everything OK, otherwise False
'*********************************************************

'Enable error handling
On Error Resume Next

'Set default return value of the function
CheckCert = FALSE

'Dims and Consts
Dim strCertPath, strCert, strCAConfig
Dim objChain, objCaCert, objCert, objCertAdmin, objCertConfig, objCertStatus
Dim iCertIndex, iCertCount
Dim dtmCertValidTo
Dim intSeverity, strError
Dim strReturn, iCACount

'Instantiate any objects
Set objCaCert = CreateObject("CAPICOM.Certificate")
Set objChain = CreateObject("CAPICOM.Chain")

'Check for CAPICOM not registered Error
Select Case err.number
Case 0'object registered OK
Case 429'CAPICOM 2.0 must be registered
debug "CAPICOM is not registered ... quitting"
err.Clear
Exit Function
Case Else
debug err.number
err.Clear
End Select

'Get the Config string for the CA running on this server
Set objCertConfig = CreateObject("CertificateAuthority.Config")
If Not ErrorHandle (Err.number, Err.Description, "Error creating CertConfig object", strReturn) Then
debug strReturn
Exit Function
End if
strCAConfig = objCertConfig.GetConfig(CC_DEFAULTCONFIG)

'Create a CertAdmin object to retrieve the CA cert with
Set objCertAdmin = CreateObject("CertificateAuthority.Admin")
If Not ErrorHandle (Err.number, Err.Description, "Error creating CertAdmin object", strReturn) Then
debug strReturn
Exit Function
End if

'Get the number of CA Certs using the CertAdmin.GetCAProperty interface
iCertCount = objCertAdmin.GetCAProperty(strCAConfig, CR_PROP_CASIGCERTCOUNT, 0, PROPTYPE_LONG, 0)
If iCertCount = 0 Or ErrorHandle _
            (Err.number, Err.Description, "Error retrieving count of CA certificates", strReturn) = _
                False Then
debug strReturn
Exit Function
End if

'retrieve the last (most recent) CA certificate
strCert = objCertAdmin.GetCAProperty _
            (strCAConfig, CR_PROP_CASIGCERT, iCertCount -1, PROPTYPE_BINARY, CV_OUT_BINARY)
objCACert.Import(strCert)


'And build the chain from the local CA cert
objChain.Build objCaCert
If err.number <> 0 then
'An error occured building the chain from the local ca cert
strError = "CA Monitor script failure - An error occured building the chain from the " & _
                    "local CA certificate (Error:" &_
Hex(Err.number) & " " & Err.Description & ")"
intSeverity = CRITICAL_ALERT
AlertID strError, intSeverity, CA_EVENT_CA_OTHER, CA_EVENT_SOURCE
debug strError
Exit Function
End If

'Walk the Chain
For Each objCert in objChain.Certificates

debug "checking validity of " & objCert.SubjectName & " Serial Number:" & objCert.SerialNumber

dtmCertValidTo = objCert.ValidToDate

'//////////////////////////////////////
' Check cert validity against three conditions
'
' First check to see if the cert is out of date - i.e. ValidTo is earlier
' than Now()
If datediff("d",now,dtmCertValidTo) <= 0 Then
'CA Cert out of date for CAName at CDP-URI - CRITICAL
strError = "CA Certificate expired: " & objCert.SubjectName & _
"  Serial Number: " & CStr(objCert.SerialNumber) & _
"  Expiry date: " & CStr(dtmCertValidTo)
intSeverity = NOSERVICE_ALERT
debug strError
AlertID strError, intSeverity, CA_EVENT_CA_CERT_EXPIRED, CA_EVENT_SOURCE

' If that was OK check to see if we have less than a month left
ElseIf datediff("d",dateadd("m",1,now),dtmCertValidTo) <= 0 Then
'CA Cert about to expire for CAName at CDP-URI - ERROR
intSeverity = ERROR_ALERT
strError = "CA Certificate about to expire:" & objCert.SubjectName & _
"  Serial Number: " & CStr(objCert.SerialNumber) & _
"  Expiry date: " & CStr(dtmCertValidTo)
debug strError
AlertID strError, intSeverity, CA_EVENT_CA_CERT_NEARLY_EXPIRED, CA_EVENT_SOURCE

' If that was OK check to see if the cert is more than 50% through its validity period
' (should be renewing it now!)
ElseIf datediff("d",dateadd("d",datediff("d",objCert.ValidFromDate, objCert.ValidToDate) / 2,now), _
                    dtmCertValidTo) <= 0 Then
'CA Cert renewal overdue for CAName at CDP-URI - WARNING
strError = "CA Certificate renewal overdue:" & objCert.SubjectName & _
"  Serial Number: " & CStr(objCert.SerialNumber) & _
"  Expiry date: " & CStr(dtmCertValidTo)
intSeverity = WARNING_ALERT
debug strError
AlertID strError, intSeverity, CA_EVENT_CA_CERT_RENEWAL_DUE, CA_EVENT_SOURCE

Else
'Check revocation status
Set objCertStatus = objCert.IsValid()
objCertStatus.CheckFlag = CAPICOM_CHECK_ONLINE_ALL

If Not objCertStatus.Result Then 
'CA Cert is untrusted or revoked
strError = "CA Certificate has been revoked:" & objCert.SubjectName & _
"  Serial Number: " & CStr(objCert.SerialNumber) 
intSeverity = ERROR_ALERT
debug strError
AlertID strError, intSeverity, CA_EVENT_CA_CERT_REVOKED, CA_EVENT_SOURCE
Else
debug "CA Cert OK"
End If
End If

Next

CheckCert = TRUE

End Function


Function CheckKRAs ()
'*********************************************************
' Name: CheckKRAs
' Purpose: Checks the CA KRA certificates' validity 
'Issues alerts if:
'1) Error if  to see if is about to expire (1 month or less left)
'2) Critical error if the cert has expired
'    
' Inputs: Nothing
' Returns: True if everything OK, otherwise False
'*********************************************************

'Enable error handling
On Error Resume Next

'Set default return value of the function
CheckKRAs = FALSE

'Dims and Consts
Dim strCertPath, strCert
Dim objCert, objCertAdmin, objCertConfig, objCertStatus
Dim iKRAIndex, iKRACount
Dim dtmCertValidTo
Dim intSeverity, strError, strReturn
Dim strCAConfig

'Instantiate any objects
Set objCert = CreateObject("CAPICOM.Certificate")

'Check for CAPICOM not registered Error
Select Case err.number
Case 0'object registered OK
Case 429'CAPICOM 2.0 must be registered
debug "CAPICOM is not registered ... quitting"
err.Clear
Exit Function
Case Else
debug err.number
err.Clear
End Select

'Get the Config string for the CA running on this server
Set objCertConfig = CreateObject("CertificateAuthority.Config")
If Not ErrorHandle (Err.number, Err.Description, "Error creating CertConfig object", strReturn) Then
debug strReturn
Exit Function
End if
strCAConfig = objCertConfig.GetConfig(CC_DEFAULTCONFIG)

'Create a CertAdmin object
Set objCertAdmin = CreateObject("CertificateAuthority.Admin")
If Not ErrorHandle (Err.number, Err.Description, "Error creating CertAdmin object", strReturn) Then
debug strReturn
Exit Function
End if

'Get the number of KRA Certs using the CertAdmin.GetCAProperty interface
iKRACount = objCertAdmin.GetCAProperty(strCAConfig, CR_PROP_KRACERTCOUNT, 0, PROPTYPE_LONG, 0)
If Not ErrorHandle _
            (Err.number, Err.Description, "Error retrieving count of KRA certificates", strReturn) Then
debug strReturn
Exit Function
End if

'If there are no KRA Certs so nothing to do
If iKRACount = 0 Then
debug "No KRAs"
Exit Function
End If

debug "KRAs = " & CStr(iKRACount)

'Otherwise we need to look at each KRA certificate
For iKRAIndex = 0 To iKRACount - 1 

strCert = objCertAdmin.GetCAProperty _
                    (strCAConfig, CR_PROP_KRACERT, iKRAIndex, PROPTYPE_BINARY, CV_OUT_BINARY)
objCert.Import(strCert)

'debug cstr(obj1)
If err.number <> 0 Then
debug "Error " & err.Description
Exit Function
End If

debug "Checking validity of " & objCert.SubjectName & "  KRA Cert#" & CStr(iKRAIndex)

dtmCertValidTo = objCert.ValidToDate

'//////////////////////////////////////
' Check cert validity against three conditions
'
' First check to see if the cert is out of date - i.e. ValidTo is earlier
' than Now()
If datediff("d",now,dtmCertValidTo) <= 0 Then
'KRA Cert out of date for CAName at CDP-URI - CRITICAL
strError = "KRA Certificate expired: " & objCert.SubjectName & _
"  Serial Number: " & CStr(objCert.SerialNumber) & _
" Expiry date: " & CStr(dtmCertValidTo)
intSeverity = ERROR_ALERT
debug strError
AlertID strError, intSeverity, CA_EVENT_KRA_CERT_EXPIRED, CA_EVENT_SOURCE

' If that was OK check to see if we have less than a month left
ElseIf datediff("d",dateadd("m",1,now),dtmCertValidTo) <= 0 Then
'KRA Cert about to expire for CAName at CDP-URI - ERROR
intSeverity = WARNING_ALERT
strError = "KRA Certificate about to expire:" & objCert.SubjectName & _
"  Serial Number: " & CStr(objCert.SerialNumber) & _
"  Expiry date: " & CStr(dtmCertValidTo)
debug strError
AlertID strError, intSeverity, CA_EVENT_KRA_CERT_NEARLY_EXPIRED, CA_EVENT_SOURCE
End If

'Check revocation status
Set objCertStatus = objCert.IsValid()
objCertStatus.CheckFlag = CAPICOM_CHECK_ONLINE_ALL

If Not objCertStatus.Result Then 
'KRA Cert is untrusted or revoked
strError = "KRA Certificate has been revoked: " & objCert.SubjectName & _
"  Serial Number: " & CStr(objCert.SerialNumber) 
intSeverity = ERROR_ALERT
debug strError
AlertID strError, intSeverity, CA_EVENT_KRA_CERT_REVOKED, CA_EVENT_SOURCE
End If

'Check trust & signature
Set objCertStatus = objCert.IsValid()
objCertStatus.CheckFlag = CAPICOM_CHECK_TRUSTED_ROOT + CAPICOM_CHECK_SIGNATURE_VALIDITY

If Not objCertStatus.Result Then 
'KRA Cert is untrusted or revoked
strError = "KRA Certificate is untrusted or has invalid signature: " & objCert.SubjectName & _
"  Serial Number: " & CStr(objCert.SerialNumber) 
intSeverity = ERROR_ALERT
debug strError
AlertID strError, intSeverity, CA_EVENT_KRA_CERT_UNTRUSTED, CA_EVENT_SOURCE
End If



Next

CheckKRAs = TRUE

End Function


Function CheckCRLsInChain ()
'*********************************************************
' Name: CheckCRLsInChain
' Purpose: Validate each each CRL in the CDPs for each CA in the chain
' Inputs: Note
' Returns: True/False
'*********************************************************

'Enable error handling
On Error Resume Next

'Set default return value of the function
CheckCRLsInChain = FALSE

'Dims and Consts
Dim objChain, objEndCert, objCert, objShell
Dim strCDP, strCRLPath, arrCDPs()
Dim intSeverity, strError, strReturn
Dim i

'Instantiate any objects
Set objEndCert = CreateObject("CAPICOM.Certificate")
Set objChain = CreateObject("CAPICOM.Chain")
'Check for CAPICOM not registered Error
Select Case err.number
Case 0'object registered OK
Case 429'CAPICOM 2.0 must be registered
debug "CAPICOM is not registered ... quitting"
err.Clear
Exit Function
Case Else
ErrorHandle Err.number, Err.Description, "Error loading CAPICOM", strReturn
debug strReturn
err.Clear
Exit Function
End Select


Set objShell = CreateObject("WScript.Shell")
If Not ErrorHandle (Err.number, Err.Description, "Error creating WScript.shell object", strReturn) Then
debug strReturn
Exit Function
End if

'Get a locally issued end-entity cert
If GetCert(objEndCert) = FALSE Then
'It was not possible to retrieve an issued cert from the local CA
strError = "CA Monitor script failure - retrieving a end-entity certificate from " & _
                    "local CA database failed"
intSeverity = ERROR_ALERT
AlertID strError, intSeverity, CA_EVENT_CA_OTHER, CA_EVENT_SOURCE
debug strError
Exit Function
End If

'Build the chain from an end-entity cert
err.Clear'clear down any error conditions
objChain.Build objEndCert
If err.number <> 0 Then
'An error occurred buiding the certificate chain
strError = "CA Monitor script failure - An error occurred buiding the certificate chain"
intSeverity = ERROR_ALERT
AlertID strError, intSeverity, CA_EVENT_CA_OTHER, CA_EVENT_SOURCE
debug strError
Exit Function
End If

'Loop through the chain of the end-entity cert
For Each objCert in objChain.Certificates

'The return value is set to FALSE here because if this is not the last cert
'in the chain then the default condition needs to be reset and if it is
'the last cert in the chain the LDAP and HTTP checks will set to TRUE if appropriate
CheckCRLsInChain = FALSE

'Get the CDPs from the cert
If ReadCDPs(objCert, arrCDPs) = FALSE then 
'If this is a Root Cert we are not worried about no CDP
'otherwise we have a problem
If objCert.SubjectName = objCert.IssuerName Then
debug "Root CA Cert - no CDP present, skipping check"
intSeverity = NO_ALERT
CheckCRLsInChain = True
Exit Function
Else
'Reading CDPs from the cert failed
strError = "failed to read at least one CDP from certificate:" & objCert.SubjectName
intSeverity = ERROR_ALERT
AlertID strError, intSeverity, CA_EVENT_CA_OTHER, CA_EVENT_SOURCE
debug strError
Exit Function
End If
End If

'Echo relevant information to debug
debug "CDPs from:" & objCert.SubjectName
For i = 0 to UBound(arrCDPs,2)
debug arrCDPs(1,i) & " CDP: " & arrCDPs(0,i)
Next
Debug ""
'----------------
'Get and check each CDP
For i = 0 to UBound(arrCDPs,2) 

' Get the CDP
strCDP = arrCDPs(0,i)
debug "Checking: " & strCDP

'Check CRL depending on type
Select Case arrCDPs(1,i)

Case "LDAP"

'----------------
'Get and check the LDAP CRL
If strCDP <> "" Then'The cert's CDPs included an LDAP URL.
strCrlPath = EnvironmentVariable("temp") & "\ldap.crl"

'If we can get CRL from CDP and dump to file
If GetLDAPCRL(strCDP,strCrlPath) Then
CheckCRLsInChain = CheckCRL(strCrlPath, strCDP, objCert)
Else
'LDAP CRL dumped to file OK so check it
strError = "Could not retrieve CRL for CA " & _
                                                    objCert.IssuerName & " at CDP: " & _
strCDP
debug strError
AlertID strError, CRITICAL_ALERT, CA_EVENT_CRL_NOT_AVAILABLE_LDAP, _
                                                    CA_EVENT_SOURCE
End If'GetLDAPCRL
End If'strCDP <> ""

Case "HTTP"

'----------------
'Get and check the HTTP CRL
If strCDP <> "" Then'The cert's CDPs included an HTTP URL.
strCrlPath = EnvironmentVariable("temp") & "\http.crl"

'If we can get CRL from CDP and dump to file
If GetHTTPCRL(strCDP,strCrlPath) Then
CheckCRLsInChain = CheckCRL(strCrlPath, strCDP, objCert)
else
' GetHTTPCRL
'HTTP CRL couldn't be retrieved
strError = "Could not retrieve CRL for CA " & objCert.IssuerName _
                                                    & " at CDP: " & _
strCDP
debug strError
AlertID strError, CRITICAL_ALERT, CA_EVENT_CRL_NOT_AVAILABLE_HTTP, _
                                                    CA_EVENT_SOURCE

End If ' GetHTTPCRL
End If' strCDP <> ""

Case Else
' support for more types here i.e. FTP, File..

End Select

Next
Next

End Function 'CheckCRLsInChain

'*********************************************************
' Name: CheckCRL
' Purpose: Dumps a CRL and sends it to be parsed to check that
'it has not expired (or nearly expired)
' Inputs: StrCRLPath, strCDP, current cert.
' Returns: True = check OK/False = script failure
'*********************************************************
Function CheckCRL(strCRLPath, strCDP, objCert)

On error resume next

Dim objStream, objShell
Dim strError
Dim intSeverity

CheckCRL = FALSE

Set objShell = CreateObject("WScript.Shell")

' We dump the CRL using Certutil. objStream is the WshScriptExec object. This captures the
' output (stdout) from the certutil command which we'll parse to check the CRL properties
Set objStream = objShell.Exec("%ComSpec% /C certutil " & strCrlPath)

'Call CheckCRLStream to check the Certutil output
If CheckCRLStream(objStream, intSeverity) Then

'The CDP Check was OK
debug "CRL Checked - CRL Status: " & CStr(intSeverity)

'Need to select an appropriate message
Select Case intSeverity
Case NOSERVICE_ALERT
AlertID "CRL for CA " & objCert.IssuerName & " at CDP: " & strCDP & _
" has expired.", NOSERVICE_ALERT, CA_EVENT_CRL_EXPIRED, CA_EVENT_SOURCE 
Case CRITICAL_ALERT
AlertID "CRL for CA " & objCert.IssuerName & " at CDP: " & strCDP & _
" is overdue.", CRITICAL_ALERT, CA_EVENT_CRL_OVERDUE, CA_EVENT_SOURCE
Case ERROR_ALERT
AlertID "Could not determine expiry dates for CRL for CA " & objCert.IssuerName & _
" at CDP: " & strCDP, ERROR_ALERT, CA_EVENT_CA_OTHER, CA_EVENT_SOURCE
End Select

CheckCRL = TRUE

Else 'Something wrong with CheckCRLStream
strError = "Could not determine expiry dates for CRL for CA " & objCert.IssuerName & _
" at CDP: " & strCDP
debug strError
AlertID strError, ERROR_ALERT, CA_EVENT_CA_OTHER, CA_EVENT_SOURCE 

End If ' CheckCRLStream

End Function

Function GetCert (byVal objCert)
'*********************************************************
' Name: GetCert
' Purpose: Open to the CA database and find last issued cert
' Inputs: None
' Returns: ObjCert - pointer to cert
'*********************************************************

'********************************************************************************
'Use ICertView to find the newest issued cert.
'Seek to the end of the RequestId column (sort in descending order), 
'and look for the first row with Request.Disposition == 20 (DB_DISP_ISSUED).  
'Fetch the RawCertficate column.  You can use the CDP URLs in this cert.
'********************************************************************************

'Enable error handling
On Error Resume Next

'Set default return value of the function
GetCert = FALSE

'Dims and Consts
Dim objView, objCol, objRow, objAttrib, objFso, objShell, objStream
Dim intIndex, intCount, intIndex2, i
Dim strCertPath
Dim lngRequestDisposition
Dim stmCert
Dim strConnection, strLine

Const CV_OUT_BASE64 = &H1
Const DB_DISP_ISSUED = 20
Const CVR_SEEK_GT = &H10
Const CVR_SORT_DESCEND = &H2

'Instantiate any objects
Set objView = CreateObject("CertificateAuthority.View")
Set objFso = CreateObject("Scripting.FileSystemObject") 
Set objShell = WScript.CreateObject("WScript.Shell")

'Build the ConnectionStringfor the local CA
Set objStream = objShell.Exec("%ComSpec% /C certutil -CaInfo name")
Do While objStream.StdOut.AtEndOfStream = FALSE
strLine = objStream.StdOut.ReadLine
If Instr(strLine,"CA name:") <> 0 Then
strConnection = EnvironmentVariable("COMPUTERNAME") & "\" & mid(strLine,10)
End If
Loop

If strConnection = "" Then
'we didn't get a CA name so end now
Debug "Error: No CA Name found!"
'Exit Function
End If

err.Clear
'Instantiate the Certificate Authority View
objView.OpenConnection(strConnection)
If err.number <> 0 then
Debug "Error: Failed to openconnection to CertAuthView"
Exit Function
End if

' Get the number of columns
intCount = objView.GetColumnCount(False)
objView.SetResultColumnCount(intCount)

' add each column to the view
For i = 0 To intCount - 1
objView.SetResultColumn (i)
Next

intIndex = objView.GetColumnIndex(False, "RequestID")
objView.SetRestriction intIndex, CVR_SEEK_GT, CVR_SORT_DESCEND, 0

Set objRow = objView.OpenView
If objRow is nothing then
Debug "Error: Failed to OpenView of CA database"
Exit Function
End If

Do Until objRow.Next = -1
Set objCol = objRow.EnumCertViewColumn()
Set objAttrib = objRow.EnumCertViewAttribute(0)
Do Until objCol.Next = -1
Select Case objCol.GetDisplayName
Case "Binary Certificate"
stmCert = objCol.GetValue(CV_OUT_BASE64)
Case "Request Disposition"
lngRequestDisposition = clng(objCol.GetValue(CV_OUT_BASE64))
End Select
Loop

If lngRequestDisposition = DB_DISP_ISSUED Then

objCert.Import stmCert
GetCert = TRUE
Exit Function

End If

Set objCol = Nothing

intIndex2 = objRow.Next 
Loop

Set objCol = Nothing
Set objRow = Nothing
Set objView = Nothing

End Function


Function ReadCDPs (byVal objCert, byRef arrCDPs())
'*********************************************************
' Name: ReadCDPs
' Purpose: Return an array of CDP paths
' Inputs: Cert, array
' Returns: array : arrCDPs
'0,y  = the CDP Path
'1,y = the CDP Type
'*********************************************************

'Enable error handling
On Error Resume Next

'Set default return value of the function
ReadCDPs = FALSE

'Dims and Consts
Dim objExtension
Dim strExtension
Dim arrCDP
Dim strHTTPCDP, strLDAPCDP
Dim i
Dim iCDPs : iCDPs=0

'Loop through the Certificate's extensions
For Each objExtension in objCert.Extensions
If objExtension.OID = 16 then 'The extention contains the CDPs
strExtension = objExtension.EncodedData.Format
arrCDP = Split(strExtension,"URL=")'Break the CDPs into an array
For i = 0 to ubound(arrCDP)'Loop through the CDP array
Select Case lcase(left(arrCDP(i),4)) 
                                'Look for the HTTP or LDAP protocol, denoting a CDP
Case "http"
' delicate string handling - Must be of correct format
strHTTPCDP = trim(arrCDP(i))
If Right(strHTTPCDP,1) = "," Then
strHTTPCDP = Left(strHTTPCDP,Len(strHTTPCDP)-1)
End If
ReDim preserve arrCDPs(1,iCDPs)
arrCDPs(0, iCDPs) = strHTTPCDP
arrCDPs(1, iCDPs) = "HTTP"
iCDPs = iCDPs + 1
Case "ldap"
' delicate string handling - Must be of correct format
strLDAPCDP = left(arrCDP(i), instr(arrCDP(i),"?") - 1)
strLDAPCDP = Replace(strLDAPCDP,"%20"," ")
strLDAPCDP = Replace(strLDAPCDP,"ldap:///","ldap://")
ReDim preserve arrCDPs(1,iCDPs)
arrCDPs(0, iCDPs) = strLDAPCDP
arrCDPs(1, iCDPs) = "LDAP"
iCDPs = iCDPs + 1
Case Else

End Select
Next
End If
Next

If iCDPs > 0 Then
'At least one of the CDPs were successfully retrieved
ReadCDPs = TRUE
End If

End Function

Function GetHTTPCRL (strPath, strCrlPath)
'*********************************************************
' Name: GetHTTPCRL
' Purpose: Retrieves a CRL at a specified URL and dumps it to a
'file
' Inputs: strPath = URL of CRL file
'strCRLPath = local file to save CRL to
' Returns: True = success, False = failure
'*********************************************************

'Enable error handling
On Error Resume Next

'Set default return value of the function
GetHTTPCRL = FALSE

'Dims and Consts
Dim objHTTP, objCRL

'Issue the Get Request to the URL
err.Clear
Set objHTTP = CreateObject("Microsoft.XMLHTTP")
objHTTP.open "GET", strPath, False
objHTTP.send
If err.number <> 0 Then
'An error occured retrieving the HTTP CRL
debug "An error occured retrieving the HTTP CRL from '" & strPath & "'"
Exit Function
End If

'Pipe the CRL from the HTTP response to a local file
err.Clear
Set objCRL = createobject("ADODB.Stream")
objCRL.Type = adTypeBinary
objCRL.Mode = adModeReadWrite
objCRL.Open
objCRL.Write objHTTP.responseBody
objCRL.SavetoFile strCrlPath, adSaveCreateOverwrite
objCRL.Close
if err.number <> 0 then
'An error occured writing the HTTP CRL to file
debug "An error occured writing the HTTP CRL to file. Error:" & CStr(Err.number) &_
"  " & Err.Description
Else
debug "HTTP CRL successfully written to file"
GetHTTPCRL = TRUE
End If

End Function

Function GetLDAPCRL (strPath, strCrlPath)
'*********************************************************
' Name: GetLDAPCRL
' Purpose: Retrieves a CRL at a specified LDAP URL and saves it to a
'file
' Inputs: strPath = URL of CRL file
'strCRLPath = local file to save CRL to
' Returns: True = success, False = failure
'*********************************************************

'Enable error handling
On Error Resume Next

'Set default return value of the function
GetLDAPCRL = FALSE

'Dims and Consts
Dim objDS, objCRL, objFso, objCRLFile
Dim binCRL
Dim strCRL
Dim chrByte
Dim j

'Get the passed in LDAP path as an object
err.Clear
Set objDS = GetObject("LDAP:") 
Set objCRL = objDS.OpenDSObject(ucase(strPath), vbNullString, vbNullString, 1) 
If err.number <> 0 then
'An error occured retrieving the AD CA Object
debug "An error occured retrieving '" & strPath & "'"
Exit Function
End if

'Get a binary representation of the CRL
err.Clear
binCRL= objCRL.Get ("certificateRevocationList")
If err.number <> 0 then
'An error occured retrieving the AD CA Object
debug "An error occured retrieving the CRL from '" & strPath & "'"
Exit Function
End if

'Convert the binary CRL into a string
err.Clear
strCRL=""
for j = lbound(binCRL) to ubound(binCRL)
chrByte = ascb(midb(binCRL,j+1,1))
strCRL = strCRL & chr(chrByte)
next
If err.number <> 0 then
'An error occured converting the CRL to a string
debug "An error occured converting the binary LDAP CRL to a string"
Exit Function
End If

'Write the string crl to a file
err.Clear
Set objFso = CreateObject("Scripting.FileSystemObject")
Set objCRLFile = objFso.CreateTextFile(strCrlPath, True) 'Create the CRL, overwriting if necessary
objCRLFile.Write( strCRL ) 'Write he content to the CRL
objCRLFile.Close
If err.number <> 0 Then
'An error occured writing the crl to file
debug "An error occured writing the LDAP CRL to file"
Exit Function
Else
'The LDAP CRL was successfully written to disk.
debug "LDAP CRL successfully written to file"
GetLDAPCRL = TRUE
End If


End Function

Function CheckCRLStream (byVal stmCRL, byRef intSeverity)
'*********************************************************
' Name: CheckCRLStream
' Purpose: Checks a CRL to determine whether is has expired or
'is about to expire
' Inputs: stmCRL = the textStream containing the CRL
' Outputs: intSeverity = the severity of the alert
' Returns: True if function worked OK, False if some kind of error 
'*********************************************************

'Enable error handling
On Error Resume Next

Dim strLine, dtmNextUpdate, dtmNextCRLPublish
Dim d, d1, d2, t2

CheckCRLStream = TRUE
intSeverity = NO_ALERT

'Retrieve the 'NextUpdate' and 'Next CRL Publish' field from the CRL
Do While stmCRL.StdOut.AtEndOfStream = FALSE
strLine = stmCRL.StdOut.ReadLine

If instr(strLine,"NextUpdate") <> 0 then
If IsDate(mid(strLine,13)) Then
dtmNextUpdate = cdate(mid(strLine,13))
Else
dtmNextUpdate = ""
End If
End If

' Format NextPublish as a date
' NextPublish is an optional date included in a CRL to indicate
' when the next CRL is due. Cert Services includes this.
If instr(strLine,"Next CRL Publish") <> 0 then
d = stmCRL.StdOut.ReadLine
d1 = Mid(d,Instr(d,",")+2)'Get rid of leading Day of week
d2 = trim(Mid(d1,1,Instr(d1,":")-3))'extract date part (no time)
t2 = trim(Mid(d1,Instr(d1,":")-2))'extract time part (no date)

If IsDate(d2) And IsDate(t2) Then
'now convert to dates and add back together
dtmNextCRLPublish = cdate(trim(d2))+ cdate(t2)
Else
dtmNextCRLPublish = ""
End If

End If

Loop

'Check that we retrieved proper date value from the CRL for
'at least the NextUpdate (not all CRLs have a NextPublish)
'If not, this is bad so duck out here and alert
If Not(IsDate(dtmNextUpdate) And IsDate(dtmNextCRLPublish)) Then
CheckCRLStream = FALSE
intSeverity = ERROR_ALERT
Exit Function
End if

'If we do have a Next publish date we can use this to work out if we should
'have published a CRL by now (i.e. we are in the CRL overlap period). If everything is
'working to plan a CRL should always be published before we get much into the CRL Overlap
'period. We have a bit of leeway by allowing us to CRL_Check_Tolerance (percentage) into the overlap
'period. If we're beyond that we need to alert.

If IsDate(dtmNextCRLPublish) Then'We don't do any of this if no NextPublish date was read from CRL!
'First do the arithmetic to see if our tolerance date has passed
'(CRL.Next_CRL_Publish + ((CRL.NextUpdate - CRL.Next_CRL_Publish) *  CRL_Check_Tolerance/100)) < Now
' a + ((b - a)* c) < now

d = DateDiff("n",dtmNextCRLPublish,dtmNextUpdate)  'b - a (time diff between expiry and nextpublish
d = clng(d * (csng(CRL_CHECK_TOLERANCE) / 100)) '(b - a)* c (calculate percentage tolerance)
d = DateAdd("n", d, dtmNextCRLPublish) 
                'a + (b - a)* c (add this to nextpublish date to get an absolute date)

' Now check if we have passed the NextCRLPublish date + tolerance margin
If datediff("n",d,now) > 0 Then
'If so, this is worrying - flag to alert
intSeverity = CRITICAL_ALERT
End If
End If

'Regardless of how NextPublish calculation turned out (this might not happen if
'Nextpublish is not in CRL) we need to know if the CRL has expired.
'If (CRL.NextUpdate < Now)
If datediff("n",d,now) > 0 Then
'If so this is an worrying - flag an error
intSeverity = CRITICAL_ALERT
End If

'If (CRL.NextUpdate < Now)
'Now check that we have not passed the expiry date of the CRL!
If datediff("n", dtmNextUpdate, now) > 0 then
'Disaster! critical alert
intSeverity = NOSERVICE_ALERT
End If

End Function


Function ErrorHandle (byVal intError, byVal strError, byVal strComment, byRef strReturn)
'*********************************************************
' Name:ErrorHandle
' Purpose:Handles the return codes for functions
' Inputs:intError = an integer value of the return value / err.number
'strError = a string value describing the return value
'strComment = a meaningful string for debug purposes
' Returns:Boolean describing whether the incoming intError is an error or not
'*********************************************************

'Enable error handling
On Error Resume Next

'Set the default return value
ErrorHandle = FALSE

'Handle the intError value
Select Case intError
Case 0
strReturn = strComment & ":OK"
ErrorHandle = TRUE
Case -2147024894
strReturn = strComment & ":file not found"
Case -2147217406
strReturn = strComment & ":unknown error"
Case -2147023517
strReturn = strComment & ":already exists, skipping"
Case -2147019886
strReturn = strComment & ":already exists, skipping"
Case Else
strReturn = strComment & ":" & strError & " (err#:" & Hex(intError) & ")"
End Select

'Reset error state
Err.Clear

End Function

Function Alert(byVal strAlert, byVal intSeverity)
'*********************************************************
' Name:Alert
' Purpose: Calls AlertID but provides default Event ID and Source
' Inputs: 
' Returns: 
'*********************************************************

AlertID strAlert, intSeverity, 911, EVENT_SOURCE

End Function

Function AlertID(byVal strAlert, byVal intSeverity, _
byVal intEventID, byVal strEventSource)
'*********************************************************
' Name:
' Purpose: 
' Inputs: 
' Returns: 
'*********************************************************

On Error Resume Next

Dim strError 'SUCCESS, ERROR, WARNING, INFORMATION
Dim strErrorType ' Critical Error, Error, Warning

'Translate intSeverity
Select Case intSeverity
Case NOSERVICE_ALERT
strError = "ERROR"
strErrorType = "Service Unavailable - Critical Failure: "
Case SECURITY_ALERT
strError = "ERROR"
strErrorType = "Security Breach: "
Case CRITICAL_ALERT
strError = "ERROR"
strErrorType = "Critical Error: "
Case ERROR_ALERT
strError = "ERROR"
strErrorType = "Error: "
Case WARNING_ALERT
strError = "WARNING"
strErrorType = "Warning: "
Case NO_ALERT
Exit Function
End Select

'Send Email if Appropriate
If bAlertEMail Then
Dim arrRecips, strRecip
arrRecips = Split(strRecipients,",")
For each strRecip in arrRecips
SendEmail strRecip, "CA Alert: " & strErrorType, strAlert, intSeverity
Next
End If

'Send MOM Alert if Appropriate
If bAlertEvtLog Then
ExecuteCommand "eventcreate /T " & strError & " /SO " & chr(34) & strEventSource & chr(34) & _
" /ID " & CStr(intEventID) & " /D " & CHR(34) & strErrorType & strAlert & CHR(34) & _
                            " /L Application","SUCCESS"
End If

End Function

Function SendEmail(byVal strRecip, byVal strSubject, byVal strBody, byVal intSeverity) 'as Boolean
'*********************************************************
' Name:Debug
' Purpose:  Commits an entry to the debug log
' Inputs:strMessage = the line comment to record
' Returns:NULL
'*********************************************************

On Error Resume Next

SendEmail = False

Dim objMsg, objFields, objConfig, strReturn

Set objMsg = CreateObject("CDO.Message")
Set objConfig = CreateObject("CDO.Configuration")
Set objFields = objConfig.Fields

If ErrorHandle(err.number,err.Description,"Creating CDO objects",strReturn) = False Then
debug strReturn
Exit Function
End If

With objFields
.Item(cdoSendUsingMethod)= 2
.Item(cdoSMTPServer)= strSMTPsrv
.Item(cdoSMTPConnectionTimeout) = 10
.Item(cdoSMTPAuthenticate)      = 0 '2=NTLM, 1=basic, 0=anon
.Update
End With

With objMsg
Set .Configuration = objConfig
.To       = strRecip
.From     = EnvironmentVariable("computername") & "@" & EnvironmentVariable("userdnsdomain")
.Subject  = strSubject
.TextBody = strBody
If intSeverity > 1 then
.Fields("urn:schemas:httpmail:importance").Value = CdoHigh
End If
.Send
End With

If ErrorHandle(err.number,err.Description,"Sending email to " &  strRecip, strReturn) = False Then
debug strReturn
Exit Function
End If

Set objMsg = Nothing : Set objConfig = Nothing : Set objFields = Nothing

SendEmail = TRUE

End Function

Function EnvironmentVariable (byVal strVariable)
'*********************************************************
' Name:EnvironmentVariable
' Purpose:  Retrieves an environment variable
' Inputs:strVariable = the name of the variable to retrieve
' Returns:  a string containing the environment variable's value
'*********************************************************

'Enable error handling
On Error Resume Next

'Declare any function specific variables
Dim objShell, strReturn

'Instantiate a copy of the Shell object
Set objShell = WScript.CreateObject("WScript.Shell")

'Set the return value of the function to the requested value
EnvironmentVariable = objShell.ExpandEnvironmentStrings("%" & strVariable & "%")

'Get the debug string
ErrorHandle err.number, err.Description, "Retrieve environment variable '" & strVariable & "'", strReturn

'Echo the debug string
debug strReturn

'Clean Up
Set objShell = Nothing

End Function

Private Function ExecuteCommand(byVal strCommand, byVal strPattern)
'********************************************************************
' Name:  ExecuteCommand           '
' Purpose: Executes a command line, waits for it to complete  '
' Inputs: strCommand = The command to execute      '
'   strPattern = A pattern to find in the output for  '
'       success / failure       '
' Returns: A True / False denoting Success / Failure    '
'********************************************************************
 
'Enable error handling
On Error Resume Next
 
'Set the default return value
ExecuteCommand = FALSE
 
'Declare any function specific variables
Dim objShell, objStream 'objects
Dim strLine, strReturn, strCmdOut, strCmdErr 'strings

'Instantiate and instance of the Shell control
Set objShell = WScript.CreateObject("WScript.Shell")
 
'Execute the command line
Set objStream = objShell.Exec("%ComSpec% /C " & strCommand)
  
'Handle any errors and return a boolean with success / failed
If ErrorHandle (err.Number, err.Description, strCommand, strReturn) = TRUE Then
'The current error level is 0 so loop through the command's output
Do While objStream.StdOut.AtEndOfStream = FALSE
strLine = objStream.StdOut.ReadLine
strCmdOut = strCmdOut & vbNewLine & strLine
If Instr(strLine, strPattern) <> 0 then
'The command executed successfully and the required pattern is in the output
debug strCommand & ":OK"
ExecuteCommand = TRUE
Exit Function
End If
Loop

debug strCommand & ":failed"
'Failure so dump cmd output to screen
wscript.echo vbNewLine 
wscript.echo "-------------------------Error Output---------------------------------"
wscript.echo strCmdOut & vbNewLine
'Capture anything sent to stderr as well
If Not objStream.StdErr.AtEndOfStream Then
strCmdErr = objStream.StdErr.ReadAll
wscript.echo strCmdErr  
End If
wscript.echo "------------------------End Error Output------------------------------" & _
                    vbNewLine & vbNewLine

Else
debug strReturn
End If
 
'Clean up
err.Clear
Set objShell = Nothing
Set objStream = Nothing
 
End Function 'ExecuteCommand

Private Function Debug (byVal strMessage)
'*********************************************************
' Name:Debug
' Purpose:  Commits an entry to the debug log
' Inputs:strMessage = the line comment to record
' Returns:NULL
'*********************************************************

wscript.echo now, vbTab, strMessage

End Function


Function SanitisedTime
'*********************************************************
' Name: SanitisedTime
' Purpose: Returns a date+time string with no spaces, "/" or ":" so that
'it can be used to create filenames
' Inputs: Nothing
' Returns: Date/Time string
'*********************************************************

Dim strShortDate, arrShortDate, strDate, strShortTime, strTime

strShortDate = cstr(FormatDateTime(now,2))

arrShortDate = split(strShortDate,"/")

strDate = arrShortDate(2) & "-" &  arrShortDate(1) & "-" & arrShortDate(0)

strShortTime = cstr(FormatDateTime(now,4))

strTime = Replace(strShortTime, ":", "")

SanitisedTime = strDate & "_" & strTime 

End Function 'SanitisedTime

