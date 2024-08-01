<html>
<head>
<title>Access Point Status</title>
<link rel="stylesheet" href="/css/normal_ws.css" type="text/css">
<link rel="stylesheet" href="/css/boxStyle.css" type="text/css">
<meta http-equiv="content-type" content="text/html; charset=iso-8859-1">
<script type="text/javascript" src="/lang/b28n.js"></script>
<META HTTP-EQUIV="refresh" CONTENT="60"; URL=./status.asp">

<script language="JavaScript" type="text/javascript">
Butterlate.setTextDomain("admin");

function style_display_on()
{
	if (window.ActiveXObject)
	{ // IE
		return "block";
	}
	else if (window.XMLHttpRequest)
	{ // Mozilla, Safari,...
		return "table-row";
	}
}

function showOpMode()
{
	var opmode = 1* <% getCfgZero(1, "OperationMode"); %>;
	if (opmode == 0)
		document.write("Bridge Mode");
	else if (opmode == 1)
		document.write("Gateway Mode");
	else if (opmode == 2)
		document.write("Ethernet Converter Mode");
	else if (opmode == 3)
		document.write("AP Client Mode");
	else
		document.write("Unknown");	
}

function showPortStatus()
{
	var str = "<% getPortStatus(); %>";
	var all = new Array();

	if(str == "-1"){
		document.write("not support");
		return ;
	}

	all = str.split(",");
	for(i=0; i< all.length-1; i+=3){
		document.write("<td>");
		if(all[i] == "1"){
			if(all[i+1] == "10")
				document.write("<img src=/graphics/10.gif> ");
			else if(all[i+1] == "100")
				document.write("<img src=/graphics/100.gif> ");

//			if(all[i+2] == "F")
//				document.write("Full ");
//			else(all[i+2] == "H")
//				document.write("Half ");
		}else if(all[i] == "0"){
				document.write("<img src=/graphics/empty.gif> ");
		}
		document.write("</td>");
	}
}

function initTranslation()
{
	var e = document.getElementById("statusTitle");
	e.innerHTML = _("status title");
	/*e = document.getElementById("statusIntroduction");
	e.innerHTML = _("status introduction");*/
	
	e = document.getElementById("statusSysInfo");
	e.innerHTML = _("status system information");
   e = document.getElementById("statusProMo");
   e.innerHTML = _("status product model");
    //e = document.getElementById("statusDeviceID");
	//e.innerHTML = _("router S/N");
   e = document.getElementById("statusHrdVersion");
	e.innerHTML = _("status hrdw version");
	e = document.getElementById("statusSDKVersion");
	e.innerHTML = _("status sdk version");
   
  
	e = document.getElementById("statusSysUpTime");
	e.innerHTML = _("status system up time");
	//e = document.getElementById("statusSysPlatform");
	//e.innerHTML = _("status system platform");
	e = document.getElementById("statusOPMode");
	e.innerHTML = _("status operate mode");

    e = document.getElementById("status3gStatus");
	e.innerHTML = _("status 3g info");
    e = document.getElementById("status3gSignal");
	e.innerHTML = _("status 3g signal");
    e = document.getElementById("status3gAttach");
	e.innerHTML = _("status 3g attach");
    
	e = document.getElementById("statusInternetConfig");
	e.innerHTML = _("status internet config");
	e = document.getElementById("statusConnectedType");
	e.innerHTML = _("status connect type");
	e = document.getElementById("statusWANIPAddr");
	e.innerHTML = _("status wan ipaddr");
	e = document.getElementById("statusSubnetMask");
	e.innerHTML = _("status subnet mask");
	e = document.getElementById("statusDefaultGW");
	e.innerHTML = _("status default gateway");
	e = document.getElementById("statusPrimaryDNS");
	e.innerHTML = _("status primary dns");
	e = document.getElementById("statusSecondaryDNS");
	e.innerHTML = _("status secondary dns");
	e = document.getElementById("statusWANMAC");
	e.innerHTML = _("status wanmac");

	e = document.getElementById("statusLocalNet");
	e.innerHTML = _("status local network");
	e = document.getElementById("statusLANIPAddr");
	e.innerHTML = _("status lan ipaddr");
	e = document.getElementById("statusLocalNetmask");
	e.innerHTML = _("status local netmask");
	e = document.getElementById("statusLANMAC");
	e.innerHTML = _("status lanmac");
	
	e = document.getElementById("modelType");
	e.innerHTML = _("status modelType");
	
	
	e = document.getElementById("help_head");
	e.innerHTML = _("help help_head");
	e = document.getElementById("status_direc");
	e.innerHTML = _("status status_direc");
	
	e = document.getElementById("imei");
	e.innerHTML = _("status imei");

//	e = document.getElementById("statusEthPortStatus");
	//e.innerHTML = _("status ethernet port status");
}

function PageInit()
{
	var ethtoolb = "<% getETHTOOLBuilt(); %>";
	initTranslation();

	if (ethtoolb == "1")
	{
		//document.getElementById("statusEthPortStatus").style.visibility = "visible";
		//document.getElementById("statusEthPortStatus").style.display = style_display_on();
//		document.getElementById("div_ethtool").style.visibility = "visible";
	//	document.getElementById("div_ethtool").style.display = style_display_on();
	}
	else
	{
		//document.getElementById("statusEthPortStatus").style.visibility = "hidden";
		//document.getElementById("statusEthPortStatus").style.display = "none";
		//document.getElementById("div_ethtool").style.visibility = "hidden";
		//document.getElementById("div_ethtool").style.display = "none";
	}	
	
	//getModelType();
}
</script>
</head>

<body onload="PageInit()">
<center id="boxes">
	<div id="box">
	<div id="head"></div>	<!--end of head-->	
	<div id="content">

	<table id="layout_table" border="0"><!--start of layout_table-->
<tr><!--start of layout tr-->
<td class="tdwidth1" id="td1"><!--start of td1-->
<div id="left"><!--start of left-->


<table class="body"><tr><td>
<H1 id="statusTitle">Access Point Status</H1>
<!--<P id="statusIntroduction">Let's take a look at the status of 3G Router </P>-->
<hr /><br/>

<style type="text/css">
	legend{
		text-align:left;
		color:#3A587A;
		font-weight:bold
	}	
	
</style>
<fieldset>
	<legend><span class="title" id="statusSysInfo">System Info</span></legend>
	<table width="540" border="0" cellpadding="2" cellspacing="1">
		<tr>
		  
		</tr>
		<tr>
		    <td class="head" id="statusProMo">Product Model</td>
		    <td>Mobile Router</td>
		<!--
		    <td>R8</td>
		<tr>
		  <td class="head" id="statusDeviceID">Device ID</td>
		  <td><% getDeviceID(); %> </td>
		</tr>
		-->
		</tr>
		<tr>
		  <td class="head" id="statusHrdVersion">Hardware Version</td>
		  <td><% getHrdVersion(); %> </td>
		</tr>
		<tr>
		  <td class="head" id="statusSDKVersion">SDK Version</td>
		  <td><% getSdkVersion(); %> (<% getSysBuildTime(); %>)</td>
		</tr>
		
		
		<tr>
		  <td class="head" id="statusSysUpTime">System Up Time</td>
		  <td><% getSysUptime(); %></td>
		</tr>
		<!--<tr>
		  <td class="head" id="statusSysPlatform">System Platform</td>
		  <td><% getPlatform(); %></td>
		</tr>-->
		<tr>
		  <td class="head" id="statusOPMode">Operation Mode</td>
		  <td><script type="text/javascript">showOpMode();</script></td>
		</tr>
	</table>
</fieldset><br/>
<fieldset>
	<legend><span class="title" id="status3gStatus">3G Status</span></legend>
	<table width="540" border="0" cellpadding="2" cellspacing="1">
		<tr>
		  
		</tr>
		<tr>
		  <td class="head" id="status3gSignal">Signal</td>
		  <td><% get3gSignal(); %></td>
		</tr>
		<tr>
		  <td class="head" id="status3gAttach">Attach State</td>
		  <td><% getSimState(); %></td>
		</tr>
		
		<script type="text/javascript">
			
		/*	function getModelType(){
				var dev_3g = "<% getCfgGeneral(1, "wan_3g_dev"); %>";
			    //	document.getElementById("MoType").innerHTML;
			    if (dev_3g == "HUAWEI-EM560")
					document.getElementById("MoType").innerHTML = "HUAWEI-EM560";
				else if (dev_3g == "HUAWEI-EM660")
					document.getElementById("MoType").innerHTML = "HUAWEI-EM660";
				else if (dev_3g == "HUAWEI-EM770")
					document.getElementById("MoType").innerHTML = "HUAWEI-EM770";
				else if (dev_3g == "SYNCWISER-801/401")
					document.getElementById("MoType").innerHTML = "SYNCWISER-801/401";
				else if (dev_3g == "LONGSUNG-U6300/U5300")
					document.getElementById("MoType").innerHTML = "LONGSUNG-U6300/U5300";
				else if (dev_3g == "MC5728")
					document.getElementById("MoType").innerHTML = "MC5728";
				else if (dev_3g == "F3607gw")
					document.getElementById("MoType").innerHTML = "Ericsson F3607gw";
				else if (dev_3g == "ZTE-MF210V")
					document.getElementById("MoType").innerHTML = "ZTE-MF210V";
		        else if (dev_3g == "SIERRA-MC8785")
		    	    document.getElementById("MoType").innerHTML = "SIERRA-MC8785";
		        else if (dev_3g == "MC8785")
		    	    document.getElementById("MoType").innerHTML = "Serria MC8785";
                else if (dev_3g == "AD3812")
		    	    document.getElementById("MoType").innerHTML = "ZTE-AD3812";
			    else
					document.getElementById("MoType").innerHTML = "NO MODEM";*/
				}
		</script>
		
		<tr>
			<td id="modelType">Model Type</td>	
			<td id="MoType"><% getCfgGeneral(1, "wan_3g_dev"); %></td>	
		</tr>
		<tr>
			<td id="imei">IMEI</td>
			<td><% getDeviceID(); %></td>
		</tr>
	</table>
</fieldset><br/>
<fieldset>
	<legend><span class="title" id="statusLocalNet">Local Network</span></legend>
	<table width="540" border="0" cellpadding="2" cellspacing="1">
		<tr>
		  
		</tr>
		<tr>
		  <td class="head" id="statusLANIPAddr">Local IP Address</td>
		  <td><% getLanIp(); %></td>
		</tr>
		<tr>
		  <td class="head" id="statusLocalNetmask">Local Netmask</td>
		  <td><% getLanNetmask(); %></td>
		</tr>
		<tr>
		  <td class="head" id="statusLANMAC">MAC Address</td>
		  <td><% getLanMac(); %></td>
		</tr>
	</table>
</fieldset><br/>
<fieldset>
	<legend><span class="title" colspan="2" id="statusInternetConfig">Internet Configurations</span></legend>
	<table width="540" border="0" cellpadding="2" cellspacing="1">
		<tr>
		  
		</tr>
		<tr>
		  <td class="head" id="statusConnectedType">Connected Type</td>
		  <td><!--<% get3gAttachState(); %> --> <% getCfgGeneral(1, "g3_operator_name"); %> </td>
		</tr>
		<tr>
		  <td class="head" id="statusWANIPAddr">WAN IP Address</td>
		  <td><% getWanIp(); %></td>
		</tr>
		<tr>
		  <td class="head" id="statusSubnetMask">Subnet Mask</td>
		  <td><% getWanNetmask(); %></td>
		</tr>
		<tr>
		  <td class="head" id="statusDefaultGW">Default Gateway</td>
		  <td><% getWanGateway(); %></td>
		</tr>
		<tr>
		  <td class="head" id="statusPrimaryDNS">Primary Domain Name Server</td>
		  <td><% getDns(1); %></td>
		</tr>
		<tr>
		  <td class="head" id="statusSecondaryDNS">Secondary Domain Name Server</td>
		  <td><% getDns(2); %></td>
		</tr>
		<tr>
		  <td class="head" id="statusWANMAC">MAC Address</td>
		  <td><% getWanMac(); %></td>
		</tr>
	</table>
</fieldset>
<table width="540" border="0" cellpadding="2" cellspacing="1">
<!-- ================= System Info ================= -->

<!--<tr>
  <td class="head" id="status3gSN">SN</td>
  <td><% get3gSN(); %></td>
</tr>
<tr>
  <td class="head" id="status3gPN">PN</td>
  <td><% get3gPN(); %></td>
</tr>
-->


<!--
<tr>
  <td class="head" id="status3gESN">ESN</td>
</tr>
-->
<!-- ================= Local Network ================= -->

<!-- ================= Other Information ================= -->
</table>

<!--
<table border="0" id="div_ethtool">
<tr>
  <td>
    <H1 id="statusEthPortStatus">Ethernet Port Status</H1>
  </td>
</tr>
<tr>
  <td>
    <script type="text/javascript">showPortStatus();</script>
  </td>
</tr>
</table>
<br>
</td></tr></table>
-->
<table width="540" border="0" cellpadding="2" cellspacing="1">
<!-- ================= Internet Configurations ================= -->

</table>
<br>
</td></tr></table>

<table width="540" cellpadding="2" cellspacing="1">
</table>

</div><!--end of left-->
</td><!--end of td1-->

<td class="tdwidth2" id="td2"><!--start of td2-->
	<div id="right"><!--start of right-->
		<h2 id="help_head">Heeelp...</h2>
		
		<p id="help_content"><span id="status_direc"></span></p>
	</div><!--end of right-->
</td><!--end of td2-->
</tr><!--end of layout tr-->
</table><!--end of layout_table-->
</div><!--end of content-->
	</div>
	</center>
</body>
</html>
