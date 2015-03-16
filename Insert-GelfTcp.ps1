[CmdletBinding(
    SupportsShouldProcess = $true
	,
    ConfirmImpact = 'High'
	,
	HelpURI = 'http://d-fens.ch/2014/12/31/nobrainer-sending-gelf-messages-to-graylog2-via-powershell'
	,
	DefaultParameterSetName = 'EndDate'
)]
PARAM
(
	[Uri] $Uri = 'tcp://192.168.174.161:12201'
	,
	[DateTime] $StartDate = [DateTime]::Now.AddDays(-7).ToString('yyyy-MM-dd')
	,
	[Parameter(Mandatory = $false, ParameterSetName = 'EndDate')]
	[DateTime] $EndDate = [DateTime]::Now.ToString('yyyy-MM-dd')
	,
	[Parameter(Mandatory = $false, ParameterSetName = 'Days')]
	[int] $Days = 7
	,
	[Parameter(Mandatory = $false)]
	[Object] $Object
	,
	[int] $IncrementInSeconds = 5
	,
	[int] $TotalEntities = 5000
	,
	[string] $DnsSuffix = 'dfch.biz'
)

try
{
	if('Days' -eq $PSCmdlet.ParameterSetName)
	{
		$EndDate = $StartDate.AddDays($Days);
	}
	
	$ShouldProcessMessage = "{0} entities: '{1}' - '{2}' @{3}s [{4} total messages]" -f $TotalEntities, $StartDate.ToString('u'), $EndDate.ToString('u'), $IncrementInSeconds, (($EndDate - $StartDate).TotalSeconds / $IncrementInSeconds * $TotalEntities);
	if(!$PSCmdlet.ShouldProcess($ShouldProcessMessage))
	{
		Exit;
	}

	$PSDefaultParameterValues.'ConvertTo-Json:Compress' = $true;

	$Address = [System.Net.IPAddress]::Parse($Uri.Host);
	# Create Endpoint and Socket 
	$EndPoint = New-Object System.Net.IPEndPoint($Address, $Uri.Port);

	# Connect to Socket 
	$Socket = New-Object System.Net.Sockets.Socket($Address.AddressFamily, [System.Net.Sockets.SocketType]::Stream, $Uri.Scheme); 
	$Socket.Connect($EndPoint);

	# generate some server ids
	$al = New-Object System.Collections.ArrayList($TotalEntities);
	$null = $al.Add('deaddead-dead-dead-dead-deaddeaddead');
	for($c = 1; $c -lt $TotalEntities; $c++)
	{
		$null = $al.Add([Guid]::NewGuid().Guid);
	}

	$CurrentDate = $StartDate;
	while($EndDate -gt $CurrentDate) 
	{
		$ProgressPreference = 'Continue';
		Write-Progress -id 1 -Activity ("CurrentDate '{0}' / EndDate '{1}'" -f $CurrentDate, $EndDate) -CurrentOperation $Uri.AbsoluteUri;
		$ProgressPreference = 'silentlyContinue';

		$Epoch = [Math]::Floor( [decimal] (Get-Date (([dateTime] $CurrentDate).ToUniversalTime()) -UFormat '%s'));
		for($c = 0; $c -lt $TotalEntities; $c++)
		{
			$Guid = $al[$c];
			if($Object)
			{
				$JsonBody = '{0}{1}' -f ($Object | ConvertTo-Json), "`0";
			}
			else
			{
				$JsonBody = '{0}{1}' -f (@{ version = '1.2'; host = ('s{0:D7}.{1}' -f $c, $DnsSuffix); timestamp = ('{0}.000' -f $Epoch); short_message = 'metrics'; _cpu = (Get-Random -Minimum 0 -Maximum 100); _mem = ((Get-Random -Minimum 1 -Maximum 16) * 1024); _disk = ((Get-Random -Minimum 20 -Maximum 512) * 1024); _guid = $Guid; } | ConvertTo-Json), "`0";
			}
			$Sent = $Socket.Send([System.Text.Encoding]::UTF8.GetBytes($JsonBody));
		}
		$CurrentDate = $CurrentDate.AddSeconds($IncrementInSeconds); 
	}
}
catch
{
	throw $_;
}
finally
{
	if($Socket)
	{
		$Socket.Disconnect($true);
		$Socket.Close();
		$Socket.Dispose();
	}
}
<#
   Copyright 2014-2015 d-fens GmbH

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
#>
