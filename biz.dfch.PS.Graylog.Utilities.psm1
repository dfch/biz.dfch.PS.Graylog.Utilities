$fn = $MyInvocation.MyCommand.Name;

Set-Variable gotoSuccess -Option 'Constant' -Value 'biz.dfch.System.Exception.gotoSuccess';
Set-Variable gotoError -Option 'Constant' -Value 'biz.dfch.System.Exception.gotoError';
Set-Variable gotoFailure -Option 'Constant' -Value 'biz.dfch.System.Exception.gotoFailure';
Set-Variable gotoNotFound -Option 'Constant' -Value 'biz.dfch.System.Exception.gotoNotFound';

[string] $ModuleConfigFile = '{0}.xml' -f (Get-Item $PSCommandPath).BaseName;
[string] $ModuleConfigurationPathAndFile = Join-Path -Path $PSScriptRoot -ChildPath $ModuleConfigFile;
$mvar = $ModuleConfigFile.Replace('.xml', '').Replace('.', '_');
if($true -eq (Test-Path -Path $ModuleConfigurationPathAndFile)) 
{
	if($true -ne (Test-Path variable:$($mvar))) 
	{
		Log-Debug $fn ("Loading module configuration file from: '{0}' ..." -f $ModuleConfigurationPathAndFile);
		Set-Variable -Name $mvar -Value (Import-Clixml -Path $ModuleConfigurationPathAndFile);
	}
}
if($true -ne (Test-Path variable:$($mvar))) 
{
	Write-Error "Could not find module configuration file '$ModuleConfigFile' in 'ENV:PSModulePath'.`nAborting module import...";
	break; # Aborts loading module.
}
Export-ModuleMember -Variable $mvar;

[string] $ManifestFile = '{0}.psd1' -f (Get-Item $PSCommandPath).BaseName;
$ManifestPathAndFile = Join-Path -Path $PSScriptRoot -ChildPath $ManifestFile;
if( Test-Path -Path $ManifestPathAndFile)
{
	$Manifest = (Get-Content -raw $ManifestPathAndFile) | iex;
	foreach( $ScriptToProcess in $Manifest.ScriptsToProcess) 
	{ 
		$ModuleToRemove = (Get-Item (Join-Path -Path $PSScriptRoot -ChildPath $ScriptToProcess)).BaseName;
		if(Get-Module $ModuleToRemove)
		{ 
			Remove-Module $ModuleToRemove -ErrorAction:SilentlyContinue;
		}
	}
}

<#
 # ########################################
 # Version history
 # ########################################
 #
 # 2015-03-15; rrink; ADD: initial release
 #
 # ########################################
 #>

# SIG # Begin signature block
# MIIaVQYJKoZIhvcNAQcCoIIaRjCCGkICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUbcCnNHi/F9A7coQEw3Wv0t97
# tdugghURMIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAw
# VzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNV
# BAsTB1Jvb3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw05ODA5
# MDExMjAwMDBaFw0yODAxMjgxMjAwMDBaMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJH
# bG9iYWxTaWduIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDaDuaZjc6j40+Kfvvxi4Mla+pIH/EqsLmVEQS98GPR4mdmzxzdzxtIK+6NiY6a
# rymAZavpxy0Sy6scTHAHoT0KMM0VjU/43dSMUBUc71DuxC73/OlS8pF94G3VNTCO
# XkNz8kHp1Wrjsok6Vjk4bwY8iGlbKk3Fp1S4bInMm/k8yuX9ifUSPJJ4ltbcdG6T
# RGHRjcdGsnUOhugZitVtbNV4FpWi6cgKOOvyJBNPc1STE4U6G7weNLWLBYy5d4ux
# 2x8gkasJU26Qzns3dLlwR5EiUWMWea6xrkEmCMgZK9FGqkjWZCrXgzT/LCrBbBlD
# SgeF59N89iFo7+ryUp9/k5DPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
# HRMBAf8EBTADAQH/MB0GA1UdDgQWBBRge2YaRQ2XyolQL30EzTSo//z9SzANBgkq
# hkiG9w0BAQUFAAOCAQEA1nPnfE920I2/7LqivjTFKDK1fPxsnCwrvQmeU79rXqoR
# SLblCKOzyj1hTdNGCbM+w6DjY1Ub8rrvrTnhQ7k4o+YviiY776BQVvnGCv04zcQL
# cFGUl5gE38NflNUVyRRBnMRddWQVDf9VMOyGj/8N7yy5Y0b2qvzfvGn9LhJIZJrg
# lfCm7ymPAbEVtQwdpf5pLGkkeB6zpxxxYu7KyJesF12KwvhHhm4qxFYxldBniYUr
# +WymXUadDKqC5JlR3XC321Y9YeRq4VzW9v493kHMB65jUr9TU/Qr6cf9tveCX4XS
# QRjbgbMEHMUfpIBvFSDJ3gyICh3WZlXi/EjJKSZp4DCCBBQwggL8oAMCAQICCwQA
# AAAAAS9O4VLXMA0GCSqGSIb3DQEBBQUAMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJH
# bG9iYWxTaWduIFJvb3QgQ0EwHhcNMTEwNDEzMTAwMDAwWhcNMjgwMTI4MTIwMDAw
# WjBSMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEoMCYG
# A1UEAxMfR2xvYmFsU2lnbiBUaW1lc3RhbXBpbmcgQ0EgLSBHMjCCASIwDQYJKoZI
# hvcNAQEBBQADggEPADCCAQoCggEBAJTvZfi1V5+gUw00BusJH7dHGGrL8Fvk/yel
# NNH3iRq/nrHNEkFuZtSBoIWLZFpGL5mgjXex4rxc3SLXamfQu+jKdN6LTw2wUuWQ
# W+tHDvHnn5wLkGU+F5YwRXJtOaEXNsq5oIwbTwgZ9oExrWEWpGLmtECew/z7lfb7
# tS6VgZjg78Xr2AJZeHf3quNSa1CRKcX8982TZdJgYSLyBvsy3RZR+g79ijDwFwmn
# u/MErquQ52zfeqn078RiJ19vmW04dKoRi9rfxxRM6YWy7MJ9SiaP51a6puDPklOA
# dPQD7GiyYLyEIACDG6HutHQFwSmOYtBHsfrwU8wY+S47+XB+tCUCAwEAAaOB5TCB
# 4jAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU
# Rtg+/9zjvv+D5vSFm7DdatYUqcEwRwYDVR0gBEAwPjA8BgRVHSAAMDQwMgYIKwYB
# BQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMDMG
# A1UdHwQsMCowKKAmoCSGImh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5uZXQvcm9vdC5j
# cmwwHwYDVR0jBBgwFoAUYHtmGkUNl8qJUC99BM00qP/8/UswDQYJKoZIhvcNAQEF
# BQADggEBAE5eVpAeRrTZSTHzuxc5KBvCFt39QdwJBQSbb7KimtaZLkCZAFW16j+l
# IHbThjTUF8xVOseC7u+ourzYBp8VUN/NFntSOgLXGRr9r/B4XOBLxRjfOiQe2qy4
# qVgEAgcw27ASXv4xvvAESPTwcPg6XlaDzz37Dbz0xe2XnbnU26UnhOM4m4unNYZE
# IKQ7baRqC6GD/Sjr2u8o9syIXfsKOwCr4CHr4i81bA+ONEWX66L3mTM1fsuairtF
# Tec/n8LZivplsm7HfmX/6JLhLDGi97AnNkiPJm877k12H3nD5X+WNbwtDswBsI5/
# /1GAgKeS1LNERmSMh08WYwcxS2Ow3/MwggQoMIIDEKADAgECAgsEAAAAAAEvTuE1
# XDANBgkqhkiG9w0BAQUFADBXMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
# U2lnbiBudi1zYTEQMA4GA1UECxMHUm9vdCBDQTEbMBkGA1UEAxMSR2xvYmFsU2ln
# biBSb290IENBMB4XDTExMDQxMzEwMDAwMFoXDTE5MDQxMzEwMDAwMFowUTELMAkG
# A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExJzAlBgNVBAMTHkds
# b2JhbFNpZ24gQ29kZVNpZ25pbmcgQ0EgLSBHMjCCASIwDQYJKoZIhvcNAQEBBQAD
# ggEPADCCAQoCggEBALJPFOcQvtcmcqs2l+9Tv0KEXljRiij8Q0ZvfihEUAt1XQDX
# PApEniBqpPdFSjdgo24/Evpt+rZGw2qjuAwnKAJXKNFQ92E5VbjD4SWGUjy/BR3X
# s5r4miQxSdWiqeLTkas+PHPv9inxyDXQMHt/TpKlBo+H4s71wWNmrBhpKsFeu1ro
# bpX/O4BinZnHxy9m1f1iGoJVWsb6QHeOyTA8G/DyNbhsWZz96dbKtEAe9wTK0Wep
# dOOlCFTZgzU7jowjDHW23oZKnho+ClBJOJzSqJC/mPrIjCsnEX4q+87eqa44kyL6
# puz7XGF2w0TWzAx+L20GgKJ0QLu3H/Q713NUH/MCAwEAAaOB+jCB9zAOBgNVHQ8B
# Af8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUCG7YtpyKv+0+
# 18N0XcyAH6gvUHowRwYDVR0gBEAwPjA8BgRVHSAAMDQwMgYIKwYBBQUHAgEWJmh0
# dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMDMGA1UdHwQsMCow
# KKAmoCSGImh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5uZXQvcm9vdC5jcmwwEwYDVR0l
# BAwwCgYIKwYBBQUHAwMwHwYDVR0jBBgwFoAUYHtmGkUNl8qJUC99BM00qP/8/Usw
# DQYJKoZIhvcNAQEFBQADggEBACJcxd099Atw2OP158WOCQG7sZY2XFoHrceoRElR
# JXquDaQZO5Kcz7lCJrs7bJfnx84RbWiR2o1t8VNNVDiMYfPIgnZpvoEyCzHDbMme
# IApYL/BI/n5IB6rXQ1iUc1QEMal4DTuMsHDBPX7XvS8qw+L1jwyQ3GulyL5oXl1t
# +HjSvkmVHhV4CJH7NMi+hK284MbdGNvzyvB7whQ8GLgDupU+IR4/YGl6f2oDno1K
# +fAoLDCEXuwmckKxbctkwxKM1oRLZ0F8sQMXeAnjrai2li2kfoADT4j3wWtaRhXN
# LBmL2HCc5S1JiGByqKQZUnBDXtrWRgOwaA4k70r2CyUk7yQwggSfMIIDh6ADAgEC
# AhIRIQaggdM/2HrlgkzBa1IJTgMwDQYJKoZIhvcNAQEFBQAwUjELMAkGA1UEBhMC
# QkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKDAmBgNVBAMTH0dsb2JhbFNp
# Z24gVGltZXN0YW1waW5nIENBIC0gRzIwHhcNMTUwMjAzMDAwMDAwWhcNMjYwMzAz
# MDAwMDAwWjBgMQswCQYDVQQGEwJTRzEfMB0GA1UEChMWR01PIEdsb2JhbFNpZ24g
# UHRlIEx0ZDEwMC4GA1UEAxMnR2xvYmFsU2lnbiBUU0EgZm9yIE1TIEF1dGhlbnRp
# Y29kZSAtIEcyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsBeuotO2
# BDBWHlgPse1VpNZUy9j2czrsXV6rJf02pfqEw2FAxUa1WVI7QqIuXxNiEKlb5nPW
# kiWxfSPjBrOHOg5D8NcAiVOiETFSKG5dQHI88gl3p0mSl9RskKB2p/243LOd8gdg
# LE9YmABr0xVU4Prd/4AsXximmP/Uq+yhRVmyLm9iXeDZGayLV5yoJivZF6UQ0kcI
# GnAsM4t/aIAqtaFda92NAgIpA6p8N7u7KU49U5OzpvqP0liTFUy5LauAo6Ml+6/3
# CGSwekQPXBDXX2E3qk5r09JTJZ2Cc/os+XKwqRk5KlD6qdA8OsroW+/1X1H0+QrZ
# lzXeaoXmIwRCrwIDAQABo4IBXzCCAVswDgYDVR0PAQH/BAQDAgeAMEwGA1UdIARF
# MEMwQQYJKwYBBAGgMgEeMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2Jh
# bHNpZ24uY29tL3JlcG9zaXRvcnkvMAkGA1UdEwQCMAAwFgYDVR0lAQH/BAwwCgYI
# KwYBBQUHAwgwQgYDVR0fBDswOTA3oDWgM4YxaHR0cDovL2NybC5nbG9iYWxzaWdu
# LmNvbS9ncy9nc3RpbWVzdGFtcGluZ2cyLmNybDBUBggrBgEFBQcBAQRIMEYwRAYI
# KwYBBQUHMAKGOGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dz
# dGltZXN0YW1waW5nZzIuY3J0MB0GA1UdDgQWBBTUooRKOFoYf7pPMFC9ndV6h9YJ
# 9zAfBgNVHSMEGDAWgBRG2D7/3OO+/4Pm9IWbsN1q1hSpwTANBgkqhkiG9w0BAQUF
# AAOCAQEAgDLcB40coJydPCroPSGLWaFNfsxEzgO+fqq8xOZ7c7tL8YjakE51Nyg4
# Y7nXKw9UqVbOdzmXMHPNm9nZBUUcjaS4A11P2RwumODpiObs1wV+Vip79xZbo62P
# lyUShBuyXGNKCtLvEFRHgoQ1aSicDOQfFBYk+nXcdHJuTsrjakOvz302SNG96QaR
# LC+myHH9z73YnSGY/K/b3iKMr6fzd++d3KNwS0Qa8HiFHvKljDm13IgcN+2tFPUH
# Cya9vm0CXrG4sFhshToN9v9aJwzF3lPnVDxWTMlOTDD28lz7GozCgr6tWZH2G01V
# e89bAdz9etNvI1wyR5sB88FRFEaKmzCCBK0wggOVoAMCAQICEhEhYHff2l3ILeBb
# QgbbK6elMjANBgkqhkiG9w0BAQUFADBRMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
# R2xvYmFsU2lnbiBudi1zYTEnMCUGA1UEAxMeR2xvYmFsU2lnbiBDb2RlU2lnbmlu
# ZyBDQSAtIEcyMB4XDTEyMDYwODA3MjQxMVoXDTE1MDcxMjEwMzQwNFowejELMAkG
# A1UEBhMCREUxGzAZBgNVBAgTElNjaGxlc3dpZy1Ib2xzdGVpbjEQMA4GA1UEBxMH
# SXR6ZWhvZTEdMBsGA1UECgwUZC1mZW5zIEdtYkggJiBDby4gS0cxHTAbBgNVBAMM
# FGQtZmVucyBHbWJIICYgQ28uIEtHMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
# CgKCAQEA0xuKJFsjlEbmGME2xhqJI/pbwYKNHcDWCXux2fcKw1FAfjLD002S/Njt
# iDTB6UPP0BDLPO2mpcx89sLWDdXVCAVGnnVe02VZnuMnIwn4ua5S/qeOP74TVZ3d
# SGxf6cbu8jsJAMJ/4kfhVm3wMhaAk4SWJPWoD1dAs8xRQS3BLRKzySL6x6veLW0S
# U6h/bMqUH6xE6HuZAVpA2H4ne1NK1JB/5m33/07/O33dJiZAnzi+h+/6gomBdtEd
# tyssOw9n9ocvc03HYMylUj8ONVk7ELQd4tOasBGd0AoLpynw0grZXS+x03VvnH10
# NiByLTesx6VAGMVsKMliznFnEuvSJwIDAQABo4IBVDCCAVAwDgYDVR0PAQH/BAQD
# AgeAMEwGA1UdIARFMEMwQQYJKwYBBAGgMgEyMDQwMgYIKwYBBQUHAgEWJmh0dHBz
# Oi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMAkGA1UdEwQCMAAwEwYD
# VR0lBAwwCgYIKwYBBQUHAwMwPgYDVR0fBDcwNTAzoDGgL4YtaHR0cDovL2NybC5n
# bG9iYWxzaWduLmNvbS9ncy9nc2NvZGVzaWduZzIuY3JsMFAGCCsGAQUFBwEBBEQw
# QjBABggrBgEFBQcwAoY0aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNl
# cnQvZ3Njb2Rlc2lnbmcyLmNydDAdBgNVHQ4EFgQU8CeCuljXweXmtZyEAx+frc3x
# QLowHwYDVR0jBBgwFoAUCG7YtpyKv+0+18N0XcyAH6gvUHowDQYJKoZIhvcNAQEF
# BQADggEBAAd2aLYyofO6O8cc5l44ImMR5fi/bZhfZ7o/0kl3wxF5p4Rs5JdXx0RK
# cl0lYAR2QF6jyp5ZgDAFo9Pk5ucgEyr1evNh5QkIvp2Yxt7SIbk1Gy3bt+W7LOdF
# OOMzQ6q/uMBD8M7hTFJ2BdoRW2M8WTBAF1ZZ2o/gqrTBej/0mTcRb2gIJxGNULyF
# yNqWFc90YQ+FXQz5jBb9D/YkPp6QtaZjS5gmhu86X31Bb2Q7l+sVJc7zotJ606PT
# ORdsOy21ks2V3nWpugzBtJ0dV3MdKsvcGJ6uDbMrcD21MvmqZmVUmpUr5XYjQwH5
# nSj9Ego8lcJPdsYDcWBcCEybjUCLaOMxggSuMIIEqgIBATBnMFExCzAJBgNVBAYT
# AkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMScwJQYDVQQDEx5HbG9iYWxT
# aWduIENvZGVTaWduaW5nIENBIC0gRzICEhEhYHff2l3ILeBbQgbbK6elMjAJBgUr
# DgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMx
# DAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkq
# hkiG9w0BCQQxFgQUSiObH+3rHqfCAeEuCvElqWCMMf0wDQYJKoZIhvcNAQEBBQAE
# ggEAFsFRTWZHheC7LhQFlAC5mSIGHEDiQr7tjuWZSBj7RwDbJM+osrMmjL4S7RfL
# bVv1IFKbYPR3NSBnG1j70XLhYVYHT+ko5A3uQ+mJ2Pxa8SylKPeBCjR/UZJ1JtWs
# +N//JJxsG7+VqRoyFXHaU60nP/h/0RQinLLZ74fL7VCTUHjCv0CaDlFsUXT3UppB
# 4MtBV7/hGSUsJGncl2abB7/+fOh+Aw9V8eiWm6c+hu/fdZi8dg2C9wqxOwCi/Np9
# K73f3l3brpKo0xU6DaoXbyxN1j36aAQjiWZuneNSQQTwJrb8F77voQFNgRuCeR+2
# 9C7D6cPrPyxK/KUD22YGtWUOVKGCAqIwggKeBgkqhkiG9w0BCQYxggKPMIICiwIB
# ATBoMFIxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSgw
# JgYDVQQDEx9HbG9iYWxTaWduIFRpbWVzdGFtcGluZyBDQSAtIEcyAhIRIQaggdM/
# 2HrlgkzBa1IJTgMwCQYFKw4DAhoFAKCB/TAYBgkqhkiG9w0BCQMxCwYJKoZIhvcN
# AQcBMBwGCSqGSIb3DQEJBTEPFw0xNTAzMTUxNTMxMThaMCMGCSqGSIb3DQEJBDEW
# BBRYhVgouNLHb37x9FK9J9bX+lKr2TCBnQYLKoZIhvcNAQkQAgwxgY0wgYowgYcw
# gYQEFLNjCLTUze1Pz71muVX647+xLCnmMGwwVqRUMFIxCzAJBgNVBAYTAkJFMRkw
# FwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSgwJgYDVQQDEx9HbG9iYWxTaWduIFRp
# bWVzdGFtcGluZyBDQSAtIEcyAhIRIQaggdM/2HrlgkzBa1IJTgMwDQYJKoZIhvcN
# AQEBBQAEggEAkpl3PabtCPsuoPPMucQ4JvdyqmbrLLaFgPBMfQg70Y4dwZBFuV0G
# KN0rDzEcZWmGBcWK0VC8gBY8mxX0paKgzL1qoWPjk6+OAtr1dcDNaiQEta49U+nG
# iIkQ7wg0TSWJAMUvQO5XsUYZ9SeHDsl2JfgqslEGDq2hSJjXr64HJ9eK0ISyhGuZ
# CTI4bDcPAeWj7LUpJzlsZFvySnPC9901tfJDf3lIPI5Kb+iOUXb8nUFpCGetmKj7
# 35rB306tt2cp1Uz9JV9JunuiMAS8hWdX5/ipEneVgmznYYI04CxDhEZpALVuxZDJ
# Cu7MTnCSWoACBJG20K4FfVq7GXoccUq1ig==
# SIG # End signature block
